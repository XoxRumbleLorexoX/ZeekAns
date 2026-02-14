#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import signal
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from collections import defaultdict, deque
from datetime import datetime, timezone

DEFAULT_CONFIG = {
    "interface": "",
    "interfaces": [],
    "start_zeek": True,
    "zeek_use_sudo": True,
    "log_dir": "./logs",
    "ollama": {
        "enabled": True,
        "url": "http://127.0.0.1:11434/api/generate",
        "model": "llama3.1",
        "timeout_sec": 30
    },
    "alerts": {
        "output_dir": "./alerts",
        "cooldown_sec": 30,
        "llm_bypass_gate_severities": ["high", "critical"],
        "llm_bypass_gate_types": []
    },
    "knockknock": {
        "enabled": True,
        "sequence_ports": [2222, 3333, 4444],
        "window_sec": 10,
        "armed_ttl_sec": 300,
        "admin_ip": "",
        "local_ips": []
    },
    "anomaly": {
        "scan_window_sec": 30,
        "scan_unique_ports_threshold": 20,
        "scan_unique_hosts_threshold": 20,
        "scan_failed_threshold": 15,
        "scan_excluded_ports": [5353],
        "scan_ignore_multicast_dest": True,
        "dns_window_sec": 60,
        "dns_unique_domains_threshold": 30,
        "dns_long_domain_len": 60,
        "dns_nxdomain_threshold": 12,
        "dns_ignore_suffixes": [".local", ".arpa"],
        "new_asn_country_enabled": False,
        "new_asn_country_warmup_sec": 900,
        "new_asn_country_lookup_url": "http://ip-api.com/json/{ip}?fields=status,country,countryCode,as,query",
        "new_asn_country_lookup_timeout_sec": 2,
        "new_asn_country_lookup_min_interval_sec": 0.2,
        "new_asn_country_known_asns": [],
        "new_asn_country_known_countries": [],
        "tls_burst_without_data_enabled": False,
        "tls_burst_window_sec": 60,
        "tls_burst_min_conns": 25,
        "tls_burst_min_unique_hosts": 5,
        "tls_burst_max_resp_bytes": 120,
        "tls_burst_max_duration_sec": 1.5,
        "beaconing_enabled": False,
        "beaconing_window_sec": 900,
        "beaconing_min_events": 6,
        "beaconing_min_interval_sec": 10,
        "beaconing_max_interval_sec": 600,
        "beaconing_max_jitter_sec": 2.5,
        "beaconing_alert_cooldown_sec": 900
    }
}


def normalize_text(value):
    return str(value or "").strip().lower()


def is_multicast_or_broadcast(addr):
    addr = str(addr or "").strip()
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
        if ip.is_multicast:
            return True
        if isinstance(ip, ipaddress.IPv4Address) and addr.endswith(".255"):
            return True
        return addr == "255.255.255.255"
    except ValueError:
        return False


def is_private_or_linklocal(addr):
    addr = str(addr or "").strip()
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_link_local or ip.is_loopback
    except ValueError:
        return False


def is_public_ip(addr):
    addr = str(addr or "").strip()
    if not addr or addr == "-":
        return False
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_global
    except ValueError:
        return False


class LogTailer:
    def __init__(self, path, start_at_end=True, wait_for_file=True):
        self.path = path
        self.start_at_end = start_at_end
        self.wait_for_file = wait_for_file
        self.file = None
        self.fields = None

    def _close(self):
        if not self.file:
            return
        try:
            self.file.close()
        finally:
            self.file = None

    def _open(self, start_at_end=None):
        if start_at_end is None:
            start_at_end = self.start_at_end
        self._close()
        self.fields = None
        self.file = open(self.path, "r", encoding="utf-8", errors="replace")
        if start_at_end:
            # Read headers to learn fields, then jump to end for new events.
            for _ in range(50):
                line = self.file.readline()
                if not line:
                    break
                if line.startswith("#fields"):
                    self.fields = line.rstrip("\n").split("\t")[1:]
            self.file.seek(0, os.SEEK_END)

    def _ensure_open(self):
        if self.file:
            return True
        while not os.path.exists(self.path):
            if not self.wait_for_file:
                return False
            time.sleep(0.2)
        self._open()
        return True

    def _reopen_if_rotated(self):
        if not self.file:
            return
        try:
            path_stat = os.stat(self.path)
        except FileNotFoundError:
            return
        try:
            file_stat = os.fstat(self.file.fileno())
            file_pos = self.file.tell()
        except OSError:
            self._open(start_at_end=False)
            return

        inode_changed = (
            path_stat.st_ino != file_stat.st_ino or
            path_stat.st_dev != file_stat.st_dev
        )
        truncated = path_stat.st_size < file_pos
        if inode_changed or truncated:
            # Reopen from start so post-rotation entries are not missed.
            self._open(start_at_end=False)

    def read_new(self):
        if not self._ensure_open():
            return []
        records = []
        while True:
            self._reopen_if_rotated()
            line = self.file.readline()
            if not line:
                prev_file = self.file
                self._reopen_if_rotated()
                if self.file is not prev_file:
                    continue
                break
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                self.fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not self.fields:
                continue
            parts = line.split("\t")
            if len(parts) != len(self.fields):
                continue
            rec = {self.fields[i]: parts[i] for i in range(len(self.fields))}
            records.append(rec)
        return records


class KnockGate:
    def __init__(self, cfg):
        self.enabled = bool(cfg.get("enabled", True))
        self.sequence = [int(p) for p in cfg.get("sequence_ports", [])]
        self.window_sec = float(cfg.get("window_sec", 10))
        self.armed_ttl_sec = float(cfg.get("armed_ttl_sec", 300))
        self.admin_ip = (cfg.get("admin_ip") or "").strip() or None
        self.local_ips = set(cfg.get("local_ips", []))
        self._state = {}
        self._armed_until = 0.0

    def is_armed(self):
        return time.time() < self._armed_until
    
    def arm_for(self, seconds):
        self._armed_until = max(self._armed_until, time.time() + float(seconds))

    def process_conn(self, rec):
        if not self.enabled or not self.sequence:
            return False
        try:
            ts = float(rec.get("ts", "0"))
        except ValueError:
            ts = time.time()
        orig = rec.get("id.orig_h", "")
        resp_h = rec.get("id.resp_h", "")
        try:
            resp_p = int(rec.get("id.resp_p", "0"))
        except ValueError:
            return False

        if self.admin_ip and orig != self.admin_ip:
            return False
        if self.local_ips and resp_h not in self.local_ips:
            return False

        idx, start_ts = self._state.get(orig, (0, ts))
        if resp_p == self.sequence[idx]:
            if idx == 0:
                start_ts = ts
            if ts - start_ts > self.window_sec:
                idx = 0
                start_ts = ts
                if resp_p != self.sequence[0]:
                    self._state[orig] = (idx, start_ts)
                    return False
            idx += 1
            if idx >= len(self.sequence):
                self._armed_until = time.time() + self.armed_ttl_sec
                self._state[orig] = (0, ts)
                return True
            self._state[orig] = (idx, start_ts)
            return False

        if resp_p == self.sequence[0]:
            self._state[orig] = (1, ts)
        else:
            self._state[orig] = (0, ts)
        return False


class AlertManager:
    def __init__(self, alerts_cfg, ollama_cfg, gate):
        self.output_dir = alerts_cfg.get("output_dir", "./alerts")
        self.cooldown_sec = float(alerts_cfg.get("cooldown_sec", 30))
        self.ollama_cfg = ollama_cfg
        self.gate = gate
        self.llm_bypass_gate_severities = {
            normalize_text(v) for v in alerts_cfg.get("llm_bypass_gate_severities", ["high", "critical"])
        }
        self.llm_bypass_gate_types = {
            normalize_text(v) for v in alerts_cfg.get("llm_bypass_gate_types", [])
        }
        self._last_llm_ts = 0.0
        os.makedirs(self.output_dir, exist_ok=True)
        self.text_log = os.path.join(self.output_dir, "alerts.log")
        self.json_log = os.path.join(self.output_dir, "alerts.jsonl")

    def _should_query_llm(self, event):
        if not self.ollama_cfg.get("enabled", True):
            return False
        if time.time() - self._last_llm_ts < self.cooldown_sec:
            return False
        if self.gate.is_armed():
            return True
        ev_type = normalize_text(event.get("type"))
        ev_sev = normalize_text(event.get("severity"))
        if event.get("llm_bypass_gate"):
            return True
        if ev_type in self.llm_bypass_gate_types:
            return True
        return ev_sev in self.llm_bypass_gate_severities

    def _ollama_generate(self, event):
        if not self._should_query_llm(event):
            return ""

        prompt = (
            "You are a local SOC assistant. Provide concise next steps.\n"
            "Focus on verification, containment, and data collection.\n"
            "Use short bullet points and include relevant Zeek log hints.\n\n"
            f"Event: {event['summary']}\n"
            f"Type: {event['type']}\n"
            f"Severity: {event.get('severity', 'medium')}\n"
            f"Details: {json.dumps(event.get('details', {}))}\n"
        )
        payload = {
            "model": self.ollama_cfg.get("model", "llama3.1"),
            "prompt": prompt,
            "stream": False
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.ollama_cfg.get("url", "http://127.0.0.1:11434/api/generate"),
            data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.ollama_cfg.get("timeout_sec", 30)) as resp:
                body = resp.read().decode("utf-8")
            result = json.loads(body)
            self._last_llm_ts = time.time()
            return result.get("response", "")
        except (urllib.error.URLError, json.JSONDecodeError):
            return ""

    def emit(self, event):
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        record = {
            "ts": ts,
            "type": event.get("type", "unknown"),
            "severity": event.get("severity", "medium"),
            "summary": event.get("summary", ""),
            "details": event.get("details", {}),
        }
        if event.get("llm_bypass_gate"):
            record["llm_bypass_gate"] = True
        guidance = self._ollama_generate(record)
        if guidance:
            record["guidance"] = guidance

        line = f"[{ts}] {record['severity'].upper()} {record['type']} - {record['summary']}"
        if guidance:
            line += f"\n{guidance}"
        print(line, flush=True)

        with open(self.text_log, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        with open(self.json_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


class AnomalyDetector:
    def __init__(self, cfg, gate, alerts):
        self.cfg = cfg
        self.gate = gate
        self.alerts = alerts
        self.scan_window = float(cfg.get("scan_window_sec", 30))
        self.scan_unique_ports_threshold = int(cfg.get("scan_unique_ports_threshold", 20))
        self.scan_unique_hosts_threshold = int(cfg.get("scan_unique_hosts_threshold", 20))
        self.scan_failed_threshold = int(cfg.get("scan_failed_threshold", 15))
        self.scan_excluded_ports = {int(p) for p in cfg.get("scan_excluded_ports", [5353])}
        self.scan_ignore_multicast_dest = bool(cfg.get("scan_ignore_multicast_dest", True))
        self.dns_window = float(cfg.get("dns_window_sec", 60))
        self.dns_unique_domains_threshold = int(cfg.get("dns_unique_domains_threshold", 30))
        self.dns_long_domain_len = int(cfg.get("dns_long_domain_len", 60))
        self.dns_nxdomain_threshold = int(cfg.get("dns_nxdomain_threshold", 12))
        self.dns_ignore_suffixes = tuple(
            normalize_text(v) for v in cfg.get("dns_ignore_suffixes", [".local", ".arpa"])
        )
        self.new_asn_country_enabled = bool(cfg.get("new_asn_country_enabled", False))
        self.new_asn_country_warmup_sec = float(cfg.get("new_asn_country_warmup_sec", 900))
        self.new_asn_country_lookup_url = str(
            cfg.get(
                "new_asn_country_lookup_url",
                "http://ip-api.com/json/{ip}?fields=status,country,countryCode,as,query",
            )
        )
        self.new_asn_country_lookup_timeout_sec = float(cfg.get("new_asn_country_lookup_timeout_sec", 2))
        self.new_asn_country_lookup_min_interval_sec = float(
            cfg.get("new_asn_country_lookup_min_interval_sec", 0.2)
        )
        self.new_asn_country_known_asns = {
            normalize_text(v).upper() for v in cfg.get("new_asn_country_known_asns", []) if normalize_text(v)
        }
        self.new_asn_country_known_countries = {
            normalize_text(v).upper()
            for v in cfg.get("new_asn_country_known_countries", [])
            if normalize_text(v)
        }
        self.tls_burst_without_data_enabled = bool(cfg.get("tls_burst_without_data_enabled", False))
        self.tls_burst_window_sec = float(cfg.get("tls_burst_window_sec", 60))
        self.tls_burst_min_conns = int(cfg.get("tls_burst_min_conns", 25))
        self.tls_burst_min_unique_hosts = int(cfg.get("tls_burst_min_unique_hosts", 5))
        self.tls_burst_max_resp_bytes = int(cfg.get("tls_burst_max_resp_bytes", 120))
        self.tls_burst_max_duration_sec = float(cfg.get("tls_burst_max_duration_sec", 1.5))
        self.beaconing_enabled = bool(cfg.get("beaconing_enabled", False))
        self.beaconing_window_sec = float(cfg.get("beaconing_window_sec", 900))
        self.beaconing_min_events = int(cfg.get("beaconing_min_events", 6))
        self.beaconing_min_interval_sec = float(cfg.get("beaconing_min_interval_sec", 10))
        self.beaconing_max_interval_sec = float(cfg.get("beaconing_max_interval_sec", 600))
        self.beaconing_max_jitter_sec = float(cfg.get("beaconing_max_jitter_sec", 2.5))
        self.beaconing_alert_cooldown_sec = float(cfg.get("beaconing_alert_cooldown_sec", 900))

        self._conn_events = defaultdict(deque)
        self._dns_events = defaultdict(deque)
        self._tls_events = defaultdict(deque)
        self._beacon_events = defaultdict(deque)
        self._beacon_last_alert_ts = {}
        self._asn_country_cache = {}
        self._seen_asns = set(self.new_asn_country_known_asns)
        self._seen_countries = set(self.new_asn_country_known_countries)
        self._last_asn_country_lookup_ts = 0.0
        self._started_wall_ts = time.time()

    def _prune(self, dq, cutoff_ts):
        while dq and dq[0][0] < cutoff_ts:
            dq.popleft()

    def _dns_query_is_eligible(self, query):
        q = normalize_text(query).rstrip(".")
        if not q or q == "-":
            return False
        for suffix in self.dns_ignore_suffixes:
            if suffix and q.endswith(suffix):
                return False
        return True

    def _parse_int(self, value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _parse_float(self, value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _extract_asn(self, asn_text):
        raw = str(asn_text or "").strip()
        if not raw:
            return ""
        upper = raw.upper()
        first = upper.split()[0]
        if first.startswith("AS"):
            return first
        if first.isdigit():
            return f"AS{first}"
        return first

    def _lookup_asn_country(self, ip_addr):
        if ip_addr in self._asn_country_cache:
            return self._asn_country_cache[ip_addr]

        now = time.time()
        if now - self._last_asn_country_lookup_ts < self.new_asn_country_lookup_min_interval_sec:
            return None
        self._last_asn_country_lookup_ts = now

        safe_ip = urllib.parse.quote(ip_addr, safe="")
        try:
            lookup_url = self.new_asn_country_lookup_url.format(ip=safe_ip)
        except Exception:
            lookup_url = self.new_asn_country_lookup_url
        req = urllib.request.Request(lookup_url, headers={"User-Agent": "ZeekAns/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=self.new_asn_country_lookup_timeout_sec) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, ValueError):
            return None

        status = normalize_text(payload.get("status"))
        if status and status != "success":
            self._asn_country_cache[ip_addr] = None
            return None

        asn_raw = payload.get("as") or payload.get("asn") or ""
        country = (payload.get("countryCode") or payload.get("country") or "").strip().upper()
        info = {
            "asn": self._extract_asn(asn_raw),
            "asn_raw": str(asn_raw or ""),
            "country": country,
        }
        self._asn_country_cache[ip_addr] = info
        return info

    def _handle_new_asn_country(self, ts, orig, resp_h, iface):
        if not self.new_asn_country_enabled:
            return
        if not is_public_ip(resp_h):
            return
        info = self._lookup_asn_country(resp_h)
        if not info:
            return

        asn = normalize_text(info.get("asn")).upper()
        country = normalize_text(info.get("country")).upper()
        new_asn = bool(asn and asn not in self._seen_asns and asn not in self.new_asn_country_known_asns)
        new_country = bool(
            country
            and country not in self._seen_countries
            and country not in self.new_asn_country_known_countries
        )
        if asn:
            self._seen_asns.add(asn)
        if country:
            self._seen_countries.add(country)

        # Use a warm-up period to establish baseline infrastructure before alerting.
        if time.time() - self._started_wall_ts < self.new_asn_country_warmup_sec:
            return
        if not (new_asn or new_country):
            return

        reasons = []
        if new_asn:
            reasons.append("new_asn")
        if new_country:
            reasons.append("new_country")
        self.alerts.emit({
            "type": "new_asn_country",
            "severity": "medium",
            "summary": f"New external infrastructure observed for {orig} -> {resp_h}",
            "details": {
                "orig_h": orig,
                "resp_h": resp_h,
                "interface": iface,
                "asn": asn,
                "asn_raw": info.get("asn_raw", ""),
                "country": country,
                "reasons": reasons,
                "ts": ts,
            },
        })

    def _handle_tls_burst_without_data(self, ts, orig, resp_h, resp_p, service, duration, orig_bytes, resp_bytes, iface):
        if not self.tls_burst_without_data_enabled:
            return
        if not is_public_ip(resp_h):
            return
        if "ssl" not in normalize_text(service):
            return

        dq = self._tls_events[orig]
        dq.append((ts, resp_h, resp_p, duration, orig_bytes, resp_bytes))
        self._prune(dq, ts - self.tls_burst_window_sec)

        suspicious = [
            (dst_h, dst_p, dur, o_bytes, r_bytes)
            for _, dst_h, dst_p, dur, o_bytes, r_bytes in dq
            if dur <= self.tls_burst_max_duration_sec and r_bytes <= self.tls_burst_max_resp_bytes
        ]
        if len(suspicious) < self.tls_burst_min_conns:
            return
        unique_hosts = {dst_h for dst_h, _, _, _, _ in suspicious if dst_h and dst_h != "-"}
        if len(unique_hosts) < self.tls_burst_min_unique_hosts:
            return

        self.alerts.emit({
            "type": "tls_burst_without_data",
            "severity": "high",
            "llm_bypass_gate": True,
            "summary": (
                f"Suspicious TLS burst without response data from {orig} "
                f"(events={len(suspicious)}, hosts={len(unique_hosts)})"
            ),
            "details": {
                "orig_h": orig,
                "interface": iface,
                "window_sec": self.tls_burst_window_sec,
                "events": len(suspicious),
                "unique_hosts": len(unique_hosts),
                "max_resp_bytes": self.tls_burst_max_resp_bytes,
                "max_duration_sec": self.tls_burst_max_duration_sec,
            },
        })
        dq.clear()

    def _handle_beaconing(self, ts, orig, resp_h, resp_p, iface):
        if not self.beaconing_enabled:
            return
        if not is_public_ip(resp_h):
            return
        key = (orig, resp_h, resp_p)
        dq = self._beacon_events[key]
        dq.append(ts)
        self._prune(dq, ts - self.beaconing_window_sec)
        if len(dq) < self.beaconing_min_events:
            return

        intervals = []
        for i in range(1, len(dq)):
            interval = dq[i] - dq[i - 1]
            if interval > 0:
                intervals.append(interval)
        if len(intervals) < self.beaconing_min_events - 1:
            return

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < self.beaconing_min_interval_sec or avg_interval > self.beaconing_max_interval_sec:
            return
        jitter = max(intervals) - min(intervals)
        if jitter > self.beaconing_max_jitter_sec:
            return

        last_alert_ts = self._beacon_last_alert_ts.get(key, 0.0)
        if ts - last_alert_ts < self.beaconing_alert_cooldown_sec:
            return
        self._beacon_last_alert_ts[key] = ts

        self.alerts.emit({
            "type": "beaconing_suspected",
            "severity": "high",
            "llm_bypass_gate": True,
            "summary": f"Possible beaconing pattern {orig} -> {resp_h}:{resp_p}",
            "details": {
                "orig_h": orig,
                "resp_h": resp_h,
                "resp_p": resp_p,
                "interface": iface,
                "events": len(dq),
                "window_sec": self.beaconing_window_sec,
                "avg_interval_sec": round(avg_interval, 3),
                "jitter_sec": round(jitter, 3),
            },
        })
        dq.clear()

    def handle_conn(self, rec, iface=""):
        try:
            ts = float(rec.get("ts", "0"))
        except ValueError:
            return
        orig = rec.get("id.orig_h", "")
        resp_p = rec.get("id.resp_p", "0")
        conn_state = rec.get("conn_state", "")
        resp_h = rec.get("id.resp_h", "")
        proto = rec.get("proto", "")
        service = rec.get("service", "")
        duration = self._parse_float(rec.get("duration", "0"), default=0.0)
        orig_bytes = self._parse_int(rec.get("orig_bytes", "0"), default=0)
        resp_bytes = self._parse_int(rec.get("resp_bytes", "0"), default=0)

        if not orig or resp_p == "-":
            return
        try:
            resp_p = int(resp_p)
        except ValueError:
            return

        if self.gate.process_conn(rec):
            self.alerts.emit({
                "type": "knockknock",
                "severity": "info",
                "summary": f"Knock sequence complete from {orig}; LLM guidance armed for {int(self.gate.armed_ttl_sec)}s",
                "details": {"orig_h": orig, "resp_h": resp_h, "sequence": self.gate.sequence, "interface": iface}
            })

        dq = self._conn_events[orig]
        dq.append((ts, resp_p, conn_state, resp_h, proto))
        self._prune(dq, ts - self.scan_window)

        filtered = []
        for _ets, port, st, dst_h, _proto in dq:
            if port in self.scan_excluded_ports:
                continue
            if self.scan_ignore_multicast_dest and is_multicast_or_broadcast(dst_h):
                continue
            filtered.append((_ets, port, st, dst_h, _proto))

        unique_ports = {p for _, p, _, _, _ in filtered}
        unique_hosts = {h for _, _, _, h, _ in filtered if h and h != "-"}
        unique_local_hosts = {h for h in unique_hosts if is_private_or_linklocal(h)}
        failed = sum(1 for _, _, st, _, _ in filtered if st in {"S0", "REJ", "RSTO", "RSTR"})

        reasons = []
        if len(unique_ports) >= self.scan_unique_ports_threshold:
            reasons.append("unique_ports")
        if len(unique_local_hosts) >= self.scan_unique_hosts_threshold:
            reasons.append("unique_local_hosts")
        if failed >= self.scan_failed_threshold:
            reasons.append("failed_connections")

        if reasons:
            scan_kind = "host_sweep" if "unique_local_hosts" in reasons else "scan"
            self.alerts.emit({
                "type": scan_kind,
                "severity": "high",
                "llm_bypass_gate": True,
                "summary": (
                    f"Possible misconduct from {orig} "
                    f"(ports={len(unique_ports)}, local_hosts={len(unique_local_hosts)}, failed={failed})"
                ),
                "details": {
                    "orig_h": orig,
                    "interface": iface,
                    "unique_ports": len(unique_ports),
                    "unique_hosts": len(unique_hosts),
                    "unique_local_hosts": len(unique_local_hosts),
                    "failed": failed,
                    "window_sec": self.scan_window,
                    "reasons": reasons
                }
            })
            dq.clear()

        self._handle_tls_burst_without_data(
            ts=ts,
            orig=orig,
            resp_h=resp_h,
            resp_p=resp_p,
            service=service,
            duration=duration,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            iface=iface,
        )
        self._handle_beaconing(ts=ts, orig=orig, resp_h=resp_h, resp_p=resp_p, iface=iface)
        self._handle_new_asn_country(ts=ts, orig=orig, resp_h=resp_h, iface=iface)

    def handle_dns(self, rec, iface=""):
        try:
            ts = float(rec.get("ts", "0"))
        except ValueError:
            return
        orig = rec.get("id.orig_h", "")
        query = rec.get("query", "")
        rcode = normalize_text(rec.get("rcode_name", ""))
        if not orig or not query:
            return
        dq = self._dns_events[orig]
        dq.append((ts, query, rcode))
        self._prune(dq, ts - self.dns_window)
        unique = {q for _, q, _ in dq if self._dns_query_is_eligible(q)}
        nxdomain = sum(1 for _, q, rc in dq if rc == "nxdomain" and self._dns_query_is_eligible(q))

        if len(query) >= self.dns_long_domain_len and self._dns_query_is_eligible(query):
            self.alerts.emit({
                "type": "dns_long_query",
                "severity": "medium",
                "summary": f"Long DNS query from {orig}: {query}",
                "details": {"orig_h": orig, "interface": iface, "query": query, "len": len(query)}
            })
            return

        if nxdomain >= self.dns_nxdomain_threshold:
            self.alerts.emit({
                "type": "dns_nxdomain_burst",
                "severity": "high",
                "llm_bypass_gate": True,
                "summary": f"High NXDOMAIN burst from {orig} (count={nxdomain})",
                "details": {
                    "orig_h": orig,
                    "interface": iface,
                    "nxdomain": nxdomain,
                    "window_sec": self.dns_window
                }
            })
            dq.clear()
            return

        if len(unique) >= self.dns_unique_domains_threshold:
            self.alerts.emit({
                "type": "dns_churn",
                "severity": "high",
                "llm_bypass_gate": True,
                "summary": f"High DNS churn from {orig} (unique={len(unique)})",
                "details": {
                    "orig_h": orig,
                    "interface": iface,
                    "unique_domains": len(unique),
                    "window_sec": self.dns_window
                }
            })
            dq.clear()

    def handle_notice(self, rec, iface=""):
        note = rec.get("note", "")
        msg = rec.get("msg", "")
        src = rec.get("src", "")
        if not note and not msg:
            return
        summary = f"Zeek notice {note}" if note else "Zeek notice"
        if msg:
            summary += f": {msg}"
        self.alerts.emit({
            "type": "notice",
            "severity": "high",
            "llm_bypass_gate": True,
            "summary": summary,
            "details": {"note": note, "msg": msg, "src": src, "interface": iface}
        })


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if not os.path.exists(path):
        return cfg
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    merge_dict(cfg, data)
    return cfg


def merge_dict(base, override):
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            merge_dict(base[k], v)
        else:
            base[k] = v


def start_zeek(interface, log_dir, zeek_script, use_sudo):
    zeek_bin = shutil.which("zeek")
    if not zeek_bin:
        raise FileNotFoundError("zeek not found in PATH")
    os.makedirs(log_dir, exist_ok=True)
    run_as_root = hasattr(os, "geteuid") and os.geteuid() == 0
    use_sudo_cmd = bool(use_sudo) and not run_as_root
    cmd = []
    if use_sudo_cmd:
        # -n prevents sudo from blocking on a hidden password prompt.
        cmd.extend(["sudo", "-n", zeek_bin])
    else:
        cmd.append(zeek_bin)
    cmd.extend([
        "-C",
        "-i",
        interface,
        "-e",
        f"redef Log::default_logdir=\"{log_dir}\"",
        zeek_script,
    ])
    stderr = subprocess.PIPE if use_sudo_cmd else subprocess.DEVNULL
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=stderr)
    if use_sudo_cmd:
        time.sleep(0.2)
        if proc.poll() is not None and proc.returncode != 0:
            err = ""
            try:
                err = proc.stderr.read().decode("utf-8", errors="replace").strip()
            except Exception:
                err = ""
            msg = "Zeek failed to start via sudo."
            if "password" in err.lower() or "a password is required" in err.lower():
                msg += " Run `sudo ./run.sh`, or run `sudo -v` to cache credentials."
            raise RuntimeError(msg)
    return proc


def main():
    parser = argparse.ArgumentParser(description="ZeekAns lightweight monitor")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--no-zeek", action="store_true")
    parser.add_argument("--test-alert", action="store_true", help="Emit a test alert and exit")
    parser.add_argument("--test-ollama", action="store_true", help="Arm LLM temporarily and emit a test alert")
    args = parser.parse_args()

    cfg = load_config(args.config)
    zeek_procs = []
    interfaces = []
    if cfg.get("interfaces"):
        interfaces = [str(i) for i in cfg.get("interfaces", []) if str(i)]
    elif cfg.get("interface"):
        interfaces = [str(cfg.get("interface"))]
    log_dir = os.path.abspath(cfg.get("log_dir", "./logs"))
    zeek_script = os.path.abspath(os.path.join("zeek", "local.zeek"))

    if not args.no_zeek and cfg.get("start_zeek", True):
        if not interfaces:
            print("Missing interface(s) in config.json", file=sys.stderr)
            sys.exit(1)
        try:
            for iface in interfaces:
                iface_log_dir = log_dir
                if cfg.get("interfaces"):
                    iface_log_dir = os.path.join(log_dir, iface)
                zeek_procs.append(start_zeek(iface, iface_log_dir, zeek_script, cfg.get("zeek_use_sudo", True)))
        except FileNotFoundError:
            print("Zeek not found in PATH. Install Zeek or run with --no-zeek.", file=sys.stderr)
            sys.exit(1)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        if cfg.get("interfaces"):
            print(f"Started Zeek on {', '.join(interfaces)}; logs in {log_dir}/<iface>")
        else:
            print(f"Started Zeek on {interfaces[0]}; logs in {log_dir}")

    gate = KnockGate(cfg.get("knockknock", {}))
    alerts = AlertManager(cfg.get("alerts", {}), cfg.get("ollama", {}), gate)
    detector = AnomalyDetector(cfg.get("anomaly", {}), gate, alerts)

    if args.test_alert or args.test_ollama:
        if args.test_ollama:
            gate.arm_for(60)
        alerts.emit({
            "type": "test",
            "summary": "Test alert from ZeekAns",
            "details": {"note": "If Ollama is enabled and gate is armed, guidance should appear."}
        })
        return

    tailers = []
    if not interfaces:
        print("Missing interface(s) in config.json", file=sys.stderr)
        sys.exit(1)
    for iface in interfaces:
        iface_log_dir = log_dir
        if cfg.get("interfaces"):
            iface_log_dir = os.path.join(log_dir, iface)
        conn_log = os.path.join(iface_log_dir, "conn.log")
        dns_log = os.path.join(iface_log_dir, "dns.log")
        notice_log = os.path.join(iface_log_dir, "notice.log")
        tailers.append((
            iface,
            LogTailer(conn_log),
            LogTailer(dns_log),
            LogTailer(notice_log, wait_for_file=False),
        ))

    stop = False

    def handle_sig(_sig, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    try:
        while not stop:
            for iface, tail_conn, tail_dns, tail_notice in tailers:
                for rec in tail_conn.read_new():
                    detector.handle_conn(rec, iface=iface)
                for rec in tail_dns.read_new():
                    detector.handle_dns(rec, iface=iface)
                for rec in tail_notice.read_new():
                    detector.handle_notice(rec, iface=iface)
            time.sleep(0.5)
    finally:
        for proc in zeek_procs:
            proc.terminate()


if __name__ == "__main__":
    main()
