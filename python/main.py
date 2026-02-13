#!/usr/bin/env python3
import argparse
import json
import os
import signal
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict, deque
from datetime import datetime

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
        "cooldown_sec": 30
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
        "scan_failed_threshold": 15,
        "dns_window_sec": 60,
        "dns_unique_domains_threshold": 30,
        "dns_long_domain_len": 60
    }
}


class LogTailer:
    def __init__(self, path, start_at_end=True):
        self.path = path
        self.start_at_end = start_at_end
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
            return
        while not os.path.exists(self.path):
            time.sleep(0.2)
        self._open()

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
        self._ensure_open()
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
        self._last_llm_ts = 0.0
        os.makedirs(self.output_dir, exist_ok=True)
        self.text_log = os.path.join(self.output_dir, "alerts.log")
        self.json_log = os.path.join(self.output_dir, "alerts.jsonl")

    def _ollama_generate(self, event):
        if not self.ollama_cfg.get("enabled", True):
            return ""
        if time.time() - self._last_llm_ts < self.cooldown_sec:
            return ""
        if not self.gate.is_armed():
            return ""

        prompt = (
            "You are a local SOC assistant. Provide concise next steps.\n"
            "Focus on verification, containment, and data collection.\n"
            "Use short bullet points and include relevant Zeek log hints.\n\n"
            f"Event: {event['summary']}\n"
            f"Type: {event['type']}\n"
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
        ts = datetime.utcnow().isoformat() + "Z"
        record = {
            "ts": ts,
            "type": event.get("type", "unknown"),
            "summary": event.get("summary", ""),
            "details": event.get("details", {}),
        }
        guidance = self._ollama_generate(record)
        if guidance:
            record["guidance"] = guidance

        line = f"[{ts}] {record['type']} - {record['summary']}"
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
        self.scan_failed_threshold = int(cfg.get("scan_failed_threshold", 15))
        self.dns_window = float(cfg.get("dns_window_sec", 60))
        self.dns_unique_domains_threshold = int(cfg.get("dns_unique_domains_threshold", 30))
        self.dns_long_domain_len = int(cfg.get("dns_long_domain_len", 60))

        self._conn_events = defaultdict(deque)
        self._dns_events = defaultdict(deque)

    def _prune(self, dq, cutoff_ts):
        while dq and dq[0][0] < cutoff_ts:
            dq.popleft()

    def handle_conn(self, rec):
        try:
            ts = float(rec.get("ts", "0"))
        except ValueError:
            return
        orig = rec.get("id.orig_h", "")
        resp_p = rec.get("id.resp_p", "0")
        conn_state = rec.get("conn_state", "")
        resp_h = rec.get("id.resp_h", "")

        if not orig or resp_p == "-":
            return
        try:
            resp_p = int(resp_p)
        except ValueError:
            return

        if self.gate.process_conn(rec):
            self.alerts.emit({
                "type": "knockknock",
                "summary": f"Knock sequence complete from {orig}; LLM guidance armed for {int(self.gate.armed_ttl_sec)}s",
                "details": {"orig_h": orig, "resp_h": resp_h, "sequence": self.gate.sequence}
            })

        dq = self._conn_events[orig]
        dq.append((ts, resp_p, conn_state, resp_h))
        self._prune(dq, ts - self.scan_window)

        unique_ports = {p for _, p, _, _ in dq}
        failed = sum(1 for _, _, st, _ in dq if st in {"S0", "REJ", "RSTO", "RSTR"})

        if len(unique_ports) >= self.scan_unique_ports_threshold or failed >= self.scan_failed_threshold:
            self.alerts.emit({
                "type": "scan",
                "summary": f"Possible scan from {orig} (ports={len(unique_ports)}, failed={failed})",
                "details": {
                    "orig_h": orig,
                    "unique_ports": len(unique_ports),
                    "failed": failed,
                    "window_sec": self.scan_window
                }
            })
            dq.clear()

    def handle_dns(self, rec):
        try:
            ts = float(rec.get("ts", "0"))
        except ValueError:
            return
        orig = rec.get("id.orig_h", "")
        query = rec.get("query", "")
        if not orig or not query:
            return
        dq = self._dns_events[orig]
        dq.append((ts, query))
        self._prune(dq, ts - self.dns_window)
        unique = {q for _, q in dq}

        if len(query) >= self.dns_long_domain_len:
            self.alerts.emit({
                "type": "dns",
                "summary": f"Long DNS query from {orig}: {query}",
                "details": {"orig_h": orig, "query": query, "len": len(query)}
            })
            return

        if len(unique) >= self.dns_unique_domains_threshold:
            self.alerts.emit({
                "type": "dns",
                "summary": f"High DNS churn from {orig} (unique={len(unique)})",
                "details": {
                    "orig_h": orig,
                    "unique_domains": len(unique),
                    "window_sec": self.dns_window
                }
            })
            dq.clear()

    def handle_notice(self, rec):
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
            "summary": summary,
            "details": {"note": note, "msg": msg, "src": src}
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
        tailers.append((LogTailer(conn_log), LogTailer(dns_log), LogTailer(notice_log)))

    stop = False

    def handle_sig(_sig, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    try:
        while not stop:
            for tail_conn, tail_dns, tail_notice in tailers:
                for rec in tail_conn.read_new():
                    detector.handle_conn(rec)
                for rec in tail_dns.read_new():
                    detector.handle_dns(rec)
                for rec in tail_notice.read_new():
                    detector.handle_notice(rec)
            time.sleep(0.5)
    finally:
        for proc in zeek_procs:
            proc.terminate()


if __name__ == "__main__":
    main()
