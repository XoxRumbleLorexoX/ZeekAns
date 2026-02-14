#!/usr/bin/env python3
import argparse
import copy
import heapq
import importlib.util
import itertools
import sys
from pathlib import Path


def load_main_module(repo_root):
    module_path = repo_root / "python" / "main.py"
    spec = importlib.util.spec_from_file_location("zeekans_main", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {module_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def iter_zeek_tsv(path):
    fields = None
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            parts = line.split("\t")
            if len(parts) != len(fields):
                continue
            yield {fields[i]: parts[i] for i in range(len(fields))}


def parse_ts(rec):
    try:
        return float(rec.get("ts", "0"))
    except (TypeError, ValueError):
        return 0.0


def discover_sources(source_dir, interface_name):
    if any((source_dir / f).exists() for f in ("conn.log", "dns.log", "notice.log")):
        return [(interface_name, source_dir)]

    sources = []
    for entry in sorted(source_dir.iterdir()):
        if not entry.is_dir():
            continue
        if any((entry / f).exists() for f in ("conn.log", "dns.log", "notice.log")):
            sources.append((entry.name, entry))
    return sources


def replay_interface(detector, iface, source_dir, include_notice, max_records_per_log):
    specs = [
        ("conn", source_dir / "conn.log", detector.handle_conn),
        ("dns", source_dir / "dns.log", detector.handle_dns),
    ]
    if include_notice:
        specs.append(("notice", source_dir / "notice.log", detector.handle_notice))

    counter = itertools.count()
    heap = []
    counts = {"conn": 0, "dns": 0, "notice": 0}

    for log_type, log_path, handler in specs:
        if not log_path.exists():
            continue
        it = iter_zeek_tsv(log_path)
        try:
            first = next(it)
        except StopIteration:
            continue
        heapq.heappush(heap, (parse_ts(first), next(counter), log_type, first, it, handler))

    while heap:
        _, _, log_type, rec, it, handler = heapq.heappop(heap)
        if max_records_per_log and counts[log_type] >= max_records_per_log:
            continue
        handler(rec, iface=iface)
        counts[log_type] += 1
        try:
            nxt = next(it)
        except StopIteration:
            continue
        heapq.heappush(heap, (parse_ts(nxt), next(counter), log_type, nxt, it, handler))

    return counts


def main():
    parser = argparse.ArgumentParser(description="Replay Zeek logs through ZeekAns detectors")
    parser.add_argument("--config", default="config.json", help="Path to ZeekAns config file")
    parser.add_argument("--source", required=True, help="Path to source logs dir (single iface or multi-iface root)")
    parser.add_argument("--interface", default="replay", help="Interface label when source is a single log dir")
    parser.add_argument("--output-dir", default="./alerts/replay", help="Replay output directory")
    parser.add_argument("--enable-ollama", action="store_true", help="Enable Ollama guidance during replay")
    parser.add_argument("--include-notice", action="store_true", help="Replay notice.log records if present")
    parser.add_argument(
        "--max-records-per-log",
        type=int,
        default=0,
        help="Optional cap per log type (0 means no cap)",
    )
    parser.add_argument(
        "--truncate-output",
        action="store_true",
        help="Truncate replay alerts.log and alerts.jsonl before replaying",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    source_dir = Path(args.source).expanduser().resolve()
    config_path = Path(args.config).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not source_dir.exists():
        print(f"Source path not found: {source_dir}", file=sys.stderr)
        return 1
    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    mod = load_main_module(repo_root)
    cfg = mod.load_config(str(config_path))
    cfg = copy.deepcopy(cfg)
    cfg.setdefault("alerts", {})
    cfg.setdefault("ollama", {})
    cfg["alerts"]["output_dir"] = str(output_dir)
    cfg["ollama"]["enabled"] = bool(args.enable_ollama)

    if args.truncate_output:
        for name in ("alerts.log", "alerts.jsonl"):
            p = output_dir / name
            if p.exists():
                p.write_text("", encoding="utf-8")

    gate = mod.KnockGate(cfg.get("knockknock", {}))
    alerts = mod.AlertManager(cfg.get("alerts", {}), cfg.get("ollama", {}), gate)
    detector = mod.AnomalyDetector(cfg.get("anomaly", {}), gate, alerts)

    sources = discover_sources(source_dir, args.interface)
    if not sources:
        print(f"No replayable logs found under: {source_dir}", file=sys.stderr)
        return 1

    total = {"conn": 0, "dns": 0, "notice": 0}
    for iface, iface_dir in sources:
        counts = replay_interface(
            detector=detector,
            iface=iface,
            source_dir=iface_dir,
            include_notice=args.include_notice,
            max_records_per_log=args.max_records_per_log,
        )
        total["conn"] += counts.get("conn", 0)
        total["dns"] += counts.get("dns", 0)
        total["notice"] += counts.get("notice", 0)
        print(
            f"Replayed {iface}: conn={counts.get('conn', 0)} "
            f"dns={counts.get('dns', 0)} notice={counts.get('notice', 0)}"
        )

    print(
        f"Replay complete. Total records: conn={total['conn']} dns={total['dns']} notice={total['notice']}. "
        f"Alerts in: {output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
