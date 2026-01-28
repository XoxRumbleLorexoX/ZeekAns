# ZeekAns

Lightweight, local network anomaly monitor that uses Zeek for telemetry, Python for detection, and Ollama for on-box LLM guidance. It includes a knockknock (port-knock) gate so LLM guidance only activates after a short, deliberate knock sequence.

## Requirements
- Zeek installed and available on your PATH
- Ollama running locally (default: `http://127.0.0.1:11434`)
- Python 3.9+

## Quick start
1) Configure your interface(s) and (optionally) local IPs in `config.json`.
2) Start Ollama and pull a model (example: `ollama pull llama3.1`).
3) Run:

```
./run.sh
```

Logs land in `./logs`. When `interfaces` is set, each interface writes to `./logs/<iface>/`. Alerts are written to `./alerts/alerts.log` and `./alerts/alerts.jsonl`.
Because Zeek needs packet-capture privileges on macOS, this project defaults to running Zeek via `sudo` (`zeek_use_sudo: true`).

## Knockknock gate
The LLM guidance is only emitted when a port-knock sequence is observed. This keeps the system quiet unless you deliberately “arm” it.

- Configure the sequence in `config.json` under `knockknock.sequence_ports`.
- Optionally set `knockknock.admin_ip` to lock arming to your admin IP.
- Optionally set `knockknock.local_ips` to the IPs on this machine so only knocks to those addresses count.

When the sequence is completed within `knockknock.window_sec`, guidance is armed for `knockknock.armed_ttl_sec` seconds.

## How it detects anomalies
- **Port scan heuristics** from `conn.log` (unique ports or failed connections in a short window)
- **DNS churn/long queries** from `dns.log`
- **Zeek notices** from `notice.log` (built-in scan detection is enabled)

## Run without Zeek (if you already have it running)
```
python3 python/main.py --config config.json --no-zeek
```

## Test alert (LLM wiring)
Emit a test alert without waiting for traffic:

```
python3 python/main.py --config config.json --no-zeek --test-alert
```

To force LLM guidance for the test (temporarily arms the gate for 60s):

```
python3 python/main.py --config config.json --no-zeek --test-ollama
```

## Multi-interface mode
Set `interfaces` in `config.json` to run one Zeek process per interface:

```
"interfaces": ["en1", "en2", "en7"]
```

Each interface writes logs under `./logs/<iface>/` and the Python monitor tails all of them.

## Notes
- This is meant to be lightweight: no external Python dependencies.
- Tune thresholds in `config.json` for your environment.
