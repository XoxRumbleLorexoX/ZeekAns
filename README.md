# ZeekAns

Lightweight, local network anomaly monitor that uses Zeek for telemetry, Python for detection, and Ollama for on-box LLM guidance. It includes a knockknock (port-knock) gate so LLM guidance only activates after a short, deliberate knock sequence.

## Why/When to use
Use ZeekAns when you want local-first anomaly triage without deploying a full SIEM stack.

- Good fit: home labs, small office networks, developer/test networks, and edge hosts where lightweight monitoring is preferred.
- Good fit: environments where you already trust Zeek logs and want practical anomaly signals plus optional on-box guidance.
- Tradeoff: heuristic detection is faster to deploy but can produce false positives until tuned.
- Tradeoff: optional enrichment heuristics can use external metadata lookups when enabled.
- Not ideal: centralized compliance-heavy environments that need full correlation, case management, and long-term retention controls out of the box.

## Requirements
- Zeek installed and available on your PATH
- Ollama running locally (default: `http://127.0.0.1:11434`)
- Python 3.9+

## Platform setup notes
macOS:
- Interface names are typically `en0`, `en1`, `en7`. List them with `ifconfig -l`.
- Packet capture requires elevated privileges; default config uses `zeek_use_sudo: true`.
- For startup service, use `./scripts/service_macos.sh install`.

Linux:
- Interface names are typically `eth0`, `ens160`, `enp3s0`. List them with `ip -br link`.
- Run as root (`sudo ./run.sh`) or grant packet-capture capabilities to Zeek and set `zeek_use_sudo: false`.
- A systemd unit example is provided at `scripts/zeekans.service.example`.

## Quick start
1) Configure your interface(s) and (optionally) local IPs in `config.json`.
2) Start Ollama and pull a model (example: `ollama pull llama3.1`).
3) Run:

```
./run.sh
```

Logs land in `./logs`. When `interfaces` is set, each interface writes to `./logs/<iface>/`. Alerts are written to `./alerts/alerts.log` and `./alerts/alerts.jsonl`.
Because Zeek needs packet-capture privileges on macOS, this project defaults to running Zeek via `sudo` (`zeek_use_sudo: true`).

## Example configs and reference
Example presets are provided under `config/examples/`:
- `config/examples/home.json`: small/quiet network profile
- `config/examples/server-only.json`: single Linux server profile
- `config/examples/lab.json`: multi-interface lab profile with optional heuristics enabled

Full field reference:
- `config/REFERENCE.md`

## Knockknock gate
The LLM guidance is only emitted when a port-knock sequence is observed. This keeps the system quiet unless you deliberately “arm” it.

- Configure the sequence in `config.json` under `knockknock.sequence_ports`.
- Optionally set `knockknock.admin_ip` to lock arming to your admin IP.
- Optionally set `knockknock.local_ips` to the IPs on this machine so only knocks to those addresses count.

When the sequence is completed within `knockknock.window_sec`, guidance is armed for `knockknock.armed_ttl_sec` seconds.

High-severity alerts can bypass the knock gate and still request LLM guidance (configured via `alerts.llm_bypass_gate_severities` and `alerts.llm_bypass_gate_types`).

## How it detects anomalies
- **Port scan heuristics** from `conn.log` (unique ports or failed connections in a short window)
- **Host sweep heuristics** (many unique destination hosts in a short window)
- **DNS churn/long queries** from `dns.log`
- **NXDOMAIN burst detection** from `dns.log`
- **Zeek notices** from `notice.log` (built-in scan detection is enabled)
- **Optional heuristics** (disabled by default): new ASN/country, TLS burst without data, and beaconing patterns

## Threshold tuning guide
Start with default values, run for 24-48 hours, then adjust using alert volume and false positives.

Key knobs in `config.json`:
- `scan_unique_ports_threshold`: lower catches scans faster, higher reduces noise.
- `scan_unique_hosts_threshold`: lower catches host sweeps faster, higher reduces local broadcast/multicast noise.
- `scan_failed_threshold`: lower catches failed-connection probing faster, higher avoids brief transient bursts.
- `dns_unique_domains_threshold`: lower catches DGA/churn faster, higher avoids normal high-churn clients.
- `dns_nxdomain_threshold`: lower catches typo-squatting/beacon failures faster, higher reduces noisy resolver/client behavior.
- `dns_long_domain_len`: lower is more sensitive to encoded/exfil-like queries, higher is stricter.

Suggested profiles:

Quiet home/SMB network (more sensitive):
- `scan_unique_ports_threshold`: `12`
- `scan_unique_hosts_threshold`: `12`
- `scan_failed_threshold`: `10`
- `dns_unique_domains_threshold`: `20`
- `dns_nxdomain_threshold`: `8`
- `dns_long_domain_len`: `50`

Typical mixed network (balanced/default-ish):
- `scan_unique_ports_threshold`: `20`
- `scan_unique_hosts_threshold`: `20`
- `scan_failed_threshold`: `15`
- `dns_unique_domains_threshold`: `30`
- `dns_nxdomain_threshold`: `12`
- `dns_long_domain_len`: `60`

Noisy lab/dev/test network (less sensitive):
- `scan_unique_ports_threshold`: `35`
- `scan_unique_hosts_threshold`: `30`
- `scan_failed_threshold`: `25`
- `dns_unique_domains_threshold`: `60`
- `dns_nxdomain_threshold`: `25`
- `dns_long_domain_len`: `75`

Practical tuning loop:
1. Keep one profile for 1 day.
2. Review `alerts/alerts.jsonl` and group false positives by `type` and `orig_h`.
3. Raise only the threshold tied to that noisy alert type.
4. Repeat until daily alert volume is manageable.

## Optional heuristics
The following are implemented and off by default:

- `new_asn_country_enabled`: alerts when external destinations resolve to previously unseen ASN/country values after warmup.
- `tls_burst_without_data_enabled`: alerts on bursts of TLS sessions that quickly return little/no response data.
- `beaconing_enabled`: alerts on periodic outbound connections with low interval jitter.

Tune these carefully in `config.json` (or start from `config/examples/lab.json`) before enabling in production.

## Alert format (`alerts.jsonl`)
Each line in `./alerts/alerts.jsonl` is a standalone JSON object:

- `ts` (string, UTC ISO-8601): alert timestamp
- `type` (string): alert class such as `scan`, `host_sweep`, `dns_churn`, `dns_nxdomain_burst`, `dns_long_query`, `notice`, `knockknock`, `test`
- `severity` (string): `info`, `medium`, `high`, or `critical`
- `summary` (string): human-readable alert summary
- `details` (object): structured fields for investigation (for example `orig_h`, `interface`, thresholds/counts, Zeek notice fields)
- `llm_bypass_gate` (boolean, optional): present when guidance was allowed without knock-gate arming
- `guidance` (string, optional): Ollama response when guidance generation is enabled and triggered

Example:

```json
{"ts":"2026-02-14T10:08:11Z","type":"dns_nxdomain_burst","severity":"high","summary":"High NXDOMAIN burst from 192.168.10.226 (count=14)","details":{"orig_h":"192.168.10.226","interface":"en1","nxdomain":14,"window_sec":60},"llm_bypass_gate":true}
```

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

## Replay logs for validation
Replay existing Zeek logs through current detector logic (no live capture required):

```bash
python3 scripts/replay_logs.py --config config.json --source ./logs --include-notice --truncate-output
```

This writes replay alerts to `./alerts/replay/alerts.log` and `./alerts/replay/alerts.jsonl`.

## Multi-interface mode
Set `interfaces` in `config.json` to run one Zeek process per interface:

```
"interfaces": ["en1", "en2", "en7"]
```

Each interface writes logs under `./logs/<iface>/` and the Python monitor tails all of them.

## Run at startup (macOS)
Install as a `launchd` system service:

```bash
./scripts/service_macos.sh install
```

The installer now performs preflight checks for:
- `python3` and `zeek` on the daemon PATH
- valid `config.json`
- configured network interfaces existing on the host

Check status:

```bash
./scripts/service_macos.sh status
```

Restart the service:

```bash
./scripts/service_macos.sh restart
```

Startup logs:

```bash
./scripts/service_macos.sh logs 120
```

Remove startup service:

```bash
./scripts/service_macos.sh uninstall
```

## Run at startup (Linux/systemd)
Use the example unit:

```bash
sudo cp scripts/zeekans.service.example /etc/systemd/system/zeekans.service
sudo systemctl daemon-reload
sudo systemctl enable --now zeekans
sudo systemctl status zeekans
```

Edit paths in the unit first if your repo is not at `/opt/zeekans`.

## Log rotation and retention
Linux (`logrotate`) example:

```bash
sudo cp scripts/logrotate.zeekans.example /etc/logrotate.d/zeekans
sudo logrotate -f /etc/logrotate.d/zeekans
```

Recommended baseline:
- rotate daily, keep 14 compressed archives for hot troubleshooting
- keep `alerts.jsonl` longer than packet-derived logs when storage is constrained
- forward alerts to centralized storage if you need retention beyond local disk

## Notes
- This is meant to be lightweight: no external Python dependencies.
- Tune thresholds in `config.json` for your environment.
