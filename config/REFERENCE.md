# ZeekAns config field reference

## Top-level
- `interface` (string): Single interface mode; ignored when `interfaces` is non-empty.
- `interfaces` (array[string]): Multi-interface mode; each interface gets its own log dir.
- `start_zeek` (bool): Start Zeek child process(es) from ZeekAns.
- `zeek_use_sudo` (bool): Use `sudo -n zeek` when not already running as root.
- `log_dir` (string): Base log directory for Zeek logs.

## `ollama`
- `enabled` (bool): Enable local LLM guidance generation.
- `url` (string): Ollama generate endpoint.
- `model` (string): Ollama model identifier.
- `timeout_sec` (number): Request timeout for Ollama calls.

## `alerts`
- `output_dir` (string): Output dir for `alerts.log` and `alerts.jsonl`.
- `cooldown_sec` (number): Minimum seconds between guidance requests.
- `llm_bypass_gate_severities` (array[string]): Severities that bypass knock gate.
- `llm_bypass_gate_types` (array[string]): Alert types that bypass knock gate.

## `knockknock`
- `enabled` (bool): Enable knock-sequence arming.
- `sequence_ports` (array[int]): Ordered port sequence used to arm guidance.
- `window_sec` (number): Sequence must complete within this window.
- `armed_ttl_sec` (number): Guidance remains armed for this duration.
- `admin_ip` (string): Optional source IP restriction for knocks.
- `local_ips` (array[string]): Optional destination IP allowlist for knocks.

## `anomaly` baseline detectors
- `scan_window_sec` (number): Sliding window for scan/sweep aggregation.
- `scan_unique_ports_threshold` (int): Unique port count threshold for scan alerting.
- `scan_unique_hosts_threshold` (int): Unique local host threshold for sweep alerting.
- `scan_failed_threshold` (int): Failed connection threshold for scan alerting.
- `scan_excluded_ports` (array[int]): Ports ignored by scan logic.
- `scan_ignore_multicast_dest` (bool): Ignore multicast/broadcast destinations in scan logic.
- `dns_window_sec` (number): Sliding window for DNS heuristics.
- `dns_unique_domains_threshold` (int): Unique domain threshold for churn alerts.
- `dns_long_domain_len` (int): Query length threshold for long-domain alerts.
- `dns_nxdomain_threshold` (int): NXDOMAIN count threshold.
- `dns_ignore_suffixes` (array[string]): Domain suffixes excluded from DNS heuristics.

## `anomaly` optional heuristics
- `new_asn_country_enabled` (bool): Enable new ASN/country detection for external destinations.
- `new_asn_country_warmup_sec` (number): Baseline-learning period before ASN/country alerts.
- `new_asn_country_lookup_url` (string): URL template for IP metadata lookup; include `{ip}`.
- `new_asn_country_lookup_timeout_sec` (number): Timeout per metadata lookup.
- `new_asn_country_lookup_min_interval_sec` (number): Minimum delay between metadata lookups.
- `new_asn_country_known_asns` (array[string]): Baseline ASN allowlist (for example `AS15169`).
- `new_asn_country_known_countries` (array[string]): Baseline country-code allowlist (for example `US`).
- `tls_burst_without_data_enabled` (bool): Enable TLS burst-without-data heuristic.
- `tls_burst_window_sec` (number): Sliding window for TLS burst detection.
- `tls_burst_min_conns` (int): Minimum suspicious TLS events in window.
- `tls_burst_min_unique_hosts` (int): Minimum unique destination hosts for TLS burst alerts.
- `tls_burst_max_resp_bytes` (int): Maximum response bytes considered "without data".
- `tls_burst_max_duration_sec` (number): Maximum connection duration for suspicious TLS events.
- `beaconing_enabled` (bool): Enable periodic beaconing detection.
- `beaconing_window_sec` (number): Sliding window for beaconing analysis.
- `beaconing_min_events` (int): Minimum events per destination to evaluate periodicity.
- `beaconing_min_interval_sec` (number): Minimum average interval for beacon candidates.
- `beaconing_max_interval_sec` (number): Maximum average interval for beacon candidates.
- `beaconing_max_jitter_sec` (number): Maximum allowed interval jitter.
- `beaconing_alert_cooldown_sec` (number): Minimum delay before repeating same beacon alert.
