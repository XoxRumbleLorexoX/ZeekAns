# TODO

## Documentation & onboarding
- [x] Add a "Why/When to Use" section with target environments and tradeoffs.
- [x] Add platform-specific setup notes (macOS/Linux interface names, permissions).
- [x] Document alert formats with an example `alerts.jsonl` entry.
- [x] Add example configs (home, server-only, lab) and a config field reference.

## Detection & tuning
- [x] Add tuning guidance for thresholds (quiet vs. noisy networks).
- [x] Add optional heuristics (new ASN/country, TLS burst without data, beaconing).
- [x] Add a log replay script for validating detections end-to-end.

## Operations
- [x] Add a systemd service example for long-running deployment.
- [x] Document log rotation and retention guidance.

## Visualization experiments
- [ ] Define "Hex Live" as a real-time event stream to hex-grid visualization.
- [ ] Prototype a "music of processes" mapping (events -> pitch/rhythm).
- [ ] Prototype a 3D visualizer for the hex live stream.
- [ ] Build a globe view showing geolocated IPs for active alerts.
