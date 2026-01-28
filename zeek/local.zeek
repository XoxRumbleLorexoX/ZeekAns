# Lightweight Zeek policy for anomaly surfacing.
# Keeps logic light; detection is handled by Python.

# Optionally log DNS and connection details (defaults already enabled).
@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice
