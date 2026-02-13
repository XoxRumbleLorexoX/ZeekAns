#!/usr/bin/env bash
set -euo pipefail

LABEL="com.zeekans.monitor"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUN_SCRIPT="${REPO_ROOT}/run.sh"
CONFIG_PATH="${REPO_ROOT}/config.json"
LOG_DIR="${REPO_ROOT}/logs"
STDOUT_LOG="${LOG_DIR}/launchd.stdout.log"
STDERR_LOG="${LOG_DIR}/launchd.stderr.log"
LAUNCHD_PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
LEGACY_TMP_PLIST="/tmp/${LABEL}.XXXXXX.plist"
if [[ -f "${LEGACY_TMP_PLIST}" ]]; then
  rm -f "${LEGACY_TMP_PLIST}"
fi
TMP_BASE="$(mktemp -t "${LABEL}")"
TMP_PLIST="${TMP_BASE}.plist"
mv "${TMP_BASE}" "${TMP_PLIST}"
trap 'rm -f "${TMP_PLIST}"' EXIT

require_launchd_cmd() {
  local cmd="$1"
  if ! PATH="${LAUNCHD_PATH}" command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command for startup service: ${cmd}" >&2
    echo "Expected command search PATH: ${LAUNCHD_PATH}" >&2
    exit 1
  fi
}

if [[ ! -x "${RUN_SCRIPT}" ]]; then
  echo "Missing executable run script: ${RUN_SCRIPT}" >&2
  exit 1
fi

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Missing config file: ${CONFIG_PATH}" >&2
  exit 1
fi

require_launchd_cmd "python3"
require_launchd_cmd "zeek"

if ! INTERFACES="$(python3 - "${CONFIG_PATH}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    cfg = json.load(f)

interfaces = [str(i) for i in cfg.get("interfaces", []) if str(i)]
if not interfaces and cfg.get("interface"):
    interfaces = [str(cfg.get("interface"))]

print(" ".join(interfaces))
PY
)"; then
  echo "Failed to parse interfaces from ${CONFIG_PATH}" >&2
  exit 1
fi

if [[ -z "${INTERFACES}" ]]; then
  echo "No interface(s) configured in ${CONFIG_PATH}. Set interface or interfaces." >&2
  exit 1
fi

for iface in ${INTERFACES}; do
  if ! /sbin/ifconfig "${iface}" >/dev/null 2>&1; then
    echo "Configured interface not found on this host: ${iface}" >&2
    exit 1
  fi
done

mkdir -p "${LOG_DIR}"

cat > "${TMP_PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${RUN_SCRIPT}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${REPO_ROOT}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>${LAUNCHD_PATH}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>30</integer>
  <key>StandardOutPath</key>
  <string>${STDOUT_LOG}</string>
  <key>StandardErrorPath</key>
  <string>${STDERR_LOG}</string>
</dict>
</plist>
EOF

sudo install -m 0644 "${TMP_PLIST}" "${PLIST_PATH}"

if sudo launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  sudo launchctl bootout system "${PLIST_PATH}" || true
fi

sudo launchctl bootstrap system "${PLIST_PATH}"
sudo launchctl enable "system/${LABEL}"
sudo launchctl kickstart -k "system/${LABEL}"

echo "Installed and started: ${LABEL}"
echo "Status: sudo launchctl print system/${LABEL}"
echo "Logs: ${STDOUT_LOG} and ${STDERR_LOG}"
