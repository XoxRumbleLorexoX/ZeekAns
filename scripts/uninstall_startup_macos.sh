#!/usr/bin/env bash
set -euo pipefail

LABEL="com.zeekans.monitor"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"

sudo launchctl disable "system/${LABEL}" >/dev/null 2>&1 || true
sudo launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || sudo launchctl bootout system "${PLIST_PATH}" >/dev/null 2>&1 || true

if [[ -f "${PLIST_PATH}" ]]; then
  sudo rm -f "${PLIST_PATH}"
fi

echo "Uninstalled: ${LABEL}"
