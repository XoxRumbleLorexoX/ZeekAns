#!/usr/bin/env bash
set -euo pipefail

LABEL="com.zeekans.monitor"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SCRIPT="${SCRIPT_DIR}/install_startup_macos.sh"
UNINSTALL_SCRIPT="${SCRIPT_DIR}/uninstall_startup_macos.sh"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STDOUT_LOG="${REPO_ROOT}/logs/launchd.stdout.log"
STDERR_LOG="${REPO_ROOT}/logs/launchd.stderr.log"

usage() {
  cat <<EOF
Usage: ./scripts/service_macos.sh <command>

Commands:
  install           Install and start service
  uninstall         Stop and remove service
  status            Show launchd service status
  restart           Restart loaded service
  logs [N]          Show last N log lines (default: 120) from stdout/stderr logs
EOF
}

cmd="${1:-}"

case "${cmd}" in
  install)
    "${INSTALL_SCRIPT}"
    ;;
  uninstall)
    "${UNINSTALL_SCRIPT}"
    ;;
  status)
    sudo launchctl print "system/${LABEL}"
    ;;
  restart)
    if sudo launchctl print "system/${LABEL}" >/dev/null 2>&1; then
      sudo launchctl kickstart -k "system/${LABEL}"
      sudo launchctl print "system/${LABEL}" | sed -n '1,40p'
    else
      echo "Service not loaded: ${LABEL}. Run ./scripts/service_macos.sh install" >&2
      exit 1
    fi
    ;;
  logs)
    lines="${2:-120}"
    if ! [[ "${lines}" =~ ^[0-9]+$ ]]; then
      echo "logs expects a numeric line count, got: ${lines}" >&2
      exit 1
    fi
    echo "=== ${STDOUT_LOG} ==="
    if [[ -f "${STDOUT_LOG}" ]]; then
      tail -n "${lines}" "${STDOUT_LOG}"
    else
      echo "(missing)"
    fi
    echo "=== ${STDERR_LOG} ==="
    if [[ -f "${STDERR_LOG}" ]]; then
      tail -n "${lines}" "${STDERR_LOG}"
    else
      echo "(missing)"
    fi
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
