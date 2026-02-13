#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

python3 "$SCRIPT_DIR/python/main.py" --config "$SCRIPT_DIR/config.json"
