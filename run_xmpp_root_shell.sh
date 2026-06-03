#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: python3 was not found. Install Python 3.10+ and try again." >&2
  exit 1
fi

exec "$PYTHON_BIN" ./harmony_xmpp_root_shell.py "$@"
