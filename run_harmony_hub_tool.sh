#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOL="$SCRIPT_DIR/run_harmony_hub_tool.py"

if [ ! -f "$TOOL" ]; then
  echo "ERROR: run_harmony_hub_tool.py was not found next to this launcher." >&2
  echo "Expected: $TOOL" >&2
  exit 1
fi

if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
  PYTHON_EXE="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_EXE="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_EXE="python"
else
  echo "ERROR: Python 3 was not found. Install Python 3 or create .venv/bin/python next to this launcher." >&2
  exit 1
fi

exec "$PYTHON_EXE" "$TOOL" "$@"
