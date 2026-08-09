#!/usr/bin/env bash
# Wrapper for encrypt.py — sets up a venv on first run, then delegates to the script.
#
# Usage:
#   ./encrypt.sh encrypt <file_or_dir>
#   ./encrypt.sh decrypt <file_or_dir> [<output_dir>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# Create venv and install dependencies if not already done
if [[ ! -f "$VENV_DIR/bin/python" ]]; then
    echo "Setting up virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
    echo "Setup complete."
    echo ""
fi

exec "$VENV_DIR/bin/python" "$SCRIPT_DIR/encrypt.py" "$@"
