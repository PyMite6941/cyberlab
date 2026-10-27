#!/usr/bin/env bash
set -euo pipefail
# cyberterminal - macOS / Linux wrapper
if [ ! -x ".venv/bin/python" ]; then
    echo ".venv not found. Run ./install.sh first."
    exit 1
fi
.venv/bin/python -m src.terminal "$@"
