#!/usr/bin/env bash
set -euo pipefail
# cyberlab CLI - macOS / Linux wrapper
if [ ! -x ".venv/bin/python" ]; then
    echo ".venv not found. Run ./install.sh first."
    exit 1
fi
.venv/bin/python -m cyberlab "$@"
