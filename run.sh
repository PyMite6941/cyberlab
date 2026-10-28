#!/usr/bin/env bash
set -euo pipefail
# cyberterminal - macOS / Linux / Windows (git-bash) wrapper
# Detect OS and use the correct venv python path.
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    VENV_PY=".venv/Scripts/python.exe"
else
    VENV_PY=".venv/bin/python"
fi

if [ ! -x "$VENV_PY" ]; then
    echo ".venv not found. Run ./install.sh first."
    exit 1
fi

"$VENV_PY" -m src.terminal "$@"
