#!/usr/bin/env bash
set -euo pipefail
# cyberlab - activate and run the cyberterminal environment
# Usage: ./cyberlab.sh              # auto-detect binary or python mode
#        ./cyberlab.sh --binary     # force the single-file dist/ binary
#        ./cyberlab.sh --python     # force the venv + source files
#        ./cyberlab.sh --install    # run install.py setup first

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BINARY="dist/cyberterminal.exe"
VENV_PY=".venv/Scripts/python.exe"
MODE="auto"

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) MODE="binary" ;;
        --python) MODE="python" ;;
        --install) python3 install.py "$@" ; shift ;;
        --help|-h)
            echo "Usage: ./cyberlab.sh [--binary|--python|--install]"
            echo "  --binary  Force the single-file dist/ binary (no Python needed)"
            echo "  --python  Force the venv + source files (Python required)"
            echo "  --install Run install.py setup before launching"
            echo "  (auto)    Use dist/ binary if present, else venv python"
            exit 0
            ;;
        *) shift ;;
    esac
done

if [ "$MODE" = "install" ]; then
    echo "Install complete. Re-run ./cyberlab.sh to launch."
    exit 0
fi

# Decide mode
if [ "$MODE" = "auto" ]; then
    if [ -x "$BINARY" ]; then
        MODE="binary"
    elif [ -x "$VENV_PY" ]; then
        MODE="python"
    else
        echo "No dist/cyberterminal.exe and .venv not found."
        echo "Run:  ./cyberlab.sh --install   (then ./cyberlab.sh)"
        exit 1
    fi
fi

if [ "$MODE" = "binary" ]; then
    exec "$BINARY" "$@"
else
    exec "$VENV_PY" -m src.terminal "$@"
fi
