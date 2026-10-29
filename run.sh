#!/usr/bin/env bash
set -euo pipefail
# cyberterminal - macOS / Linux / Windows (git-bash) wrapper
# Prefers the single-file binary in dist/ if present, falls back to the venv.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$ROOT_DIR/dist/cyberterminal"

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    BINARY="$ROOT_DIR/dist/cyberterminal.exe"
    VENV_PY="$ROOT_DIR/.venv/Scripts/python.exe"
else
    VENV_PY="$ROOT_DIR/.venv/bin/python"
fi

if [ -x "$BINARY" ]; then
    exec "$BINARY" "$@"
fi

if [ ! -x "$VENV_PY" ]; then
    echo "No dist/cyberterminal binary and .venv not found. Run ./install.sh first."
    exit 1
fi

"$VENV_PY" -m src.terminal "$@"
