#!/usr/bin/env bash
# Install everything for the cyber class, offline:
#
#   ./install.sh               security tools (asks for your sudo password) + cyberlab
#   ./install.sh --skip-tools  only cyberlab
#
# Run it as your normal user, not with sudo: cyberlab is installed for you,
# and only the tools step uses sudo.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_TOOLS=0
for arg in "$@"; do
    case "$arg" in
        --skip-tools) SKIP_TOOLS=1 ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        *) echo "Unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done
if [ "$(id -u)" -eq 0 ]; then
    echo "Run this as your normal user, without sudo:  ./install.sh" >&2
    echo "(It asks for your password when it needs it.)" >&2
    exit 1
fi

if [ "$SKIP_TOOLS" -eq 0 ]; then
    echo "== 1/2  Security tools (offline, needs sudo) =="
    sudo bash "$HERE/tools/install.sh"
    echo
fi

echo "== 2/2  cyberlab =="
# A stable copy, so deleting this unpacked folder later doesn't break cyberlab.
# (Progress lives separately, in ~/cyberlab, and is kept.)
DEST="${XDG_DATA_HOME:-$HOME/.local/share}/cyberlab-app"
rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
cp -R "$HERE/cyberlab" "$DEST"
sh "$DEST/setup.sh"
