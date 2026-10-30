#!/bin/sh
# One-time setup: make `cyberlab` a command you can run from anywhere.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HOME/.local/bin"
ln -sf "$DIR/bin/cyberlab" "$HOME/.local/bin/cyberlab"
echo "Linked $HOME/.local/bin/cyberlab -> $DIR/bin/cyberlab"
case ":$PATH:" in
    *":$HOME/.local/bin:"*) echo "Ready: try  cyberlab list" ;;
    *) echo "Open a new terminal (or log out and back in) so ~/.local/bin is on your PATH," \
            "then try  cyberlab list.  Until then:  $DIR/bin/cyberlab list" ;;
esac
