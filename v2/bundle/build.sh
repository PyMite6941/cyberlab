#!/usr/bin/env bash
# Assemble the one-file class bundle: cyberlab v2 plus the offline tools pack.
#
#   bash v2/bundle/build.sh <built-tools-pack-dir> [out-dir]
#
# The tools pack comes from v2/tools-pack/build.sh; the workflow runs both.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
V2="$(cd "$HERE/.." && pwd)"
TOOLS="$(cd "$1" && pwd)"
OUT="$(mkdir -p "${2:-$HERE/out}" && cd "${2:-$HERE/out}" && pwd)"

read -r CODENAME ARCH < "$TOOLS/TARGET"
NAME="cyberlab-class-$CODENAME-$ARCH"
STAGE="$OUT/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE/cyberlab"

cp -R "$V2/bin" "$V2/cyberlab" "$V2/setup.sh" "$V2/README.md" "$V2/DESIGN.md" "$STAGE/cyberlab/"
find "$STAGE/cyberlab" -name __pycache__ -type d -prune -exec rm -rf {} +
cp -R "$TOOLS" "$STAGE/tools"
cp "$HERE/install.sh" "$HERE/README.txt" "$STAGE/"
chmod +x "$STAGE/install.sh" "$STAGE/cyberlab/setup.sh" "$STAGE/cyberlab/bin/cyberlab" "$STAGE/tools/install.sh"

(cd "$OUT" && tar czf "$NAME.tar.gz" "$NAME")
echo "Built $OUT/$NAME.tar.gz ($(du -sh "$OUT/$NAME.tar.gz" | cut -f1))"
