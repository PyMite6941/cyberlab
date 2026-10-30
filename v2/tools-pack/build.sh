#!/usr/bin/env bash
# Build the offline tools pack. Run it inside a clean container of the same
# Ubuntu release as the school machines (Mint 22.x = Ubuntu 24.04 "noble"):
#
#   docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work \
#       ubuntu:24.04 bash v2/tools-pack/build.sh out
#
# GitHub Actions does this for you (.github/workflows/tools-pack.yml).
#
# The pack is a small offline apt repository: every tool in tools.txt plus its
# whole dependency chain. The school machines are offline and never updated, so
# a tool may need a newer library than they have; bundling the full chain lets
# apt add or upgrade exactly what's missing. apt never downgrades from it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(mkdir -p "${1:-$HERE/out}" && cd "${1:-$HERE/out}" && pwd)"
export DEBIAN_FRONTEND=noninteractive

. /etc/os-release
CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
ARCH="$(dpkg --print-architecture)"
PACK="cyberlab-tools-$CODENAME-$ARCH"
mapfile -t TOOLS < <(sed 's/#.*//' "$HERE/tools.txt" | awk 'NF {print $1}')

# nikto lives in multiverse; make sure every component is enabled.
if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
    sed -i 's/^Components:.*/Components: main restricted universe multiverse/' \
        /etc/apt/sources.list.d/ubuntu.sources
fi
apt-get update
apt-get install -y --no-install-recommends apt-utils   # apt-ftparchive

# Every real package in the dependency closure (virtual ones print as <name>),
# keeping only those with a downloadable version: apt-get download fails the
# whole batch on a single name it can't fetch.
mapfile -t CLOSURE < <(apt-cache depends --recurse --no-recommends --no-suggests \
    --no-conflicts --no-breaks --no-replaces --no-enhances "${TOOLS[@]}" \
    | grep '^[a-z0-9]' | sort -u)
mapfile -t PKGS < <( (apt-cache show --no-all-versions "${CLOSURE[@]}" 2>/dev/null || true) \
    | awk '/^Package:/ {print $2}' | sort -u)
for tool in "${TOOLS[@]}"; do
    printf '%s\n' "${PKGS[@]}" | grep -qx "$tool" || { echo "No such package: $tool" >&2; exit 1; }
done

DEBS="$OUT/$PACK/debs"
rm -rf "$OUT/$PACK" && mkdir -p "$DEBS" "$OUT/$PACK/licenses"
(cd "$DEBS" && apt-get download "${PKGS[@]}")
(cd "$DEBS" && apt-ftparchive packages . > Packages && apt-ftparchive release . > Release)

# Keep each package's license notice with the pack.
for deb in "$DEBS"/*.deb; do
    pkg="$(dpkg-deb -f "$deb" Package)"
    dpkg-deb --fsys-tarfile "$deb" \
        | tar -xO "./usr/share/doc/$pkg/copyright" > "$OUT/$PACK/licenses/$pkg.txt" 2>/dev/null \
        || rm -f "$OUT/$PACK/licenses/$pkg.txt"
done

cp "$HERE/install.sh" "$HERE/tools.txt" "$HERE/README.md" "$OUT/$PACK/"
echo "$CODENAME $ARCH" > "$OUT/$PACK/TARGET"
(cd "$OUT" && tar czf "$PACK.tar.gz" "$PACK")
echo "Built $OUT/$PACK.tar.gz: ${#PKGS[@]} packages, $(du -sh "$OUT/$PACK.tar.gz" | cut -f1)"
