#!/usr/bin/env bash
# Install the cyberlab tools offline from this pack:
#
#   sudo ./install.sh
#
# Uses only the packages in ./debs (no internet). apt installs what's missing
# and upgrades a library only if a tool needs a newer one; it never downgrades
# anything and doesn't touch unrelated packages. Your normal apt sources are
# left as they are.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$(id -u)" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi

# The pack only works on the release it was built for.
read -r PACK_CODENAME PACK_ARCH < "$HERE/TARGET"
. /etc/os-release
CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
ARCH="$(dpkg --print-architecture)"
if [ "$CODENAME/$ARCH" != "$PACK_CODENAME/$PACK_ARCH" ]; then
    echo "This pack is for $PACK_CODENAME/$PACK_ARCH, but this machine is $CODENAME/$ARCH." >&2
    echo "(Mint 22.x is noble/amd64.) Use the matching pack." >&2
    exit 1
fi

# apt's file: URLs can't contain spaces; use a copy in /tmp if they would.
REPO="$HERE/debs"
case "$REPO" in
    *" "*)
        TMP_REPO="$(mktemp -d)"
        cp "$REPO"/* "$TMP_REPO/"
        REPO="$TMP_REPO"
        ;;
esac

LIST="$(mktemp --suffix=.list)"
cleanup() { rm -f "$LIST"; [ -n "${TMP_REPO:-}" ] && rm -rf "$TMP_REPO"; }
trap cleanup EXIT
echo "deb [trusted=yes] file:$REPO ./" > "$LIST"

# Look only at the pack, and keep the system's existing package lists.
APT=(apt-get -o Dir::Etc::SourceList="$LIST" -o Dir::Etc::SourceParts=-
     -o APT::Get::List-Cleanup=0 -o APT::Sandbox::User=root)

mapfile -t TOOLS < <(sed 's/#.*//' "$HERE/tools.txt" | awk 'NF {print $1}')

# Wireshark asks whether non-root users may capture live traffic. The lab only
# reads pcap files, so answer no.
echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

"${APT[@]}" update
DEBIAN_FRONTEND=noninteractive "${APT[@]}" install -y --no-install-recommends "${TOOLS[@]}"

echo
echo "Installed:"
for cmd in nmap tshark wireshark hydra sqlmap john nikto gobuster curl nc; do
    if command -v "$cmd" >/dev/null 2>&1; then
        printf '  %-10s %s\n' "$cmd" "$(command -v "$cmd")"
    else
        printf '  %-10s MISSING\n' "$cmd"
    fi
done
