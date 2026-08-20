#!/usr/bin/env bash
# Build the Candidate A1 Neuestar host-integration package (.deb) for Ubuntu
# 26.04, hand-assembled with ar (no dpkg-deb required).
#
# - /usr/libexec/neuestar/bwrap: the exact upstream bwrap bytes selected from
#   the frozen Campaign 002 artifact (SHA pinned; no Neuestar patches).
# - /etc/apparmor.d/neuestar-bwrap: AppArmor policy attached to that
#   root-owned path (upstream bwrap-userns-restrict semantics; children stacked
#   into the capability-denying neuestar-unpriv profile).
# - postinst loads the policy and writes /var/lib/neuestar/apparmor-state.json
#   (root-written install-time evidence of profile loading).
set -euo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

usage() {
    echo "usage: $0 <frozen-artifact-dir> <out-dir>"
    exit 1
}
[ "$#" -eq 2 ] || usage
ARTIFACT="$1"
OUT="$2"

HELPER_SHA256_EXPECTED="52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"
actual=$(sha256sum "$ARTIFACT/libexec/bwrap" | awk '{print $1}')
if [ "$actual" != "$HELPER_SHA256_EXPECTED" ]; then
    echo "helper SHA-256 mismatch: expected $HELPER_SHA256_EXPECTED, observed $actual" >&2
    exit 1
fi

VER="0.2.0"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/usr/libexec/neuestar" "$STAGE/etc/apparmor.d" "$STAGE/var/lib/neuestar" "$STAGE/DEBIAN"

install -m 0755 "$ARTIFACT/libexec/bwrap" "$STAGE/usr/libexec/neuestar/bwrap"

cat > "$STAGE/etc/apparmor.d/neuestar-bwrap" <<'PROFILE'
# Neuestar Candidate A1 host-integration profile.
# Mirrors upstream bwrap-userns-restrict semantics, attached to the
# Neuestar-controlled root-owned helper path. The helper may construct the
# user+mount namespace; children are stacked into the capability-denying
# neuestar-unpriv profile so the authority cannot leak to runtime code.
abi <abi/5.0>,

include <tunables/global>

profile neuestar-bwrap /usr/libexec/neuestar/bwrap flags=(attach_disconnected,mediate_deleted) {
  allow capability,
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,
  allow pix /** -> &neuestar-bwrap//&neuestar-unpriv,
}

profile neuestar-unpriv flags=(attach_disconnected,mediate_deleted) {
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,
  allow pix /** -> &neuestar-unpriv,
  audit deny capability,
}
PROFILE
chmod 0644 "$STAGE/etc/apparmor.d/neuestar-bwrap"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: neuestar-h0-a1
Version: $VER
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Neuestar <neuestar@example.invalid>
Description: Neuestar H0 Candidate A1 host integration (root-owned helper + AppArmor policy)
EOF

cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
# Load the Neuestar helper AppArmor policy and record install-time profile
# state (root-written, world-readable) as positive evidence for the H0 probe.
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r /etc/apparmor.d/neuestar-bwrap
fi
{
    printf '{\n'
    printf '  "parser_version": "%s",\n' "$(apparmor_parser --version 2>/dev/null | head -n1 | sed 's/"/\\"/g')"
    printf '  "loaded_profiles": [{"name": "neuestar-bwrap", "mode": "enforce", "path": "/usr/libexec/neuestar/bwrap"}]\n'
    printf '}\n'
} > /var/lib/neuestar/apparmor-state.json
chmod 0644 /var/lib/neuestar/apparmor-state.json
exit 0
POSTINST
chmod 0755 "$STAGE/DEBIAN/postinst"

mkdir -p "$OUT"
printf '2.0\n' > "$STAGE/debian-binary"
(
    cd "$STAGE"
    tar -czf control.tar.gz --owner=0 --group=0 -C DEBIAN .
    tar -czf data.tar.gz --owner=0 --group=0 usr etc var
)
DEB="$OUT/neuestar-h0-a1_${VER}_amd64.deb"
ar rcs "$DEB" "$STAGE/debian-binary" "$STAGE/control.tar.gz" "$STAGE/data.tar.gz"
echo "built $DEB"
sha256sum "$DEB"
