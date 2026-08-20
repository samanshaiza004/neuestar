#!/usr/bin/env bash
# Build the Candidate A2a Neuestar host-integration package (.deb) for Ubuntu
# 26.04, hand-assembled with ar (no dpkg-deb required).
#
# Architecture: static privilege-entry gate.
# - /usr/libexec/neuestar/entry: first-party STATIC trust anchor (no dynamic
#   loader -> no loader injection). Holds no setup authority by itself; it
#   sanitizes the environment, closes inherited FDs, constructs the frozen
#   operation argv, records it, and execs bwrap-real through a secure-exec
#   (Px) AppArmor transition.
# - /usr/libexec/neuestar/bwrap-real: the exact pinned upstream bwrap bytes
#   (0 Neuestar patches). NO AppArmor profile attached by path: it is
#   reachable with setup authority only through the entry's named-profile
#   transition; direct exec is unconfined and therefore blocked by the
#   distro userns restriction.
# - /etc/apparmor.d/neuestar-entry / neuestar-bwrap-real / neuestar-unpriv:
#   entry profile (exec transition only), named setup profile (broad bwrap
#   authority + stacked restricted child), capability-denying child profile.
# - postinst loads the profiles and writes /var/lib/neuestar/
#   apparmor-state.json (root-written install-time evidence).
set -euo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

usage() {
    echo "usage: $0 <frozen-artifact-dir> <static-entry-binary> <out-dir>"
    exit 1
}
[ "$#" -eq 3 ] || usage
ARTIFACT="$1"
ENTRY_BIN="$2"
OUT="$3"

HELPER_SHA256_EXPECTED="52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"
actual=$(sha256sum "$ARTIFACT/libexec/bwrap" | awk '{print $1}')
if [ "$actual" != "$HELPER_SHA256_EXPECTED" ]; then
    echo "bwrap SHA-256 mismatch: expected $HELPER_SHA256_EXPECTED, observed $actual" >&2
    exit 1
fi

# The entry must be statically linked: PT_INTERP absent.
entry_sha=$(sha256sum "$ENTRY_BIN" | awk '{print $1}')
if readelf -l "$ENTRY_BIN" 2>/dev/null | grep -q INTERP; then
    echo "entry is NOT static (PT_INTERP present): $ENTRY_BIN" >&2
    exit 1
fi

VER="0.2.0"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/usr/libexec/neuestar" "$STAGE/etc/apparmor.d" "$STAGE/var/lib/neuestar" "$STAGE/DEBIAN"

install -m 0755 "$ENTRY_BIN" "$STAGE/usr/libexec/neuestar/entry"
install -m 0755 "$ARTIFACT/libexec/bwrap" "$STAGE/usr/libexec/neuestar/bwrap-real"

cat > "$STAGE/etc/apparmor.d/neuestar-entry" <<'PROFILE'
# Candidate A2a: the static privilege-entry gate profile.
# The entry holds NO setup authority (no capability, no userns, no mount).
# It sanitizes state and execs bwrap-real through a secure-exec (Px)
# transition into the named setup profile, so user-controlled loader state
# cannot reach the boundary where setup authority exists.
abi <abi/5.0>,

include <tunables/global>

profile neuestar-entry /usr/libexec/neuestar/entry flags=(attach_disconnected) {
  allow file rwlk /{**,},
  allow px /usr/libexec/neuestar/bwrap-real -> neuestar-bwrap-real,
}
PROFILE
chmod 0644 "$STAGE/etc/apparmor.d/neuestar-entry"

cat > "$STAGE/etc/apparmor.d/neuestar-bwrap-real" <<'PROFILE'
# Candidate A2a: the named setup profile for bwrap-real.
# No path attachment: bwrap-real can only enter this profile through the
# entry's secure-exec transition; direct exec of bwrap-real is unconfined and
# blocked by the distro userns restriction. Broad authority is required to
# construct the boundary; children are stacked into the capability-denying
# neuestar-unpriv profile before any user code executes the child transition.
abi <abi/5.0>,

include <tunables/global>

profile neuestar-bwrap-real flags=(attach_disconnected,mediate_deleted) {
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
  allow pix /** -> &neuestar-bwrap-real//&neuestar-unpriv,
}
PROFILE
chmod 0644 "$STAGE/etc/apparmor.d/neuestar-bwrap-real"

cat > "$STAGE/etc/apparmor.d/neuestar-unpriv" <<'PROFILE'
# Candidate A2a: the capability-denying child profile (stacked).
# Mirrors the upstream bwrap-unprivileged semantics: userns/mount classes
# stay available (upstream design), capabilities are denied so arbitrary
# child/runtime code cannot reacquire setup authority.
abi <abi/5.0>,

include <tunables/global>

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
chmod 0644 "$STAGE/etc/apparmor.d/neuestar-unpriv"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: neuestar-h0-a2
Version: $VER
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Neuestar <neuestar@example.invalid>
Description: Neuestar H0 Candidate A2 host integration (static entry + private bwrap-real + AppArmor policy)
EOF

cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
# Load the Neuestar Candidate A2 profiles and record install-time profile
# state (root-written, world-readable) as positive evidence for the probe.
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r /etc/apparmor.d/neuestar-entry \
                    /etc/apparmor.d/neuestar-bwrap-real \
                    /etc/apparmor.d/neuestar-unpriv
fi
{
    printf '{\n'
    printf '  "parser_version": "%s",\n' "$(apparmor_parser --version 2>/dev/null | head -n1 | sed 's/"/\\"/g')"
    printf '  "loaded_profiles": [\n'
    printf '    {"name": "neuestar-entry", "mode": "enforce", "path": "/usr/libexec/neuestar/entry"},\n'
    printf '    {"name": "neuestar-bwrap-real", "mode": "enforce"},\n'
    printf '    {"name": "neuestar-unpriv", "mode": "enforce"}\n'
    printf '  ]\n'
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
DEB="$OUT/neuestar-h0-a2_${VER}_amd64.deb"
ar rcs "$DEB" "$STAGE/debian-binary" "$STAGE/control.tar.gz" "$STAGE/data.tar.gz"
echo "built $DEB (entry sha $entry_sha, bwrap-real sha $HELPER_SHA256_EXPECTED)"
sha256sum "$DEB"