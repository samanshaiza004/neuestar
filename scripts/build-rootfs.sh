#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 STAGING_DIR GNU_PROBE BWRAP" >&2
  exit 64
fi

staging_dir=$1
probe_bin=$2
bwrap_bin=$3

for tool in lddtree readelf sha256sum install realpath; do
  command -v "$tool" >/dev/null || {
    echo "required tool missing: $tool" >&2
    exit 69
  }
done

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo "canonical rootfs build requires Linux x86_64" >&2
  exit 69
}

probe_bin=$(realpath "$probe_bin")
bwrap_bin=$(realpath "$bwrap_bin")
mkdir -p "$staging_dir/root" "$staging_dir/libexec/lib" "$staging_dir/app"
mkdir -p "$staging_dir/root/app" "$staging_dir/root/dev" \
  "$staging_dir/root/evidence" "$staging_dir/root/proc" \
  "$staging_dir/root/tmp" "$staging_dir/root/etc/neuestar"

install -m 0755 "$probe_bin" "$staging_dir/app/probe"
install -m 0755 "$bwrap_bin" "$staging_dir/libexec/bwrap"

copy_root_closure() {
  local binary=$1 dependency resolved target
  while IFS= read -r dependency; do
    [[ -n $dependency ]] || continue
    resolved=$(realpath -e "$dependency")
    [[ $resolved == "$binary" ]] && continue
    target="$staging_dir/root$dependency"
    install -D -m 0755 "$resolved" "$target"
  done < <(lddtree -l "$binary")
}

copy_helper_closure() {
  local binary=$1 dependency resolved base
  while IFS= read -r dependency; do
    [[ -n $dependency ]] || continue
    resolved=$(realpath -e "$dependency")
    [[ $resolved == "$binary" ]] && continue
    base=$(basename "$dependency")
    if [[ $base == ld-linux-x86-64.so.2 ]]; then
      install -m 0755 "$resolved" "$staging_dir/libexec/ld-linux-x86-64.so.2"
    else
      install -m 0755 "$resolved" "$staging_dir/libexec/lib/$base"
    fi
  done < <(lddtree -l "$binary")
}

copy_root_closure "$probe_bin"
copy_helper_closure "$bwrap_bin"

[[ -x $staging_dir/root/lib64/ld-linux-x86-64.so.2 || \
   -x $staging_dir/root/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ]] || {
  echo "probe ELF interpreter was not captured" >&2
  exit 65
}
[[ -x $staging_dir/libexec/ld-linux-x86-64.so.2 ]] || {
  echo "bubblewrap ELF interpreter was not captured" >&2
  exit 65
}

install -m 0644 "$staging_dir/runtime.toml" \
  "$staging_dir/root/etc/neuestar/runtime.toml"

(
  cd "$staging_dir"
  find root -type f -print0 | LC_ALL=C sort -z | \
    xargs -0 sha256sum >rootfs.SHA256SUMS
)

