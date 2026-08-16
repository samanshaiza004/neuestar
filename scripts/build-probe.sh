#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dist_dir=${NEUESTAR_DIST_DIR:-"$repo_dir/dist"}
bwrap_bin=${NEUESTAR_BWRAP_BIN:-$(command -v bwrap || true)}

for tool in cargo git jq sha256sum tar zstd lddtree readelf; do
  command -v "$tool" >/dev/null || {
    echo "required tool missing: $tool" >&2
    exit 69
  }
done
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo "canonical probe build requires Linux x86_64" >&2
  exit 69
}
[[ -n $bwrap_bin && -x $bwrap_bin ]] || {
  echo "a build-host bubblewrap binary is required for pinned closure capture" >&2
  exit 69
}

source_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repo_dir" show -s --format=%ct HEAD)}
source_commit=${GITHUB_SHA:-$(git -C "$repo_dir" rev-parse HEAD)}
version=$(cargo metadata --no-deps --format-version 1 --manifest-path "$repo_dir/Cargo.toml" | jq -r '.packages[] | select(.name == "neuestar-probe-launcher") | .version')

cargo build --manifest-path "$repo_dir/Cargo.toml" --locked --release \
  --target x86_64-unknown-linux-musl -p neuestar-probe-launcher
cargo build --manifest-path "$repo_dir/Cargo.toml" --locked --release \
  --target x86_64-unknown-linux-gnu -p neuestar-probe-app

launcher_bin="$repo_dir/target/x86_64-unknown-linux-musl/release/neuestar-probe"
child_bin="$repo_dir/target/x86_64-unknown-linux-gnu/release/probe"
if readelf -l "$launcher_bin" | grep -q 'Requesting program interpreter'; then
  echo "launcher is not static" >&2
  exit 65
fi
readelf -l "$child_bin" | grep -q 'Requesting program interpreter' || {
  echo "probe child is not dynamically glibc-linked" >&2
  exit 65
}
child_interpreter=$(readelf -l "$child_bin" | sed -n \
  's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
[[ $child_interpreter == /* ]] || {
  echo "probe child interpreter could not be determined" >&2
  exit 65
}

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
staging_dir="$work_dir/neuestar-probe"
mkdir -p "$staging_dir"
install -m 0755 \
  "$launcher_bin" \
  "$staging_dir/neuestar-probe"
install -m 0644 "$repo_dir/rootfs/runtime.toml" "$staging_dir/runtime.toml"
install -m 0644 "$repo_dir/rootfs/capture-rules.json" "$staging_dir/capture-rules.json"

"$repo_dir/scripts/build-rootfs.sh" "$staging_dir" \
  "$child_bin" "$bwrap_bin"
controlled_libc_version=$("$staging_dir/root$child_interpreter" --version | sed -n '1p')
[[ -n $controlled_libc_version ]] || {
  echo "controlled glibc version could not be determined" >&2
  exit 65
}

payload_manifest_tmp="$work_dir/payload.SHA256SUMS"
(
  cd "$staging_dir"
  find . -type f \
    ! -name artifact.json \
    ! -name SHA256SUMS \
    -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) >"$payload_manifest_tmp"
install -m 0644 "$payload_manifest_tmp" "$staging_dir/SHA256SUMS"

payload_manifest_sha256=$(sha256sum "$staging_dir/SHA256SUMS" | awk '{print $1}')
root_manifest_sha256=$(sha256sum "$staging_dir/rootfs.SHA256SUMS" | awk '{print $1}')
capture_rule_sha256=$(sha256sum "$staging_dir/capture-rules.json" | awk '{print $1}')
build_timestamp=$(date -u -d "@$source_epoch" '+%Y-%m-%dT%H:%M:%SZ')
rustc_version=$(rustc --version)
cargo_version=$(cargo --version)
bwrap_version=$("$bwrap_bin" --version | head -n 1)
bwrap_sha256=$(sha256sum "$bwrap_bin" | awk '{print $1}')

jq -n \
  --arg schema "neuestar.artifact/v1" \
  --arg artifact_sha256 "$payload_manifest_sha256" \
  --arg payload_manifest_sha256 "$payload_manifest_sha256" \
  --arg source_commit "$source_commit" \
  --arg probe_version "$version" \
  --arg build_timestamp "$build_timestamp" \
  --arg architecture "x86_64" \
  --arg root_manifest_sha256 "$root_manifest_sha256" \
  --arg capture_rule_sha256 "$capture_rule_sha256" \
  --arg child_interpreter "$child_interpreter" \
  --arg controlled_libc_version "$controlled_libc_version" \
  --arg rustc "$rustc_version" \
  --arg cargo "$cargo_version" \
  --arg bwrap "$bwrap_version" \
  --arg bwrap_sha256 "$bwrap_sha256" \
  '{
    schema: $schema,
    artifact_sha256: $artifact_sha256,
    payload_manifest_sha256: $payload_manifest_sha256,
    source_commit: $source_commit,
    probe_version: $probe_version,
    build_timestamp: $build_timestamp,
    architecture: $architecture,
    runtime_root_manifest_sha256: $root_manifest_sha256,
    capture_rule_sha256: $capture_rule_sha256,
    child_interpreter: $child_interpreter,
    controlled_libc_version: $controlled_libc_version,
    toolchains: {
      rustc: $rustc,
      cargo: $cargo,
      bubblewrap: $bwrap,
      bubblewrap_sha256: $bwrap_sha256
    }
  }' >"$staging_dir/artifact.json"

find "$staging_dir" -type d -exec chmod 0755 '{}' +

mkdir -p "$dist_dir"
archive="$dist_dir/neuestar-probe-x86_64.tar.zst"
tar --sort=name --format=posix --pax-option=delete=atime,delete=ctime \
  --mtime="@$source_epoch" \
  --owner=0 --group=0 --numeric-owner \
  -C "$work_dir" -cf - neuestar-probe | zstd -19 --threads=1 -q -o "$archive"
sha256sum "$archive" >"$archive.sha256"
install -m 0644 "$staging_dir/artifact.json" "$dist_dir/artifact.json"
install -m 0644 "$staging_dir/SHA256SUMS" "$dist_dir/SHA256SUMS"

"$repo_dir/scripts/verify-artifact.sh" "$archive" \
  "$(awk '{print $1}' "$archive.sha256")"
printf 'canonical archive: %s\n' "$archive"
printf 'archive sha256: %s\n' "$(awk '{print $1}' "$archive.sha256")"
printf 'payload manifest sha256: %s\n' "$payload_manifest_sha256"
