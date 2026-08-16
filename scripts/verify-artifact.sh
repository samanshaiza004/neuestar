#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 ARCHIVE [EXPECTED_ARCHIVE_SHA256]" >&2
  exit 64
fi

archive=$1
expected=${2:-}
for tool in jq sha256sum tar zstd; do
  command -v "$tool" >/dev/null || {
    echo "required tool missing: $tool" >&2
    exit 69
  }
done

actual=$(sha256sum "$archive" | awk '{print $1}')
if [[ -n $expected && $actual != "$expected" ]]; then
  echo "archive SHA-256 mismatch: expected $expected, got $actual" >&2
  exit 65
fi

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
tar --use-compress-program=unzstd -xf "$archive" -C "$work_dir"
artifact_dir="$work_dir/neuestar-probe"

if [[ -n $(find "$artifact_dir" -type l -print -quit) ]]; then
  echo "artifact contains a symlink" >&2
  exit 65
fi

for required in neuestar-probe app/probe libexec/bwrap \
  libexec/ld-linux-x86-64.so.2 runtime.toml capture-rules.json \
  artifact.json SHA256SUMS; do
  [[ -e $artifact_dir/$required ]] || {
    echo "artifact member missing: $required" >&2
    exit 65
  }
done

(
  cd "$artifact_dir"
  sha256sum --strict --check SHA256SUMS
)
for required in neuestar-probe app/probe libexec/bwrap \
  libexec/ld-linux-x86-64.so.2 runtime.toml capture-rules.json \
  rootfs.SHA256SUMS; do
  awk -v path="./$required" '
    $2 == path || $2 == substr(path, 3) { found = 1 }
    END { exit !found }
  ' "$artifact_dir/SHA256SUMS" || {
    echo "payload manifest omits required member: $required" >&2
    exit 65
  }
done
while IFS= read -r -d '' payload_file; do
  relative=${payload_file#"$artifact_dir"/}
  [[ $relative == artifact.json || $relative == SHA256SUMS ]] && continue
  awk -v path="./$relative" '
    $2 == path || $2 == substr(path, 3) { found = 1 }
    END { exit !found }
  ' "$artifact_dir/SHA256SUMS" || {
    echo "artifact contains unmanifested file: $relative" >&2
    exit 65
  }
done < <(find "$artifact_dir" -type f -print0)
payload_actual=$(sha256sum "$artifact_dir/SHA256SUMS" | awk '{print $1}')
payload_expected=$(jq -er '.payload_manifest_sha256' "$artifact_dir/artifact.json")
artifact_identity=$(jq -er '.artifact_sha256' "$artifact_dir/artifact.json")
capture_rule_actual=$(sha256sum "$artifact_dir/capture-rules.json" | awk '{print $1}')
capture_rule_expected=$(jq -er '.capture_rule_sha256' "$artifact_dir/artifact.json")
child_interpreter=$(jq -er '.child_interpreter' "$artifact_dir/artifact.json")
[[ $payload_actual == "$payload_expected" && $payload_actual == "$artifact_identity" ]] || {
  echo "embedded payload identity mismatch" >&2
  exit 65
}
[[ $capture_rule_actual == "$capture_rule_expected" ]] || {
  echo "capture-rule identity mismatch" >&2
  exit 65
}
[[ $child_interpreter == /* && -f $artifact_dir/root$child_interpreter ]] || {
  echo "controlled child interpreter is missing" >&2
  exit 65
}
awk -v path="./root$child_interpreter" '
  $2 == path || $2 == substr(path, 3) { found = 1 }
  END { exit !found }
' "$artifact_dir/SHA256SUMS" || {
  echo "payload manifest omits controlled child interpreter" >&2
  exit 65
}
jq -e '
  .schema == "neuestar.artifact/v1" and
  .architecture == "x86_64" and
  (.source_commit | test("^[0-9a-f]{40}$")) and
  (.runtime_root_manifest_sha256 | test("^[0-9a-f]{64}$")) and
  (.capture_rule_sha256 | test("^[0-9a-f]{64}$")) and
  (.child_interpreter | test("^/[^[:space:]]+$")) and
  (.controlled_libc_version | type == "string" and length > 0 and length <= 128)
' "$artifact_dir/artifact.json" >/dev/null

printf '%s\n' "$actual"
