#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema" and
  .["$id"] == "urn:neuestar:report:v2"
' schema/report.schema.json >/dev/null

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema" and
  .["$id"] == "urn:neuestar:report:v1" and
  (.properties.schema.const == "neuestar.report/v1") and
  (."$defs".containmentEvidence.properties | has("substage") | not) and
  (."$defs".containmentEvidence.properties | has("process_stderr") | not)
' schema/report-v1.schema.json >/dev/null

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema" and
  .["$id"] == "urn:neuestar:h0:v1" and
  (.properties.schema.const == "neuestar.h0/v1") and
  (.properties.trusted_helper.properties | has("regular_file") | not) and
  (.properties.apparatus.properties | has("security_evidence_argv") | not)
' schema/h0.v1.schema.json >/dev/null

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema" and
  .["$id"] == "urn:neuestar:h0:v2" and
  (.properties.schema.const == "neuestar.h0/v2") and
  (.properties.trusted_helper.properties | has("regular_file")) and
  (.properties.apparatus.properties | has("security_evidence_argv"))
' schema/h0.v2.schema.json >/dev/null

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema" and
  .["$id"] == "urn:neuestar:h0:adjudication:v1" and
  (.properties.schema.const == "neuestar.h0.adjudication/v1")
' schema/h0.adjudication.schema.json >/dev/null

# The committed A1 adjudication must chain to the exact raw record bytes and
# to a recomputable evidence manifest.
raw_sha=$(sha256sum docs/a1-preflight-evidence/a1-ubuntu-report.json | cut -d' ' -f1)
adj_raw=$(jq -r .raw_record_sha256 docs/a1-preflight-evidence/a1-adjudication.json)
test "$raw_sha" = "$adj_raw" || { echo "adjudication raw_record_sha256 mismatch"; exit 1; }
manifest=$(cd docs/a1-preflight-evidence/adversarial && for f in $(LC_ALL=C ls); do printf '%s %s\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"; done)
manifest_sha=$(printf '%s\n' "$manifest" | sha256sum | cut -d' ' -f1)
adj_manifest=$(jq -r .evidence_manifest_sha256 docs/a1-preflight-evidence/a1-adjudication.json)
test "$manifest_sha" = "$adj_manifest" || { echo "adjudication evidence_manifest_sha256 mismatch"; exit 1; }

shellcheck scripts/*.sh 2>/dev/null || true
git diff --check
