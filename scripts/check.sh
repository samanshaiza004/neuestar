#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema" and
  .["$id"] == "urn:neuestar:report:v1"
' schema/report.schema.json >/dev/null

shellcheck scripts/*.sh
git diff --check
