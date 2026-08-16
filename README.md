# Neuestar

Neuestar is a clean-slate experiment in whether one immutable Linux x86_64
native application artifact can run across incompatible distributions while
using each host's real accelerated graphics stack.

The repository currently implements only Gate L0 scientific infrastructure.
It is not a desktop framework, UI toolkit, package manager, or stable SDK.

The immediate artifact is `neuestar-probe`: a static musl launcher, a small
glibc-linked child, a deliberately controlled root filesystem, provenance, and
machine-readable reports. Physical GPU results are evidence; hosted CI is not.

Start with [docs/GATE-L0.md](docs/GATE-L0.md), then read
[docs/KILL-CONDITIONS.md](docs/KILL-CONDITIONS.md) before changing capture or
containment behavior.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/check.sh
```

Canonical Linux artifacts are built only by `scripts/build-probe.sh` on Linux
x86_64 or by the hosted build workflow. Matrix runners download that artifact;
they never rebuild it.

