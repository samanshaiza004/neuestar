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

Full-VM preflight lab evidence (graphical guests, Wayland sessions, and the
preflight-rejection vs L0.0-failure distinction): [docs/full-vm-lab.md](docs/full-vm-lab.md).
Campaign 001 apparatus-failure verdict and Campaign 002 charter:
[docs/CAMPAIGN-001-VERDICT.md](docs/CAMPAIGN-001-VERDICT.md).

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

A physical Phase 1 attempt must declare its asserted cell and the verified
outer archive hash:

```sh
./neuestar-probe \
  --archive-sha256 "$EXPECTED_SHA256" \
  --distro ubuntu --gpu nvidia --display wayland \
  --report report.json
```

The report separately contains host values observed at runtime. A successful
Phase 1 attempt passes only L0.0/L0.1; later graphics gates remain explicitly
unrun and the overall attempt is not classified as a Gate L0 pass.
