# Status

Updated 2026-08-20. Neuestar/Instar research is frozen. This file separates
the implementation and evidence that exist from the product conclusion drawn
after the platform premise changed.

For the full rationale, see [docs/RESEARCH-CLOSURE.md](docs/RESEARCH-CLOSURE.md).
The detailed campaign and H0 documents remain historical experiment records,
not a roadmap or an obligation to complete the physical matrix.

## Current disposition

- **Research phase:** closed.
- **Repository:** preserved as an archival experiment.
- **Product/framework status:** no Neuestar platform is being built.
- **Physical matrix:** intentionally not completed; no additional Fedora,
  Arch, Ubuntu, NixOS, GPU, or churn work is on the product-critical path.
- **Evidence claim:** no overall Gate L0 pass is claimed. Full-VM evidence is
  preserved below, but it is not physical matrix evidence.

## Implemented

- Project thesis, architecture boundary, fixed Gate L0 gates, and hard kill
  conditions recorded before implementation.
- Primary upstream facts for Phase 0/1 recorded.
- Rust workspace with bounded host observation, a static-launcher target, a
  glibc-linked child target, versioned reports, and fail-closed aggregation.
- Canonical Linux x86_64 build scripts for a normalized `tar.zst` containing a
  static musl launcher, the exact bundled bubblewrap closure, controlled glibc
  root, payload/root/capture-rule manifests, and source/toolchain provenance.
- Launcher-side payload verification, observed-host evidence, strict namespace
  plan, controlled-root launch, schema-valid failure reporting, and successful
  Phase 1 L0.0/L0.1 reporting.
- Hosted build/check workflows plus manual, exact-label physical cell, churn,
  and aggregation workflows. Physical workflows download and verify; they do
  not build or repair hosts.
- H0 apparatus, candidate A/B/A2a records, adversarial suites, full-VM lab
  evidence, and H0 baseline evidence from NixOS, Fedora, Arch, and Ubuntu.

## Verified locally and in full VMs

- `scripts/check.sh` passes: formatting, strict workspace Clippy, the complete
  Rust test suite, report-schema shape, ShellCheck, and diff integrity.
- Workflow syntax/lint checks pass.
- Report aggregation and launcher/preflight smoke tests produce schema-valid
  evidence and preserve unrun cells explicitly.
- The Campaign 002 frozen specimen passes L0.0/L0.1 in a stock NixOS 26.05
  full VM with controlled glibc 2.39 and no host glibc import.
- The same Campaign 002 specimen fails L0.0 in a stock Ubuntu 26.04 full VM at
  user-namespace uid-map setup because AppArmor denies the unprivileged
  transition. Ubuntu 24.04 current-updates reproduces the same H0.0 family.
- H0 evidence records the A2a preflight and the NixOS, Fedora, and Arch
  zero-preparation baselines, including the valid adversarial closing run.

These checks and full-VM runs are evidence for the recorded experiments. They
are not evidence of a complete physical matrix, GPU presentation, or an overall
Gate L0 pass.

## Gate status

- **L0.0:** implemented; full-VM NixOS pass and full-VM Ubuntu failure are
  recorded; no physical matrix run.
- **L0.1:** implemented; passed in the full-VM NixOS Campaign 002 run with
  controlled glibc; no physical matrix run.
- **L0.2:** not implemented.
- **L0.3:** not implemented.
- **L0.4:** not run.
- **L0.5:** not run.
- **Overall Gate L0:** no pass claimed.

## Unresolved research questions (not active commitments)

- No physical GPU matrix or driver-churn evidence exists.
- Independent bit-for-bit reconstruction of the distribution-provided
  bubblewrap input remains unresolved; exact captured bytes are nevertheless
  part of the immutable payload identity.
- Host-driver versus controlled-glibc compatibility remains the central
  unresolved technical question, but answering it is optional future research,
  not a reason to keep the platform effort alive.
- The A2a installed-substrate mechanism may be worth preserving as a narrowly
  scoped security contribution or upstream technique. It is not an
  application-framework critical path.

## What happens next

Nothing in this repository is on the critical path for the next serious
engineering work. Punks and Scratchpad should be built as ordinary native
applications with direct toolkit and OS composition. Record friction literally,
solve it locally first, and only extract a small primitive after a second real
application hits the same problem. Outside users and multiple consumers must
justify any later compatibility surface.
