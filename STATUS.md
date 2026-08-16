# Status

Updated 2026-08-15. This file distinguishes implementation checks from physical
Gate L0 evidence.

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

## Verified locally

- Repository began empty on 2026-08-15.
- `scripts/check.sh` passes: formatting, strict workspace Clippy, 44 Rust tests,
  report-schema shape, ShellCheck, and diff integrity.
- A report-aggregation smoke test validated one explicit report while retaining
  the other 23 cells as unrun.
- A launcher preflight smoke test emitted a schema-valid failure report and the
  aggregator accepted it as failed evidence.
- Workflow syntax/lint checks pass.

These are implementation checks only. They are not evidence that Linux user
namespaces, bundled bubblewrap, controlled glibc, Vulkan, or presentation work
on any physical matrix cell.

## Unresolved risks

- This development host is macOS arm64, so no canonical Linux x86_64 artifact
  has yet been built or executed here.
- The hosted build workflow has not yet published a campaign artifact.
- Bundled bubblewrap dependency closure and controlled root are implemented but
  not yet proven by a Linux build or ordinary-user containment attempt.
- Independent bit-for-bit reconstruction of the distribution-provided
  bubblewrap input remains unresolved; exact captured bytes are nevertheless
  part of the immutable payload identity.
- No physical matrix or driver churn evidence exists.
- Host-driver versus controlled-glibc compatibility remains the central risk.

## Gate status

- L0.0: implemented, not run on Linux
- L0.1: implemented for the minimal child, not run on Linux
- L0.2: not implemented
- L0.3: not implemented
- L0.4: not run
- L0.5: not run

## Next falsifier

Run the canonical build on Linux x86_64, publish exactly one archive/hash pair,
then attempt ordinary-user L0.0/L0.1 on stock NixOS NVIDIA and Ubuntu NVIDIA
Wayland/X11 hosts without preparation. Namespace denial is a valid failed
result and must not be repaired.
