# Status

Updated 2026-08-16. This file distinguishes implementation checks from physical
Gate L0 evidence. Full-VM lab evidence (graphical Wayland guests, exit-65
preflight vs exit-71 containment outcomes): [docs/full-vm-lab.md](docs/full-vm-lab.md).

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

## Gate status

- L0.0: implemented; not run on physical Linux (observed failing in full VMs on
  stock Ubuntu 26.04 userns policy and stock NixOS 26.05 controlled-root
  construction, exit 71)
- L0.1: implemented for the minimal child, not run on Linux
- L0.2: not implemented
- L0.3: not implemented
- L0.4: not run
- L0.5: not run

## Next falsifier

Run the canonical build on Linux x86_64, publish exactly one archive/hash pair,
then attempt ordinary-user L0.0/L0.1 on stock NixOS NVIDIA and Ubuntu NVIDIA
Wayland/X11 hosts without preparation. Namespace denial is a valid failed
result and must not be repaired. The full-VM lab established the only
precondition the virtual environment can: the unchanged archive now passes
preflight against a real logged-in Wayland session and fails inside namespace
construction (exit 71) rather than at the display guard (exit 65). Implementation
checks are not evidence that Linux user namespaces, bundled bubblewrap, controlled
glibc, Vulkan, or presentation work on any physical matrix cell.

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
