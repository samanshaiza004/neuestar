# Status

Updated 2026-08-16. This file distinguishes implementation checks from physical
Gate L0 evidence. Full-VM lab evidence: [docs/full-vm-lab.md](docs/full-vm-lab.md);
Campaign 001 apparatus-failure verdict: [docs/CAMPAIGN-001-VERDICT.md](docs/CAMPAIGN-001-VERDICT.md).

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

- L0.0: implemented; not run on physical Linux. Full-VM executions of the
  Campaign 001 specimen failed at exit 71 in two specimen-defect modes —
  over-scoped netns setup on Ubuntu 26.04 and a read-only-root bind-mount defect
  on NixOS 26.05 (docs/CAMPAIGN-001-VERDICT.md). Neither was attributed to
  platform incompatibility; L0.0 under stock NixOS/Ubuntu policy is unresolved
  pending Campaign 002.
- L0.1: implemented for the minimal child, not run on Linux
- L0.2: not implemented
- L0.3: not implemented
- L0.4: not run
- L0.5: not run

## Next falsifier

Run the canonical build on Linux x86_64, publish exactly one archive/hash pair,
then attempt ordinary-user L0.0/L0.1 on stock NixOS NVIDIA and Ubuntu NVIDIA
Wayland/X11 hosts without preparation. Namespace denial is a valid failed
result and must not be repaired. The immediate next falsifier is Campaign 002
(minimum user+mount containment, corrected `/app` bind, bounded containment
diagnostics) passing L0.0/L0.1 in the same two full VMs; physical execution
starts only afterward. The full-VM lab established the only precondition the
virtual environment can: the unchanged archive now passes preflight against a
real logged-in Wayland session and fails inside namespace construction (exit 71)
rather than at the display guard (exit 65). Implementation checks are not
evidence that Linux user namespaces, bundled bubblewrap, controlled glibc,
Vulkan, or presentation work on any physical matrix cell.

## Unresolved risks

- The canonical Campaign 001 Linux x86_64 artifact has been executed only
  inside full VMs (Fedora Kinoite host, ordinary user `lab`) — never on
  physical matrix hardware.
- The hosted build workflow published the Campaign 001 artifact (Actions run
  31951274008, canonical-artifact 9264713287); a Campaign 002 artifact is not
  yet published.
- Bundled bubblewrap executed as an ordinary user inside full VMs during
  Campaign 001 and exposed two specimen defects (over-scoped netns;
  read-only-root bind destination); a clean controlled-root launch under the
  minimum L0 contract remains to be demonstrated by Campaign 002.
- Independent bit-for-bit reconstruction of the distribution-provided
  bubblewrap input remains unresolved; exact captured bytes are nevertheless
  part of the immutable payload identity.
- No physical matrix or driver churn evidence exists.
- Host-driver versus controlled-glibc compatibility remains the central risk.
