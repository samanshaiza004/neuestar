# Status

Updated 2026-08-16. This file distinguishes implementation checks from physical
Gate L0 evidence. Full-VM lab evidence: [docs/full-vm-lab.md](docs/full-vm-lab.md);
Campaign 001 apparatus-failure verdict: [docs/CAMPAIGN-001-VERDICT.md](docs/CAMPAIGN-001-VERDICT.md);
Campaign 002 frozen specimen + outcome: [docs/CAMPAIGN-002.md](docs/CAMPAIGN-002.md).

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

- L0.0: implemented; not run on physical Linux. FULL-VM executions of the
  Campaign 002 specimen (probe 0.2.0, docs/CAMPAIGN-002.md): L0.0/L0.1 PASS on
  stock NixOS 26.05; L0.0 FAIL on stock Ubuntu 26.04 (AppArmor denies
  unprivileged user-namespace uid-map setup — `bwrap: setting up uid map:
  Permission denied`). FULL-VM preflight only; physical cells pending.
- L0.1: implemented for the minimal child; passed in the full-VM Campaign 002
  run on stock NixOS 26.05 (controlled glibc 2.39, no host glibc import); not
  run on physical Linux
- L0.2: not implemented
- L0.3: not implemented
- L0.4: not run
- L0.5: not run

## Next falsifier

The next falsifier is one confirmation run of the same frozen Campaign 002
artifact (probe 0.2.0, outer a5773bc2…c10fe) on a stock bare-metal Ubuntu
26.04 install as an ordinary user, expecting the same AppArmor uid-map denial
(`bwrap: setting up uid map: Permission denied`). Ubuntu userns/AppArmor
policy is a kernel/security-policy property, not a virtual-GPU property, so a
physical Ubuntu reproduction is a confirmation run, not an open-ended
investigation. NixOS is already demonstrated in the full VM and does not need
physical priority. No L0.2/Vulkan work before the architecture decision that
follows the confirmation:

- preserve zero-preparation extraction as a hard requirement → if physical
  Ubuntu reproduces the denial, move to the Vertical Native fallback
  (predeclared in KILL-CONDITIONS); or
- adopt an explicit small installation-time host-integration layer (distro
  AppArmor/SELinux policy or distro bubblewrap integration) → this is
  Campaign 003, a revised substrate hypothesis, not a fix to Campaign 002.

Do not silently switch to the host `/usr/bin/bwrap` — that changes two frozen
assumptions at once (bundled known helper → host dependency; arbitrary
portable artifact → distro-provided execution infrastructure) and must be
evaluated as a new hypothesis.

Implementation checks are not evidence that Linux user namespaces, bundled
bubblewrap, controlled glibc, Vulkan, or presentation work on any physical
matrix cell.

## Unresolved risks

- The canonical Campaign 001/002 Linux x86_64 artifacts have been executed
  only inside full VMs (Fedora Kinoite host, ordinary user `lab`) — never on
  physical matrix hardware.
- The hosted build workflow published the Campaign 001 artifact (Actions run
  31951274008) and the Campaign 002 artifact (Actions run 31979454518,
  artifact 9271952770, outer a5773bc2…c10fe, probe 0.2.0).
- Bundled bubblewrap now executes cleanly under the minimum L0 contract in the
  full-VM Campaign 002 run on stock NixOS 26.05 (L0.0/L0.1 pass); on stock
  Ubuntu 26.04 the same artifact is denied at user-namespace uid-map setup by
  AppArmor policy that Ubuntu grants only to system-integrated executables
  such as `/usr/bin/bwrap` (see docs/CAMPAIGN-002.md).
- Independent bit-for-bit reconstruction of the distribution-provided
  bubblewrap input remains unresolved; exact captured bytes are nevertheless
  part of the immutable payload identity.
- No physical matrix or driver churn evidence exists.
- Host-driver versus controlled-glibc compatibility remains the central risk.
