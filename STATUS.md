# Status

## Completed

- Project thesis, architecture boundary, fixed Gate L0 gates, and hard kill
  conditions recorded before implementation.
- Primary upstream facts for Phase 0/1 recorded.
- Canonical campaign, provenance, physical-runner, and churn rules designed.

## Evidence

- Repository began empty on 2026-08-15.
- Upstream bubblewrap no longer provides historical setuid mode.
- Ubuntu AppArmor can deny unprofiled downloaded applications access to
  unprivileged user namespaces.
- Khronos documents explicit manifest override and host shared-library
  resolution as separate concerns.

## Unresolved risks

- No Linux artifact has yet been built or executed.
- Bundled bubblewrap dependency closure and controlled root are not yet proven
  reproducible.
- No physical matrix or driver churn evidence exists.
- Host-driver versus controlled-glibc compatibility remains the central risk.

## Gate status

- L0.0: not run
- L0.1: not run
- L0.2: not implemented
- L0.3: not implemented
- L0.4: not run
- L0.5: not run

## Next falsifier

Build one canonical Linux x86_64 Phase 1 artifact, verify its provenance and
minimal root, then attempt ordinary-user namespace construction on stock Ubuntu
and NixOS without host preparation.

