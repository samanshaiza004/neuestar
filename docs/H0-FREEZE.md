# H0 — Freeze Record

Freeze date: 2026-08-16. Freeze commit on `main`: `6714c9755788dca07c0633e5c884a8bfa12e1a35`
(merge of `h0-hypothesis` @ `609d598`).

## Immutable experimental policy

- `docs/GATE-H0.md` — hypothesis, invariants, gates (H0.0–H0.6, H0.P),
  baseline inventory, target profiles, candidate architectures, burden
  thresholds, evidence model, execution order.
- `docs/H0-KILL-CONDITIONS.md` — precommitted kill conditions 1–14 and the
  kill-condition-13 threshold table.

These documents are experimental policy. **They are not edited in response to
H0 results.** Result-driven changes to these rules are prohibited; a kill
condition is honored as written, ambiguity resolves against Installed
Substrate (toward the predeclared Vertical Native fallback).

Campaign 002 remains frozen and untouched by this freeze; H0 does not supersede
L0 and never changes any Campaign 002 statement.

## Enforced interpretations (recorded at freeze; encoded in the H0 schema/checker)

1. **Burden budgets include the carried bwrap.** The 8 MiB root-owned-byte and
   20-file budgets count everything the Neuestar integration package installs,
   including the carried bwrap binary. "Third-party component" excludes bwrap
   from *first-party source LOC* only; it does not exclude bwrap from installed
   byte/file footprint. `Neuestar-carried third-party components <= 1` and
   `Neuestar-local patches = 0` are hard requirements.
2. **H0.1S capability evidence is namespace-scoped.** "No retained setup
   capabilities" is recorded as the child's effective capability set
   (`child_effective_capabilities`) **together with the child's namespace
   identity** (`child_user_namespace_id`, `child_mount_namespace_id`) and the
   helper/child AppArmor profile labels, so the claim cannot be read without
   namespace context.
3. **Candidate-aware fields.** Candidate B legitimately records
   `neuestar_integration_package_sha256 = null` with
   `host_bwrap_package_version`; no meaningless zero hashes are forced.

## Next steps (execution order)

1. Build the `neuestar.h0/v1` evidence schema (schema/h0.v1.schema.json, frozen; schema/h0.v2.schema.json is the post-H0.P mechanized revision) — review
   before the probe.
2. Build the minimal H0 probe.
3. H0.P probe equivalence (Ubuntu 26.04 boundary failure; NixOS 26.05 minimum
   controlled-root success).
4. Candidate A1 (stable root-owned Neuestar-controlled bwrap + Ubuntu AppArmor
   integration), then H0.1S adversarial checks, then the H0 PREFLIGHT matrix.

## Apparatus revision (pre-H0.P, schema-only; frozen policy untouched)

- **H0.P is a single outcome run.** The frozen Campaign 002 child runs under
  the exact frozen containment command (shared verbatim via
  `crates/neuestar-probe-core`, including the cleared outer environment and
  the full Campaign identity variables) with Campaign 002's success predicate
  (helper exit + user/mount namespace change vs the probe parent + controlled
  libc) and no display/GPU preflight. The dedicated security-evidence
  invocation (CapEff raw+decoded, profile labels) is reserved for H0.1S and is
  structurally required only when `gates.h0_1s` is evaluated — never for H0.P
  (schema revision in `schema/h0.v1.schema.json` / `schema/h0.v2.schema.json`).
- **AppArmor evidence honesty**: `abi` is recorded only when observable
  (optional in schema); `loaded_profile_state_sha256` is an observational
  digest over the sorted `name (mode)` profile list plus parser version — it
  is explicitly NOT a kernel-policy hash. Unreadable LSM state classifies as
  `other`, never `none`. Profile modes are preserved only when identifiable
  (enforce/complain/unconfined; otherwise `other`).
- **Checker**: `forbidden_preparation != []` is a policy failure; H0.1S pass
  requires raw CapEff == 0 and an empty decoded set.

- **Gate truthfulness**: apparatus failures (pre-command or around containment)
  record `h0_0 = not-run`, never `fail`; only a baseline failure (the frozen
  child actually ran under the boundary and failed) records `h0_0 = fail`.
  `containment_argv` may be `[]` only before a command was constructed;
  `helper_started=true` requires a non-empty argv. Wait failure records
  `helper_started=true`.
- **Shared child parser**: the bounded Campaign 002 child-result parser and
  the exact success predicate live in `neuestar-probe-core::child_result` and
  are consumed verbatim by both the frozen launcher and the H0 probe.
- **H0.1S raw mask**: pass requires raw CapEff numerically zero, an empty
  decoded set, and raw/decoded agreement (apparatus consistency).
