# H0 — Precommitted Kill Conditions (Installed Substrate)

Status: **PROPOSAL, revised per architectural review — committed before any H0
implementation or testing.** These rules must not be relaxed after observing
failures.

Installed Substrate dies and Neuestar falls back to Vertical Native if any of
the following becomes necessary:

1. Per-application AppArmor/SELinux/security policy.
2. Per-runtime-generation policy.
3. Per-GPU or per-driver security policy.
4. Per-machine edits or operator instructions beyond normal install/update/
   remove of the declared integration package through the distro package
   manager (invariant D).
5. Disabling or globally weakening AppArmor/SELinux/userns restrictions.
6. A setuid helper as a compatibility strategy.
7. File capabilities as a compatibility strategy.
8. Security profiles attached to user-writable executable locations.
9. Runtime artifacts rebuilt differently per distro solely for H0.
10. Host integration package changed whenever a normal runtime generation
    changes.
11. A growing distro/security special-case rule table analogous to the L0
    capture-rule failure mode.
12. Any ordinary in-release supported security-policy update requiring a
    Neuestar integration-source change. (Strict reading: "any", not
    "repeatedly". Cross-major-release adaptation is measured separately under
    H0.4R / H0.6 and is not in-release churn. Upstream security/version updates
    of a Neuestar-carried third-party component are recorded as integration-
    identity changes and maintenance events, not H0.5 failures — H0.5 measures
    host-policy churn.)
13. The integration layer grows enough that Neuestar is effectively
    maintaining a mini Flatpak/Steam Runtime distribution stack rather than a
    small host adapter (thresholds below).
14. A failed target is omitted or reclassified after results are known.

## Thresholds for kill condition 13 (proposed, pending review/freeze)

Ceilings for the whole maintained integration layer across all target distros.
Definitions are intrinsic and non-gameable:

- root-owned bytes = Neuestar-owned payload bytes installed outside
  package-manager metadata;
- file count = Neuestar-owned filesystem entries only;
- policy LOC = nonblank/noncomment Neuestar-maintained policy source,
  including local includes;
- distro branch = a semantically different code/policy path, not packaging
  boilerplate;
- helper LOC = first-party helper code only; generated/vendor code excluded
  (a Neuestar-selected bwrap binary counts zero first-party LOC and is
  accounted under Neuestar-carried third-party components instead).

| Metric | Ceiling | Rationale |
|---|---|---|
| Root-owned installed bytes | ≤ 8 MiB | Generous headroom; definition matters more than the number. |
| Installed file count (Neuestar-owned) | ≤ 20 | Helper + 1–2 policy profiles + package control files. Flatpak-class installs are hundreds of files. |
| Policy LOC (all distros) | ≤ 200 | Upstream `bwrap-userns-restrict` ≈ 60 lines; one Neuestar profile ≈ ≤ 100. |
| Distro-specific implementation branches | ≤ 2 | Baseline predicts only the Ubuntu/AppArmor family needs policy. |
| Services/daemons | 0 | A static on-demand helper needs no daemon. |
| Additional required host packages | ≤ 2 | Distro supported repos only; no third-party repos; no exact version pinning; no dependency whose ABI/version forces Neuestar policy changes during ordinary supported updates; all counted. A dependency is not automatically equal maintenance burden to vendored code. |
| Neuestar-maintained dependencies | 0 | Any dependency we must maintain ourselves is churn surface. |
| Neuestar-carried third-party components | ≤ 1 | e.g., the selected bwrap in A1. For each: upstream project, upstream version/commit, source provenance, binary SHA-256, patch count, security/update responsibility. Carrying a component inherits release/vulnerability/compatibility tracking even when its source is not ours. |
| Neuestar-local patches to carried third-party components | 0 | A private bwrap patch stack changes the integration burden; zero patches is a hard requirement for H0. |
| Helper source LOC (first-party) | ≤ 2 000 | Auditability of the root-owned trust anchor if A2 is ever built. |
| Policy churn tolerance (in-release) | 0 edits per ordinary supported update | Any required edit is H0.5 failure (hard gate, not a threshold). |

## Rules

- These conditions were committed before physical/virtual H0 execution and
  before any integration prototype existed. They must not be relaxed after
  observing failures.
- No kill-condition-based H0 result is renegotiated: a failed target is
  recorded as failed evidence, never omitted or reclassified.
- Ambiguity is interpreted against the Installed Substrate hypothesis — i.e.,
  in favor of the predeclared Vertical Native fallback.
- On a kill, architecture expansion stops. Work is limited to reproduction,
  machine-readable evidence, an explicit verdict, and implications for the
  predeclared Vertical Native fallback.
