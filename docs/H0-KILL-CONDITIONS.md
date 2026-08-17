# H0 — Precommitted Kill Conditions (Installed Substrate)

Status: **PROPOSAL for review — committed before any H0 implementation or
testing.** These rules must not be relaxed after observing failures.

Installed Substrate dies and Neuestar falls back to Vertical Native if any of
the following becomes necessary:

1. Per-application AppArmor/SELinux/security policy.
2. Per-runtime-generation policy.
3. Per-GPU or per-driver security policy.
4. Per-machine edits or operator instructions.
5. Disabling or globally weakening AppArmor/SELinux/userns restrictions.
6. A setuid helper as a compatibility strategy.
7. File capabilities as a compatibility strategy.
8. Security profiles attached to user-writable executable locations.
9. Runtime artifacts rebuilt differently per distro solely for H0.
10. Host integration package changed whenever a normal runtime generation
    changes.
11. A growing distro/security special-case rule table analogous to the L0
    capture-rule failure mode.
12. Normal distro security-policy churn repeatedly requiring Neuestar policy
    source edits.
13. The integration layer grows enough that Neuestar is effectively
    maintaining a mini Flatpak/Steam Runtime distribution stack rather than a
    small host adapter.
14. A failed target is omitted or reclassified after results are known.

## Thresholds for kill condition 13 (proposed, pending review/freeze)

Ceilings for the whole maintained integration layer across all target distros.
These are proposals for architectural review and must be frozen before any
prototype code; they are not chosen silently during testing.

| Metric | Ceiling | Rationale |
|---|---|---|
| Root-owned installed bytes | ≤ 8 MiB | Static musl helper ≈ 1–2 MiB + KB of policy; 8 MiB ≈ 1/100 of a Flatpak runtime bundle, ~10× a single helper. Keeps "small adapter" honest. |
| Installed file count | ≤ 20 | Helper + 1–2 policy profiles + package control files. Flatpak-class installs are hundreds of files. |
| Policy LOC (all distros) | ≤ 200 | Upstream `bwrap-userns-restrict` (profile + unpriv profile) ≈ 60 lines; one Neuestar profile of the same pattern ≈ ≤ 100; 200 total leaves headroom for a second family. |
| Distro-specific implementation branches | ≤ 2 | Baseline predicts only the Ubuntu/AppArmor family needs policy; the second branch is budgeted only if Fedora SELinux proves necessary. |
| Services/daemons | 0 | A static on-demand helper needs no daemon; daemons add perpetual maintenance and attack surface. |
| External runtime package dependencies | 0 | Every runtime dependency is churn surface; build-time dependencies do not count. |
| Helper source LOC | ≤ 2 000 | Auditability of the new root-owned trust anchor (bwrap ≈ 5k LOC; a purpose-built userns+mount+exec helper should be far smaller). |
| Policy churn tolerance | 0 edits per normal distro update | Any required edit is an H0.5 failure (hard gate, not a threshold). |

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
