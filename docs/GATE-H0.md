# Gate H0 — Installed Substrate

Status: **PROPOSAL for review — not yet frozen, no code or VMs touched.**

Campaign 002 (frozen) tested the strong Zero-Preparation Substrate hypothesis
and was rejected on Ubuntu 26.04 full-VM policy (`bwrap: setting up uid map:
Permission denied`). That result stands; it is never reclassified, repaired,
omitted, or replaced by H0 evidence.

Gate H0 tests a NEW hypothesis:

> A small, one-time, system-integrated Neuestar host package may establish the
> minimum host trust/security integration required by a distribution, while all
> runtime generations and applications above that layer remain portable,
> versioned, immutable, and independent of distro/security-policy details.

Until the pending bare-metal Ubuntu 26.04 Campaign 002 confirmation completes,
all H0 execution is labeled **H0 PREFLIGHT**. H0 does not supersede L0, and a
successful H0 does not change any Campaign 002 statement.

The only valid post-H0 statement is:

> "Campaign 002 rejected the zero-preparation substrate on Ubuntu. Gate H0
> separately found that an installed host-integration layer can/cannot recover
> the Installed Substrate hypothesis within its precommitted maintenance
> budget."

## 1. Hypothesis question

> What is the minimum one-time host integration Neuestar needs across its
> target Linux distributions, and is that integration sufficiently small,
> generic, and stable that a shared versioned runtime still provides meaningful
> value over ordinary Vertical Native packaging?

The host-integration layer is privileged **at install time only**. Normal
application/runtime execution is ordinary-user execution.

## 2. Precommitted invariants

A. No per-application policy.
B. No per-runtime-generation policy.
C. No per-GPU-vendor or driver-version policy.
D. No per-machine policy or operator instructions.
E. No sysctl/security-disable workaround.
F. No setuid requirement.
G. No file capabilities used as an escape hatch.
H. No AppArmor/SELinux policy attached to a user-writable executable path.
I. Runtime/application artifacts remain byte-identical across distributions.
J. Runtime generations remain content-addressed/versioned and do not require
   host-policy edits when generations are added or removed.
K. The host integration layer may contain a root-owned stable helper
   executable and security-policy/package metadata.
L. A distro that needs no host integration is recorded as zero integration;
   do not invent uniform work merely for symmetry.

## 3. Layer model (must not collapse)

| Layer | Owner | Privilege | Versioning | Policy coupling |
|---|---|---|---|---|
| Host integration package | distro-installed, root-owned | install-time only | own version; part of integration identity | attached to this layer only |
| Runtime generation | Neuestar, content-addressed | ordinary user | immutable per generation | none (never referenced by policy) |
| Application | Neuestar, per-app payload | ordinary user | per app | none (unknown to host layer) |

The host layer knows "Neuestar runtime", never a specific application or
generation identity.

## 4. Gates

### H0.0 — Baseline classification (observational)

On pristine/current target systems, record whether the frozen Campaign 002
minimum user+mount operation works **without integration**. Reproduce existing
evidence where available; never infer one distro's result from another.

Initial targets:

- Ubuntu 26.04 LTS
- Ubuntu 24.04.4 LTS
- Fedora 44
- Arch Linux (current)
- NixOS 26.05

Campaign 002 NixOS/Ubuntu full-VM evidence may be referenced, not rewritten.

### H0.1 — Minimum host integration

Where baseline fails, determine the smallest legitimate system-installed
integration that allows the SAME minimum controlled-root operation, installed
through the distro's normal system integration mechanism.

Preferred candidate to evaluate (Candidate A):

- root-owned stable Neuestar host helper, e.g. `/usr/libexec/neuestar/…`
  (or distro-equivalent), plus
- the minimum required host security policy attached **only** to
  root-controlled executable paths.

Never attach userns/mount privileges to `~/.local`, `~/Downloads`, `/tmp`,
user-writable runtime stores, or content-addressed generation directories
writable by the user. Never disable AppArmor or SELinux.

Do not merely install or invoke host `/usr/bin/bwrap` and call that solved —
using the distro bwrap instead of the Neuestar-controlled helper changes helper
provenance and is a separate candidate design (Candidate B).

### H0.2 — Runtime-generation independence

The SAME installed host integration must successfully launch the controlled
root from at least two distinct runtime-generation locations/identities (e.g.,
two content addresses of the same frozen payload), so the policy cannot
accidentally depend on a generation hash. Later, repeat with a materially new
runtime generation without changing the host-integration package. An
integration edit caused only by adding a generation is failure.

### H0.3 — Application independence

Use at least two minimal application payload identities through the same
runtime/host integration. No application name, path, application ID,
executable hash, or application policy may appear in the host integration.

### H0.4 — Cross-distro burden

For each target distribution record: zero integration required, or a concrete
integration package with installed files, root-owned binaries, security-policy
files, package dependencies, services/daemons introduced, installation
privileges, package bytes, source/policy LOC, distro-specific source paths, and
exact package/integration SHA-256s. Do NOT force Fedora/Arch/NixOS to have an
integration package merely because Ubuntu needs one. The key metric is
maintenance burden, not visual symmetry.

### H0.5 — Policy churn

Freeze the integration package/source/hash. Perform normal supported host
updates without changing Neuestar (same integration package hash, same runtime
generation, distro/security-policy update) and rerun. The integration passes
churn only if it continues to work unchanged. An integration source/policy edit
required solely because the distro's normal security policy changed is an H0
churn failure.

Immediate Ubuntu cross-release test: Ubuntu 24.04.4 LTS and Ubuntu 26.04 LTS
with the same Neuestar integration SOURCE and policy design. Packaging metadata
may differ only where normal package-format/platform metadata genuinely
requires it; record every difference. Do not weaken one host's native security
configuration to force sameness.

## 5. Baseline inventory (primary sources, 2026-08-16)

| Distro | userns policy (primary source) | LSM | Expected H0.0 |
|---|---|---|---|
| Ubuntu 26.04 LTS | AppArmor unprivileged-userns restriction default-on since 24.04; `bwrap-userns-restrict` profile ships in Ubuntu AppArmor packaging attached to `/usr/bin/bwrap` (granting userns/mount/pivot_root, stacking a capability-denying child) | AppArmor (enforcing) | fail (Campaign 002 reproduced) |
| Ubuntu 24.04.4 LTS | Same restriction default-on; profile available as extra profile in `apparmor-profiles` (`/usr/share/apparmor/extra-profiles/bwrap-userns-restrict`), not enabled by default | AppArmor | fail (expected; must be observed) |
| Fedora 44 | Unprivileged userns enabled by default (`user.max_user_namespaces`; no Ubuntu-style AppArmor mediation); SELinux enforcing but default desktop users unconfined; bwrap/flatpak work | SELinux | pass (expected; must be observed) |
| Arch (current) | Unprivileged userns enabled on stock kernels (`linux-hardened` excepted); AppArmor not enabled/enforcing by default | none by default | pass (expected; must be observed) |
| NixOS 26.05 | Unprivileged userns permitted; no AppArmor userns mediation | none by default | pass (Campaign 002 evidence) |

Every expected value is a hypothesis to be observed on a pristine system; no
distro result is inferred from another.

## 6. Candidate architectures (compare; do not assume a winner)

### Candidate A — Neuestar-owned stable host helper (preferred to evaluate)

```
distro package
   ├─ root-owned Neuestar namespace/helper binary (static musl, minimal)
   └─ host security integration where required (e.g., AppArmor profile on
      /usr/libexec/neuestar/…, mirroring the upstream bwrap-userns-restrict
      pattern: in-profile userns+mount, stacked capability-denying child)
        │
        ▼
   portable Neuestar runtime generations (user-side, content-addressed,
   byte-identical across distros)
```

Advantages to test: known helper identity; stable policy attachment to a
root-controlled path; runtime-generation independence; immutable helper
provenance (our bytes, not a distro's). Costs to measure: distro packaging;
helper update cadence; policy maintenance; the helper is a new root-owned trust
anchor and must be minimal and audited.

### Candidate B — distro-provided `/usr/bin/bwrap`

```
package dependency → host /usr/bin/bwrap → Neuestar controlled root
```

Do not adopt implicitly. Measure the loss of helper-version control, immutable
helper provenance, and cross-distro helper consistency (bwrap version/behavior
differs per distro/release; Ubuntu's shipped profile is bound to
`/usr/bin/bwrap`, so it carries distro-maintained policy). If Candidate B wins,
state explicitly that Neuestar depends on a distro-provided execution
substrate.

### Candidate C — broad profile over runtime-generation paths

Evaluate only enough to determine whether it violates the security invariants.
A profile granting namespace/mount privilege to user-writable executable
locations violates invariant H and is rejected, not made to pass. Unsafe
variants are never implemented to obtain a positive result.

## 7. Burden thresholds (PROPOSED — for review/freeze, not silently chosen)

Warning thresholds for kill condition 13 (mini-Flatpak drift). Values are
budget ceilings for the WHOLE maintained integration layer (all distros).

| Metric | Ceiling | Rationale |
|---|---|---|
| Root-owned installed bytes (integration package total) | ≤ 8 MiB | A static musl helper is ~1–2 MiB; policy is KB. 8 MiB is ~1/100 of a typical Flatpak runtime bundle and ~10× a single helper — keeps "small adapter" honest. |
| Installed file count | ≤ 20 | One helper + 1–2 policy profiles + package control files. Flatpak-class installs are hundreds of files. |
| Policy LOC (all distros, combined) | ≤ 200 | Upstream `bwrap-userns-restrict` (profile + unpriv profile) is ~60 lines; one Neuestar profile of the same pattern ≤ ~100; 200 total leaves headroom for a second family. |
| Distro-specific implementation branches | ≤ 2 | Baseline predicts only the Ubuntu/AppArmor family needs policy; the second branch is budgeted only if Fedora SELinux proves necessary. |
| Services/daemons introduced | 0 | A static helper invoked on demand needs no daemon; daemons add perpetual maintenance and attack surface. |
| External runtime package dependencies | 0 | The helper is static; each runtime dependency is churn surface. Build-time dependencies do not count. |
| Helper source LOC | ≤ 2 000 | Auditability of the new root-owned trust anchor (bwrap itself is ~5k LOC; a purpose-built userns+mount+exec helper should be far smaller). |
| Policy churn tolerance | 0 edits per normal distro update | Any required edit = H0.5 failure (hard gate, not a threshold). |

These ceilings are proposals for review and freeze **before** any prototype
code; they are not chosen silently during testing.

## 8. H0 evidence model (separate from neuestar.report/v2)

Proposed `neuestar.h0/v1` — a new schema/version; no H0 fields are added to
`neuestar.report/v2` and no frozen artifact/report/hash is touched. Every H0
attempt records at least:

- H0 schema version
- distro + version + kernel
- relevant active LSM/security-policy state (enforcing status, loaded profiles,
  restriction sysctls)
- integration candidate (A/B/C/none)
- integration package SHA-256
- integration source SHA-256
- security-policy SHA-256
- root-owned helper SHA-256
- runtime artifact SHA-256
- runtime generation/path identity
- application payload identity
- exact installed file manifest
- installed byte count
- package dependencies
- services/daemons introduced
- privileged install operations
- forbidden preparation
- result per H0 gate (H0.0–H0.5)
- stderr/failure evidence
- pre/post host state relevant to policy
- whether integration source changed since previous run

Evidence fails closed: a missing/malformed record is failure; a failed guest is
never silently repaired.

Integration identity: canonical hash over ALL Neuestar-maintained system
integration (helper source/binary, AppArmor/SELinux policy, package
scripts/specs, config installed into privileged system locations).
Host-discovered state is evidence but is NOT part of the integration hash.

## 9. Experimental environments (H0 PREFLIGHT)

Full QEMU/KVM + libvirt VMs only; never Docker/Podman. New pristine bases and
overlays where needed. Existing Ubuntu 26.04 and NixOS 26.05 pristine bases are
reused through NEW external overlays. Campaign 001 and Campaign 002 evidence
guests are never mutated. New bases to build: Ubuntu 24.04.4 LTS, Fedora 44,
current Arch. No GPU passthrough; H0 is about the host integration needed to
establish the controlled user+mount runtime boundary, not Vulkan.

If the existing launcher's display/GPU preflight blocks an H0-isolated test,
do not fake display variables; use a purpose-built H0 probe whose only job is
to test the host integration boundary. The frozen Campaign 002 artifact is not
modified.

## 10. First execution order (not the full matrix)

A. Write the H0 hypothesis/gates/kill conditions (this document set).
B. Inventory current upstream distro behavior from primary sources only.
C. Propose quantitative H0 burden thresholds.
D. Review/freeze those documents.
E. Build only the minimum H0 probe/integration prototype.
F. Run Ubuntu 26.04 H0 PREFLIGHT first.
G. Run NixOS 26.05 as the zero-integration control.
H. Run Fedora 44 as an independent zero-integration hypothesis.
I. Run Arch as an independent zero-integration hypothesis.
J. Run Ubuntu 24.04.4 with the exact same integration design.
K. Only after those results, design the first churn run.

Stop immediately if a precommitted kill condition is hit.

## 11. Premise risks (reasons to stop before coding)

1. **AppArmor stacking must be validated on-system first.** The candidate A
   mechanism (confined root-owned helper with in-profile userns/mount, stacked
   capability-denying child) mirrors the shipped `/usr/bin/bwrap` profile, but
   the transition semantics for a Neuestar path must be demonstrated before
   writing the prototype — that is the very first prototype test, not a
   deferred assumption.
2. **Ubuntu policy is tightening, not static.** `bwrap-userns-restrict` is
   itself a reaction; H0.5 churn risk is real. The 24.04→26.04 cross-release
   test is within one policy family and is a weak churn probe; a full verdict
   needs an LTS-lifetime view (one update series + a policy-version jump).
   Interim verdicts after step K are provisional until then.
3. **The root-owned helper is a new trust anchor.** A defect there is worse
   than today's unprivileged launcher. It must be minimal, static, argv-bound,
   exec only into the controlled root, and audited; helper LOC is a threshold.
4. **Two execution paths (zero-integration and integrated) must be designed,
   not incidental.** The portable runtime must behave identically through both;
   drift between paths is an apparatus risk.
5. **Generation-store placement.** A root-owned store would reintroduce
   per-generation install actions (violating J). A user-writable
   content-addressed store requires the unpriv stacking to hold for children
   exec'd from user-writable paths — the mechanism Flatpak relies on, but it
   must be proven for our profile, not assumed.
6. **Even full H0 success does not touch L0.** Narrative discipline (never
   "Campaign 002 now passes on Ubuntu") is a protocol invariant.

## 12. Explicitly NOT built yet

- No H0 probe, helper binary, AppArmor/SELinux profile file, package, or
  workflow changes.
- No new VM base, overlay, or guest boot; no matrix run.
- No changes to the frozen Campaign 002 artifact, report, hash, or verdict; no
  changes to `neuestar.report/v2` or `schema/report-v1.schema.json`.
- No Candidate C unsafe variants; no sysctl/AppArmor-disable experiments; no
  silent adoption of host `/usr/bin/bwrap`.
- No Vulkan/L0.2, Scene, UI, Scratchpad, renderer, or broker work.
