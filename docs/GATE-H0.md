# Gate H0 — Installed Substrate

Status: **PROPOSAL, revised per architectural review — awaiting freeze.**
No code or VMs touched.

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

System modification is permitted only through the normal privileged package
lifecycle (install/update/remove) of the declared integration package; every
runtime/application launch is ordinary-user execution.

## 2. Precommitted invariants

A. No per-application policy.
B. No per-runtime-generation policy.
C. No per-GPU-vendor or driver-version policy.
D. No bespoke per-machine instructions or edits beyond normal
   install/update/remove of the declared integration package through the
   distro package manager.
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
| Host integration package | distro-installed, root-owned | package lifecycle (install/update/remove) only | own version; part of integration identity | attached to this layer only |
| Runtime generation | Neuestar, content-addressed | ordinary user | immutable per generation | none (never referenced by policy) |
| Application | Neuestar, per-app payload | ordinary user | per app | none (unknown to host layer) |

The host layer knows "Neuestar runtime", never a specific application or
generation identity.

## 4. Gates

### H0.0 — Baseline classification (observational)

On pristine/current target systems, record whether the frozen Campaign 002
minimum user+mount operation works **without integration**. Reproduce existing
evidence where available; never infer one distro's result from another.

Initial targets (see §6 for exact scoping): Ubuntu 26.04 LTS, Ubuntu 24.04.4
LTS, Fedora 44, Arch Linux (official `linux` kernel), NixOS 26.05.

### H0.1 — Minimum host integration

Where baseline fails, determine the smallest legitimate system-installed
integration that allows the SAME minimum controlled-root operation, installed
through the distro's normal system integration mechanism, with policy attached
only to root-controlled executable paths. Never attach userns/mount privileges
to `~/.local`, `~/Downloads`, `/tmp`, user-writable runtime stores, or
content-addressed generation directories writable by the user. Never disable
AppArmor or SELinux. Candidate designs in §8.

### H0.1S — Host-security preservation (hard gate)

The installed integration must not turn the trusted helper into a general
bypass of the distro's user-namespace restriction. Required negative evidence:

- helper executable is root-owned and not user-writable;
- policy attachment actually resolves to that helper;
- the child runs under the intended stacked/restricted profile;
- the child does not retain setup capabilities;
- arbitrary child execution cannot retain `CAP_SYS_ADMIN` or equivalent setup
  authority;
- the helper cannot be redirected to an alternate user-writable executable;
- application/runtime code receives no additional host privilege merely
  because the integration package is installed.

Failure of H0.1S rejects that integration candidate. This gate exists because
Ubuntu's own `bwrap-userns-restrict` design exists specifically to prevent
bwrap from becoming a trivial bypass of the userns restriction.

### H0.2a — Generation-identity independence

The SAME installed host integration must successfully launch the controlled
root from two genuinely different runtime artifacts G1 and G2 with distinct
content hashes but identical H0-relevant behavior (they may differ only by a
harmless build marker/test payload initially). The host integration must not
mention either hash. A content-addressed store must not be tested with
manufactured duplicate identities for the same bytes — identical bytes carry
identical content identity by definition.

If physical path independence is separately of interest, test that explicitly
(distinct installation paths) rather than conflating it with content identity.

### H0.2b — Real generation churn

Later, replace G2 with a materially new runtime generation. The exact same host
integration identity must continue to work. An integration edit caused only by
adding a generation is failure.

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

### H0.4R — Cross-release integration portability

Same architecture and common integration source across supported distro
releases (e.g., Ubuntu 24.04.4 and Ubuntu 26.04 are different major LTS
generations with different AppArmor generations and policy evolution). Small,
explicitly measured compatibility declarations may differ; every difference
counts against the distro-specific burden. Cross-major-release adaptation is
measured here, not as in-release churn.

### H0.5 — In-release churn (strict)

Freeze the integration identity (source + package + policy). Perform normal
supported in-release host updates without changing Neuestar (same integration
package hash, same runtime generation, distro/security-policy update) and
rerun. **Any** ordinary in-release supported security-policy update requiring a
Neuestar integration-source change is H0.5 failure (this matches the stricter
reading of kill condition 12; the two must not diverge).

### H0.6 — Lifecycle evidence (long-horizon, later)

If a long-horizon claim is wanted (e.g., 26.04 → next Ubuntu LTS /
security-policy generation), it is a separate later test, explicitly labeled
lifecycle evidence, never merged into H0.5.

### H0.P — Probe equivalence (apparatus gate, before Fedora/Arch)

Before the purpose-built H0 probe is used on Fedora and Arch, prove it is
equivalent to the part of Campaign 002 it extracts. The unintegrated H0 probe
must reproduce the known Campaign 002 containment outcomes:

- Ubuntu 26.04: Campaign 002 → userns/uid-map failure; H0 probe → the same
  boundary failure.
- NixOS 26.05: Campaign 002 → L0.0/L0.1 success; H0 probe → the same minimum
  controlled-root success.

If equivalence does not hold, stop and fix the apparatus before learning
anything from Fedora/Arch.

## 5. Baseline inventory (primary sources, 2026-08-16)

| Distro | userns / LSM state (primary source) | Expected H0.0 |
|---|---|---|
| Ubuntu 26.04 LTS | AppArmor unprivileged-userns restriction default-on; `bwrap-userns-restrict` profile ships in Ubuntu AppArmor packaging, attached to `/usr/bin/bwrap` (userns/mount/pivot_root in profile, capability-denying stacked child) | fail (Campaign 002 reproduced) |
| Ubuntu 24.04.4 LTS | Restriction default-on since 24.04 (part of the LTS security model). The bwrap-profile packaging/enforcement state **changed during Noble updates**: a July 2024 bwrap profile caused regressions and was reverted; `4.0.1really4.0.1-0ubuntu0.24.04.3` (September 2024, Noble updates) retained the change that enables `bwrap-userns-restrict`; current Noble is beyond that. H0 must inspect the exact currently installed/loaded policy state rather than assume the initial-release state. | fail (expected; must be observed) |
| Fedora 44 | Unprivileged userns enabled by default (`user.max_user_namespaces`; no Ubuntu-style AppArmor mediation); SELinux enforcing but default desktop users unconfined; bwrap/flatpak work | pass (expected; must be observed) |
| Arch (official `linux`) | Unprivileged userns enabled on officially supported kernels **except `linux-hardened`**; AppArmor not enabled/enforcing by default | pass (expected; must be observed) |
| NixOS 26.05 | Unprivileged userns permitted; no AppArmor userns mediation (stock generated configuration) | pass (Campaign 002 evidence) |

Every expected value is a hypothesis to be observed on a pristine system; no
distro result is inferred from another. For the AppArmor-family hosts, H0
evidence records the concrete policy state (below).

## 6. Target host profiles (exact scoping)

- **Arch Linux**: official `linux` kernel; exact ISO/snapshot date (YYYY-MM-DD)
  and exact kernel version recorded; stock AppArmor state; ordinary
  desktop/user configuration. Decide **before execution** whether
  `linux-hardened` is (a) a required target whose failure can kill H0, or (b)
  an explicitly unsupported optional kernel profile. Default proposal: (b),
  recorded as such — do not discover the policy after it fails. Note that the
  Arch bubblewrap documentation warns hardened-kernel users may need
  `bubblewrap-suid`, which H0 forbids (invariant F).
- **NixOS 26.05**: "stock generated configuration / no AppArmor" is a
  particular target profile, not a claim about every configurable NixOS
  installation; record the actual configuration surface.
- **Ubuntu**: exact current update state captured (see evidence model), since
  Noble's bwrap/profile packaging changed over time.

## 7. Candidate architectures

### A1 — Neuestar-controlled bwrap at a stable root-owned path (preferred first)

```
distro package
   ├─ /usr/libexec/neuestar/bwrap
   │     exact known Neuestar-selected binary (mature namespace/mount tool)
   │     root-owned, non-user-writable
   └─ Neuestar security policy attached to that path
         upstream-style child-profile stacking
         (no custom namespace implementation)
        │
        ▼
   portable Neuestar runtime generations
```

No new security-sensitive namespace code is written for A1.

### A2 — Purpose-built Neuestar helper (last resort)

Only considered if A1 demonstrably cannot satisfy H0. New security-sensitive
namespace/mount code is a last resort, gated on a demonstrated reason (helper
LOC threshold applies; §9).

### B — distro-provided `/usr/bin/bwrap`

```
package dependency → host /usr/bin/bwrap → Neuestar controlled root
```

Evaluate as the provenance tradeoff, not implicitly. Comparison with A1 is
clean: Neuestar chooses bwrap vs distro chooses bwrap; stable Neuestar path vs
distro system path; Neuestar policy vs distro policy; known helper version vs
distro helper version. If B wins, state explicitly that Neuestar depends on a
distro-provided execution substrate.

### C — broad profile over runtime-generation paths — DESIGN-REJECTED

No execution. A profile granting namespace/mount privilege to user-writable
executable locations violates invariant H; it is rejected by design, and no
variant of it is implemented to obtain a positive result.

## 8. Burden thresholds (PROPOSED — for review/freeze; non-gameable by definition)

Definitions (tightened so the numbers cannot be gamed):

- root-owned bytes = Neuestar-owned payload bytes installed outside
  package-manager metadata;
- file count = Neuestar-owned filesystem entries only;
- policy LOC = nonblank/noncomment Neuestar-maintained policy source,
  including local includes;
- distro branch = a semantically different code/policy path, not packaging
  boilerplate;
- helper LOC = first-party helper code only; generated/vendor code excluded
  (A1's selected bwrap binary therefore counts zero).

| Metric | Ceiling | Rationale |
|---|---|---|
| Root-owned installed bytes | ≤ 8 MiB | Generous headroom; the exact number matters less than the intrinsic definition above. |
| Installed file count (Neuestar-owned) | ≤ 20 | Helper + 1–2 policy profiles + package control files. Flatpak-class installs are hundreds of files. |
| Policy LOC (all distros, nonblank/noncomment) | ≤ 200 | Upstream `bwrap-userns-restrict` (profile + unpriv profile) ≈ 60 lines; one Neuestar profile of the same pattern ≈ ≤ 100; 200 leaves headroom for a second family. |
| Distro-specific implementation branches | ≤ 2 | Baseline predicts only the Ubuntu/AppArmor family needs policy; the second branch is budgeted only if Fedora SELinux proves necessary. |
| Services/daemons | 0 | A static on-demand helper needs no daemon; daemons add perpetual maintenance and attack surface. |
| Additional required host packages | ≤ 2 | Must come from the distro's supported repositories; no third-party repositories; no exact package-version pinning; no dependency whose ABI/version forces Neuestar policy changes during ordinary supported updates; all dependencies counted and recorded. A dependency is not automatically equal maintenance burden to vendored code. |
| Neuestar-maintained dependencies | 0 | Any dependency we must maintain ourselves is churn surface. |
| Helper source LOC (first-party) | ≤ 2 000 | Auditability of the root-owned trust anchor if A2 is ever built (bwrap itself ≈ 5k LOC but is vendor/excluded for A1). |
| Policy churn tolerance (in-release) | 0 edits per ordinary supported update | Any required edit is H0.5 failure (hard gate, not a threshold). |

These ceilings are proposals for review and freeze before any prototype code.

## 9. H0 evidence model (separate `neuestar.h0/v1`)

A new schema/version; no H0 fields are added to `neuestar.report/v2`; no frozen
artifact/report/hash is touched. Every H0 attempt records:

- H0 schema version; distro + version + kernel; exact target-profile scoping
  (ISO/snapshot date, kernel version, LSM configuration surface)
- relevant active LSM/security-policy state: AppArmor parser version, ABI,
  loaded-profile names/modes, loaded-policy SHA-256, actual bwrap/helper
  profile path, `kernel.apparmor_restrict_unprivileged_userns` (and equivalent
  for SELinux hosts: enforcing mode, booleans)
- integration candidate (A1/A2/B/none); integration package SHA-256;
  integration source SHA-256; security-policy SHA-256; root-owned helper
  SHA-256; runtime artifact SHA-256; runtime generation/path identity;
  application payload identity
- `trusted_helper`: canonical_path, sha256, uid, gid, mode,
  parent_mount_writable_by_test_user
- `apparmor`: parser_version, abi, loaded_profile_name, loaded_profile_mode,
  loaded_policy_sha256
- `execution`: helper_profile_label, child_profile_label,
  child_effective_capabilities
- `apparatus`: probe_sha256, containment_argv
- exact installed file manifest; installed byte count; package dependencies;
  services/daemons introduced; privileged install operations; forbidden
  preparation
- result per H0 gate (H0.0, H0.1, H0.1S, H0.2a, H0.2b, H0.3, H0.4, H0.4R,
  H0.5, H0.P); stderr/failure evidence; pre/post host state relevant to policy;
  whether integration source changed since previous run

Candidate-aware fields: a candidate may legitimately record
`neuestar_integration_package_sha = null` with `host_bwrap_package_version = …`
(Candidate B). Do not force meaningless zero hashes to satisfy a common schema.

Evidence fails closed: a missing/malformed record is failure; a failed guest is
never silently repaired.

Integration identity: canonical hash over ALL Neuestar-maintained system
integration (helper source/binary, AppArmor/SELinux policy, package
scripts/specs, config installed into privileged system locations).
Host-discovered state is evidence but is NOT part of the integration hash.

## 10. Experimental environments (H0 PREFLIGHT)

Full QEMU/KVM + libvirt VMs only; never Docker/Podman. New pristine bases and
overlays where needed. Existing Ubuntu 26.04 and NixOS 26.05 pristine bases are
reused through NEW external overlays. Campaign 001 and Campaign 002 evidence
guests are never mutated. New bases: Ubuntu 24.04.4 LTS, Fedora 44, Arch
(official `linux`). No GPU passthrough; H0 is about the host integration needed
to establish the controlled user+mount runtime boundary, not Vulkan.

If the existing launcher's display/GPU preflight blocks an H0-isolated test,
do not fake display variables; use the purpose-built H0 probe (gated by H0.P).
The frozen Campaign 002 artifact is not modified.

## 11. Execution order

1. Freeze GATE-H0 + H0-KILL-CONDITIONS (after review adjustments).
2. Build the H0 evidence schema (`neuestar.h0/v1`).
3. Build the minimal H0 probe.
4. H0.P probe equivalence: Ubuntu 26.04, NixOS 26.05.
5. Candidate A1: stable root-owned Neuestar-controlled bwrap + Ubuntu AppArmor
   integration.
6. H0.1S adversarial security checks.
7. Ubuntu 26.04 H0 PREFLIGHT.
8. NixOS control (zero integration).
9. Fedora 44 stock (independent zero-integration hypothesis).
10. Arch stock `linux`, pinned snapshot (independent zero-integration
    hypothesis).
11. Ubuntu 24.04 current-updates state (same integration source/policy design).
12. Compare A1 against Candidate B.
13. Only then decide whether A2 (custom helper) deserves to exist.
14. Design in-release H0.5 churn.

Stop immediately if a precommitted kill condition is hit.

## 12. Premise risks (reasons to stop before coding)

1. **AppArmor stacking must be validated on-system first.** A1's mechanism
   (confined root-owned helper with in-profile userns/mount, stacked
   capability-denying child) mirrors the shipped `/usr/bin/bwrap` profile, but
   the transition semantics for a Neuestar path must be demonstrated before
   building beyond the probe — that is the first prototype test.
2. **Ubuntu policy is tightening, not static.** `bwrap-userns-restrict` is a
   reaction; Noble's own regression/rollback/re-enable history is evidence.
   In-release churn (H0.5) is strict; cross-release adaptation (H0.4R) is
   measured separately; long-horizon claims require H0.6.
3. **A1 keeps the trust anchor mature; A2 would create a new one.** A2's helper
   would be a new root-owned security-sensitive binary — only justified by a
   demonstrated A1 failure, bounded by the helper-LOC threshold.
4. **Two execution paths (zero-integration and integrated) must be designed,
   not incidental.** The portable runtime must behave identically through both;
   drift between paths is an apparatus risk.
5. **Generation-store placement.** A root-owned store would reintroduce
   per-generation install actions (violating J). A user-writable
   content-addressed store requires the stacked child profile to hold for
   children exec'd from user-writable paths — proven, not assumed.
6. **Even full H0 success does not touch L0.** Narrative discipline (never
   "Campaign 002 now passes on Ubuntu") is a protocol invariant.

## 13. Explicitly NOT built yet

- No H0 evidence schema, probe, helper binary, bwrap selection, AppArmor/SELinux
  profile file, package, or workflow changes.
- No new VM base, overlay, or guest boot; no matrix run.
- No changes to the frozen Campaign 002 artifact, report, hash, or verdict; no
  changes to `neuestar.report/v2` or `schema/report-v1.schema.json`.
- No Candidate C execution of any variant; no sysctl/AppArmor-disable
  experiments; no silent adoption of host `/usr/bin/bwrap`.
- No Vulkan/L0.2, Scene, UI, Scratchpad, renderer, or broker work.
