# A2 PREFLIGHT — Candidate A2a on Ubuntu 26.04 (2026-08-17)

Status: **H0 PREFLIGHT** in a QEMU/KVM + libvirt VM, **fresh overlay**
(`ubuntu-2604-a2`, created after A1 was rejected; nothing Neuestar-specific
in the base — verified before install). The A2 adversarial suite
(`docs/A2-ADVERSARIAL-SUITE.md`, precommitted before any A2 code) is the
acceptance gate; the machine record is evidence admissibility, not the
verdict.

## Architecture (A2a — static privilege-entry gate)

Fixes the discovered failure class (A1 AND distro bwrap): user-controlled
code must never execute while setup authority exists.

```
ordinary user
    ↓
/usr/libexec/neuestar/entry        STATIC (no PT_INTERP, no PT_DYNAMIC), root 0755
    | holds NO setup authority; sanitizes env from scratch, closes inherited
    | FDs > 2, constructs the frozen Campaign 002 operation argv, records it,
    | execs bwrap-real via a secure-exec (Px) AppArmor transition
    ↓
/usr/libexec/neuestar/bwrap-real   exact pinned upstream bwrap (52231e1c…, 0 patches)
    | NO path profile → direct exec is unconfined → blocked by the distro
    | userns restriction; setup authority (neuestar-bwrap-real, enforce)
    | reached ONLY through the entry's named-profile transition
    ↓
namespace setup → child stacked into neuestar-bwrap-real//&neuestar-unpriv
    ↓
runtime/app (CapEff 0)
```

## Identities

| | value |
|---|---|
| H0 probe binary SHA-256 | `e22dfd5bd32add3561c8235b0aa280e50471e7fbd1e6c25799a3af9a3c0b4987` |
| entry SHA-256 | `3961d4a49b95a717c9d92ce02ec818336cab5b731edeab1350fd280a8b44c180` (431,480-byte static binary) |
| bwrap-real SHA-256 | `52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712` (exact pin, 0 patches) |
| A2 package SHA-256 | `94ccee7f6bd2e9062526a9b7f4c7dbf065b2cb4a82bd8092dd7a73e0b1e122e6` |
| integration source | `4ee0e12991b6e6c03cd3c3124ea1ebb979aeb8da` |
| frozen artifact | `a5773bc2…` (Campaign 002, unchanged) |

## Machine record (`neuestar.h0/v2`)

| | value |
|---|---|
| gates.h0_1 | **pass** — the minimum user+mount operation completes through the entry |
| gates.h0_1s | **pass** (machine) — evidence invocation re-executes the probe in the same boundary |
| child_profile_label | `neuestar-bwrap-real//&neuestar-unpriv (enforce)` |
| child CapEff raw / decoded | `0000000000000000` / `[]` |
| helper_profile_label | `neuestar-entry` (root-written install-time state) |
| trusted_helper | `/usr/libexec/neuestar/entry`, uid 0, mode 0755, regular, **elf_interpreter: null** (static), parent not writable |
| constructed argv | outcome 52 args / evidence 56 args — recorded AND verified byte-equal to the frozen command shape (drift guard) |
| burden | 6 files, 1 carried component (bwrap-real, 0 patches), 3 policies (102 LOC) |
| h0-check | **PASS (0 violations)** |

## Adversarial suite results (the gate)

| # | test | result |
|---|---|---|
| 1 | Entry injection (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, GLIBC_TUNABLES, GCONV_PATH) | constructor **never runs** (static entry has no loader); operation completes |
| 2 | Direct `/usr/libexec/neuestar/bwrap-real` + LD_PRELOAD | `unshare=1 uid_map=0` — **denied** (unconfined, restriction active) |
| 2 | entry copied to user path + hostile env | `bwrap: setting up uid map: Permission denied` — **denied** |
| 2 | bwrap-real copied to user path + LD_PRELOAD | `unshare=1 uid_map=0` — **denied** |
| 3 | Argument abuse: unknown flag / evil mode / missing --evidence-probe / bad root | all rejected (exit 2), no authority |
| 4 | Hostile inherited FDs (regular file, marker file, FIFO) | entry closes all FDs > 2; bwrap-real runs with exactly 3 fds (0,1,2) |
| 5 | Contained hostile child (static adversarial specimen bound from outside) | `unshare_ns=2 mount=0 pivot=0` — nested **uid_map denied**, **mount denied**, **pivot_root denied** under the stacked profile |
| 6 | Static-property evidence | `readelf`: PT_INTERP/PT_DYNAMIC absent; `ldd`: not a dynamic executable; recorded `elf_interpreter: null` |

No user-controlled code acquired uid-map authority through any privileged
path. The A1 failure vector (loader-injected constructor under the setup
profile) is structurally eliminated: the setup-profile process is reached
only through a static stage with a scrubbed boundary, and the private setup
binary carries no path-granted profile.

## Verdict

```
H0.P                PASS
A1/H0.1             PASS
A1/H0.1S            FAIL → A1 rejected
B functional        PASS (Ubuntu 26.04)
B hostile loader    FAIL → B rejected (Ubuntu 26.04)
A2a/H0.1 + H0.1S    PASS (machine + adversarial suite)
```

Candidate A2a is a PREFLIGHT PASS on the precommitted suite, pending
apparatus review. The burden is inside the frozen ceilings (1 carried
component, 0 patches, no setuid, no file caps, no daemon, no distro branch —
Ubuntu-specific packaging only, no private bwrap patches).

Note on scope: this was the A2a falsifier on the mandatory target. The
frozen order's remaining substrate baselines (fresh NixOS control, Fedora,
Arch, Ubuntu 24.04) and the later gates (H0.5 churn, generation tests) have
not been run.

Evidence: [`docs/a2-preflight-evidence/`](a2-preflight-evidence/) (record,
child evidence, entry-recorded argv, suite outputs, manifest).