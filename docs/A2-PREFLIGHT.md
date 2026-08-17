# A2 PREFLIGHT — Candidate A2a on Ubuntu 26.04 (2026-08-17)

Status: **H0 PREFLIGHT** in a QEMU/KVM + libvirt VM, **fresh overlay**
(`ubuntu-2604-a3`, created after A1/B rejection; base verified pristine
before install). This is the **valid closing run**: exact frozen Campaign 002
identity, mechanically bound; the precommitted adversarial suite
(`docs/A2-ADVERSARIAL-SUITE.md`) plus the pre-exec ptrace falsifier are the
gate.

> The earlier run (`80d979b`, record `h0-report.json`) is preserved as
> **A2a exploratory/apparatus evidence with the wrong frozen payload
> identity** (Campaign 002 outer sha combined with the Campaign 001 extracted
> payload `e0c2c60f…`/`689760e3…`/probe 0.1.0). It is not the accepted run
> and is not rewritten. The probe now rejects that combination mechanically
> (`outer-archive-binding` apparatus failure).

## Architecture (A2a — static privilege-entry gate)

Fixes the discovered failure class (A1 AND distro bwrap): user-controlled
code must never execute while setup authority exists.

```
ordinary user
    ↓
/usr/libexec/neuestar/entry        STATIC (no PT_INTERP, no PT_DYNAMIC), root 0755
    | holds NO setup authority; sanitizes env from scratch, closes inherited
    | FDs > 2 (fail closed: abort if unprovable), fixes the artifact cwd
    | (fail closed), constructs the frozen Campaign 002 operation argv,
    | records it, execs bwrap-real via a secure-exec (Px) AppArmor transition
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

## Identities (valid run)

| | value |
|---|---|
| H0 probe binary SHA-256 | `1e4773c66a09a2395556e7964da29e0d8825aa9d0fe5cb5c81a0004b6431d596` |
| entry SHA-256 | `685e6f45b01f953c1078ad5b9f621c3d7ee6cb609fb69265feaa84da0d1d987a` (static; fail-closed FD/cwd fixes) |
| bwrap-real SHA-256 | `52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712` (exact pin, 0 patches) |
| A2 package SHA-256 | `91f098b69c528965cc607c663faf160e136434b0abc9277312ae05ecd049e35d` |
| integration source | `4ee0e12991b6e6c03cd3c3124ea1ebb979aeb8da` |
| **outer archive** | `a5773bc2b1cec810a6767aa2eb561791f3ab6c312b90afa4dac11e103c9c10fe` (verified on guest) |
| **payload manifest** | `b6f127341d019da391e6cc60cc1d432fde12f8e27602a61ff5e288aafedd0f8e` |
| **source commit** | `06adad5e83f1e31000bdbb44c693a3ece3dc5a6f` |
| **probe version** | `0.2.0` |
| first-party helper LOC | **296** (frozen definition: nonblank, non-comment) |
| policy LOC | **42** (frozen definition, across the 3 policy files) |

## Machine record (`neuestar.h0/v2`)

| | value |
|---|---|
| runtime.artifact / generation | `a5773bc2…` / `b6f12734…` — **exact C002 pair, outer↔payload binding verified** |
| gates.h0_1 / h0_1s | pass / pass (machine) |
| child_profile_label | `neuestar-bwrap-real//&neuestar-unpriv (enforce)` |
| child CapEff raw / decoded | `0000000000000000` / `[]` |
| helper_profile_label | `neuestar-entry` (root-written install-time state) |
| trusted_helper | `/usr/libexec/neuestar/entry`, uid 0, mode 0755, regular, **elf_interpreter: null**, parent not writable |
| constructed argv | outcome 52 / evidence 56 — recorded AND verified byte-equal to the frozen command shape |
| burden | 6 files, 1 carried component (0 patches), helper_loc 296, policy_loc 42 |
| h0-check | **PASS (0 violations)** |

## Adversarial suite results (valid run; the gate)

| # | test | result |
|---|---|---|
| 1 | Entry injection (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, GLIBC_TUNABLES, GCONV_PATH) | constructor **never runs**; operation completes |
| 2 | Direct bwrap-real / entry copy / bwrap-real copy + hostile env | all denied: `uid_map=0` or `bwrap: setting up uid map: Permission denied` |
| 3 | Argument abuse (unknown flag / evil mode / missing --evidence-probe) | all rejected (exit 2) |
| 4 | Hostile inherited FDs (file, marker, FIFO) | closed; bwrap-real runs with exactly 3 fds (0,1,2) |
| 5 | Contained hostile child (static specimen, bound from outside) | `unshare_ns=2 mount=0 pivot=0` — nested **uid_map denied, mount denied, pivot_root denied** |
| 6 | Static-property | PT_INTERP/PT_DYNAMIC absent; `elf_interpreter: null` recorded |
| 8 | **Pre-exec ptrace falsifier** | **PASS**: unconfined tracer survives both execs, but the traced exec is **withheld from the setup profile** — label at and after the second exec is `neuestar-entry (enforce)` (AppArmor refuses the domain transition for a traced exec), and the injected `unshare(CLONE_NEWUSER)` is **denied (-13 EACCES)**; uid_map is structurally unreachable. No user-controlled code acquired setup authority. |

No user-controlled code acquired uid-map authority through any privileged
path, by loader injection, direct path abuse, argument abuse, FD
inheritance, child code, or pre-exec ptrace.

## Verdict

```
H0.P                PASS
A1/H0.1             PASS
A1/H0.1S            FAIL → A1 rejected
B functional        PASS (Ubuntu 26.04)
B hostile loader    FAIL → B rejected (Ubuntu 26.04)
A2a/H0.1 + H0.1S    PASS (valid C002 run; machine + adversarial suite + ptrace falsifier)
```

Candidate A2a is a PREFLIGHT PASS pending apparatus review. Burden inside
every frozen ceiling: 1 carried component (0 patches), 296 first-party
helper LOC (≤ 2000), no setuid, no file caps, no daemon, no distro branch
(no private bwrap patches).

Remaining frozen-order items not started: fresh NixOS drift control, Fedora,
Arch, Ubuntu 24.04, generation independence, H0.5 churn.

Evidence: [`docs/a2-preflight-evidence/`](a2-preflight-evidence/) —
`h0-report-valid-c002.json`, `h0-child-evidence-valid-c002.json`,
`ptrace-falsifier-valid-c002.txt`, `ptrace_attacker.c`, suite outputs,
`manifest-valid-c002.txt`; the earlier wrong-identity record remains as
`h0-report.json`.
