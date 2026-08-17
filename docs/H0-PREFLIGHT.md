# H0 PREFLIGHT — H0.P equivalence (2026-08-17)

Status: **H0 PREFLIGHT**. The physical Gate L0 verdict on Campaign 002 remains
pending the precommitted bare-metal Ubuntu confirmation; H0 does not supersede
L0 and no Campaign 002 statement changes. All execution in full QEMU/KVM +
libvirt VMs, never containers.

## Frozen apparatus identity

| Identity | Value |
|---|---|
| H0 source commit | `bdd190b70978ac946abe98025788010c51895a7b` |
| `h0-probe` binary SHA-256 | `ad255dd96b88cd79c6144f2fed32d02e8d7bdda3040541b13f5dfc9835b49f8d` |
| Campaign 002 artifact (unchanged) | outer `a5773bc2b1cec810a6767aa2eb561791f3ab6c312b90afa4dac11e103c9c10fe`, probe 0.2.0 |

The same static musl probe binary and the same frozen artifact were used for
both guests (binary SHA re-verified on each guest before the run). The probe
shares the Campaign 002 command construction, artifact preflight, and bounded
child-result predicate via `neuestar-probe-core`; it has no display/GPU
preflight and performs a single outcome run.

## Environment

Fresh external overlays (`ubuntu-2604-h0p.qcow2`, `nixos-2605-h0p.qcow2`) over
the pristine Campaign 002 base disks, fresh NVRAM, fresh evidence directories
(`/home/lab/h0p-ubuntu-2026-08-16/`, `/home/lab/h0p-nixos-2026-08-16/`).
Ordinary user `lab`; no sudo during any run; lab credential rotated on the
Ubuntu overlay as ordinary provisioning (SSH-key-only access). Artifact
SHA-256 and payload manifest re-verified on each guest before the run.

## H0.P results (single outcome run per guest)

| | ubuntu-2604-h0p (26.04, k7.0.0-29) | nixos-2605-h0p (26.05, k6.18.44) |
|---|---|---|
| helper_started | true | true |
| child_reached | false | true |
| child user ns | — | `user:[4026532491]` (parent `user:[4026531837]` — differs) |
| child mount ns | — | `mnt:[4026532490]` (parent `mnt:[4026531832]` — differs) |
| child arch / controlled libc | — | x86_64 / `/lib/x86_64-linux-gnu/libc.so.6` |
| gates.h0_0 | fail | pass |
| classification | fail | pass |
| failure | stage `baseline`, code `child-unreached`, stderr `bwrap: setting up uid map: Permission denied` | — |
| schema | `neuestar.h0/v1` valid | valid |
| h0-check | PASS (admissible, 0 violations) | PASS |

## H0.P verdict: PASS

The unintegrated H0 probe reproduces both frozen Campaign 002 outcomes with
the identical artifact, command environment, and success predicate:

- **Ubuntu 26.04**: Campaign 002 FAIL at the uid-map boundary == H0.P FAIL at
  the same boundary (verbatim stderr, `h0_0=fail`).
- **NixOS 26.05**: Campaign 002 PASS L0.0/L0.1 == H0.P PASS (user+mount
  namespaces differ from the probe parent, x86_64, controlled libc observed,
  `h0_0=pass`).

No material divergence; the apparatus is equivalent to Campaign 002 minus the
display/GPU preflight. Per protocol, nothing was repaired between an observed
failure and evidence preservation; both guests were powered off as-is.

`h0-check PASS` is evidence admissibility, not the experiment outcome: the
Ubuntu record legitimately reads schema-valid + h0-check PASS + classification
fail + `h0_0=fail` + baseline uid-map failure.

## H0.0 baseline observations (unintegrated minimum operation)

- Ubuntu 26.04 LTS: **fail** without integration (userns uid-map denial) —
  reproduced, not inferred.
- NixOS 26.05: **pass** with zero integration.

Remaining per GATE-H0 execution order (not yet run): Fedora 44 and Arch
(official `linux`) independent zero-integration baselines, Ubuntu 24.04.4
current-updates baseline, then Candidate A1 (new prototype + H0.1S), A1 vs B,
and in-release H0.5 churn.

Evidence: [`docs/h0-preflight-evidence/`](h0-preflight-evidence/) (both
reports, run logs, pre-run states, apparatus identity).
