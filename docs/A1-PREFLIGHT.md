# A1 PREFLIGHT — Candidate A1 on Ubuntu 26.04 (2026-08-17)

Status: **H0 PREFLIGHT**. H0 does not supersede L0; the physical Campaign 002
confirmation is still pending. Execution in a full QEMU/KVM + libvirt VM.

## Apparatus identity

| Identity | Value |
|---|---|
| H0 probe binary SHA-256 | `af6de651c0288f8827402adc5f064f098991fe4bf7a4fdb96de968af00d7cca5` |
| Campaign 002 artifact (unchanged) | outer `a5773bc2b1cec810a6767aa2eb561791f3ab6c312b90afa4dac11e103c9c10fe`, probe 0.2.0 |
| A1 integration package (.deb) SHA-256 | `609b5f25d7032eedd5ef239c028adfd7d95e9378892cd845e28cb2047bfd84a0` |
| A1 integration source | commit `840684c8fa0fae5383bb258bd8852cb3635e0bb6` (`scripts/build-a1-deb.sh`) |
| Carried helper | upstream bwrap 0.9.0, SHA `52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712`, **0 Neuestar patches** |

## Experiment (narrower than the eventual package)

Fresh overlay `ubuntu-2604-a1` over the pristine base. Installed through the
normal privileged package lifecycle (`dpkg -i` of the hand-assembled .deb):
`/usr/libexec/neuestar/bwrap` (root-owned 0755, exact pinned upstream bytes) +
`/etc/apparmor.d/neuestar-bwrap` (AppArmor policy attached to that root-owned
path; upstream bwrap-userns-restrict semantics: in-profile userns/mount, child
stacked into the capability-denying `neuestar-unpriv`). The postinst loaded the
policy with `apparmor_parser` (AppArmor 5.0.0~beta1) and wrote
`/var/lib/neuestar/apparmor-state.json` as root-written install-time proof of
profile loading. The probe then ran as ordinary user `lab` reproducing only the
minimum user+mount operation, followed by the H0.1S security-evidence
invocation (probe re-exec inside the same boundary).

## Result

| | value |
|---|---|
| candidate | A1 |
| helper_started / child_reached | true / true |
| child ns identity | user `[4026532506]`, mount `[4026532505]` (differ from parent) |
| **helper_profile_label** | `neuestar-bwrap` |
| **child_profile_label** | `neuestar-bwrap//&neuestar-unpriv (enforce)` |
| **child CapEff raw / decoded** | `0000000000000000` / `[]` |
| gates.h0_1 | **pass** |
| gates.h0_1s | machine result **pass**; gate verdict **FAIL** after adversarial review |
| classification | historical machine record: pass; adjudicated H0.1S: fail |
| trusted_helper | `/usr/libexec/neuestar/bwrap`, uid 0, mode 0755, parent dir not user-writable |
| burden | 3 installed files / 73,430 bytes, policy 34 LOC, 1 distro branch, 1 carried component (0 patches) |
| schema + h0-check | valid + **PASS** (0 violations) |

## Adjudication (2026-08-17)

- **H0.1 — PASS (accepted).**
- **H0.1S — FAIL.** The historical machine result (stacked child, raw CapEff
  0) is preserved unchanged as raw evidence in
  `docs/a1-preflight-evidence/a1-ubuntu-report.json`; it was premature as a
  gate verdict because it did not execute the required negatives. The focused
  adversarial suite then found a genuine bypass: a user-controlled
  `LD_PRELOAD` constructor running inside the trusted helper created a nested
  user namespace and successfully wrote `uid_map` before bwrap's normal logic.
  The suite was halted at that stop condition; the malicious-child specimen's
  loader failure is inconclusive, not a negative result.

## Interpretation

- **H0.1 = pass**: the installed root-owned helper with the Neuestar AppArmor
  policy attached to its path recovers the minimum user+mount operation on
  Ubuntu 26.04 — the same operation that fails zero-preparation (H0.P /
  Campaign 002, `bwrap: setting up uid map: Permission denied`).
- The positive H0.1S specimen remains useful: the contained child reached the
  stacked restricted profile `neuestar-bwrap//&neuestar-unpriv (enforce)` with
  **raw CapEff 0 and an empty decoded set**.
- **H0.1S fails its negative contract**: the hostile loader constructor
  reported `unshare=1 uid_map=1 mount=0 pivot=0`. Arbitrary user-controlled
  code ran in the helper's broad profile and reacquired equivalent namespace
  setup authority. This is a genuine A1 security failure, not an apparatus
  failure. No profile tightening or reinterpretation was applied after the
  fact.
- The user-writable exact helper copy and ordinary application tests remained
  safely denied. The malicious-child run was inconclusive because the
  host-built specimen failed to load `libpthread.so.0` before `main`.
- `h0-check PASS` on the historical raw record was evidence admissibility, not
  the experiment outcome; the new checker/probe now mechanize the static
  invariants and freeze the second invocation argv.

## Gate consequence

H0.1S is **FAIL**. Stop A1 evaluation here; do not proceed to the NixOS
control, Fedora/Arch/Ubuntu baselines, A1-vs-B comparison, or later H0 gates.
The A1 trust-anchor design must be revised and re-adjudicated before any
further substrate control runs.

Evidence: [`docs/a1-preflight-evidence/`](a1-preflight-evidence/) (record, run
log, pre-run state).
