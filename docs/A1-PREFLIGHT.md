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
| gates.h0_1s | **pass** |
| classification | pass |
| trusted_helper | `/usr/libexec/neuestar/bwrap`, uid 0, mode 0755, parent dir not user-writable |
| burden | 3 installed files / 73,430 bytes, policy 34 LOC, 1 distro branch, 1 carried component (0 patches) |
| schema + h0-check | valid + **PASS** (0 violations) |

## Adjudication (2026-08-17)

- **H0.1 — PASS (accepted).**
- **H0.1S — PARTIAL / NOT YET ACCEPTED as the gate verdict.** The machine
  result (stacked child, raw CapEff 0) is preserved as raw evidence in
  `docs/a1-preflight-evidence/`, but the frozen H0.1S contract requires
  negative evidence — arbitrary child code must not be able to obtain
  equivalent setup authority, the helper must not be redirectable to a
  user-writable executable, and installing A1 must not grant ordinary
  application code additional host privilege — none of which the machine
  result executed. The adversarial suite (user-writable helper copy, ordinary
  app userns attempt, malicious child, hostile LD_PRELOAD/loader-env
  injection, mechanized static invariants) is the pending gate.

## Interpretation

- **H0.1 = pass**: the installed root-owned helper with the Neuestar AppArmor
  policy attached to its path recovers the minimum user+mount operation on
  Ubuntu 26.04 — the same operation that fails zero-preparation (H0.P /
  Campaign 002, `bwrap: setting up uid map: Permission denied`).
- **H0.1S = pass, with on-system positive evidence**: the helper is granted
  enough authority to construct the namespace, and the contained child runs
  under the stacked restricted profile `neuestar-bwrap//&neuestar-unpriv
  (enforce)` with **raw CapEff 0 and an empty decoded set** — authority is
  stripped from arbitrary child/runtime code, not merely documented. Profile
  attachment is evidenced by the root-written install-time state (the
  ordinary-user securityfs view is empty, as observed in H0.P; the A1 record
  therefore does not rely on it).
- `h0-check PASS` is evidence admissibility, not the experiment outcome.

## Next per frozen GATE-H0 order

NixOS zero-integration control (fresh run as a drift control) → Fedora 44 →
Arch official `linux` → Ubuntu 24.04 current-updates → A1 vs B → H0.5 churn.
No Fedora/Arch bases built yet.

Evidence: [`docs/a1-preflight-evidence/`](a1-preflight-evidence/) (record, run
log, pre-run state).
