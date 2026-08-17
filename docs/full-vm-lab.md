# Full-VM Lab: Graphical Guests and Campaign 001 Rerun

Status: FULL-VM PREFLIGHT evidence only. The virtual machines below validated the
unchanged-artifact pipeline, the Wayland-session prerequisite, and the transition
from preflight rejection to a genuine L0.0 containment failure. They are never
physical Gate L0 evidence (see [GATE-L0.md](GATE-L0.md)); physical cells still
require label-routed NVIDIA+Wayland hosts.

Raw machine-readable evidence lives beside this document in
[`full-vm-lab-evidence/`](full-vm-lab-evidence/). The authoritative state record
is [`full-vm-lab-evidence/STATE.md`](full-vm-lab-evidence/STATE.md).

## 1. Objective

Recreate the NixOS 26.05 and Ubuntu 26.04 full VMs as graphical desktop guests —
QEMU/KVM + libvirt, Q35, OVMF, CPU host-passthrough, VirtIO disk/network and a
VirtIO virtual GPU with SPICE — with an actual logged-in GNOME Wayland session.
The VMs are operated entirely over SSH but must not be guest-headless. Then,
before Campaign 001, prove through `loginctl` that the lab user holds an active
Wayland session and that its `WAYLAND_DISPLAY` socket actually exists, execute
the exact unchanged Campaign 001 specimen from that graphical session
environment, preserve all evidence, and distinguish preflight rejection from an
actual L0.0 namespace failure. Stop without repair immediately if namespace
construction or L0.1 child launch fails.

## 2. Host lab environment

| | |
|---|---|
| OS | Fedora Kinoite 44 (44.20260801.0), kernel `7.1.5-201.fc44.x86_64` |
| CPU | AMD Ryzen 5 7600X (AMD-V), KVM acceleration |
| Virtualization | libvirt 12.0.0, QEMU 10.2.2, virt-install 5.1.0, OVMF edk2 (SELinux enforcing) |
| RAM | 14 GiB total — 8 GiB guests must run sequentially |
| Networking | libvirt `default` network 192.168.122.0/24, VirtIO vhost |
| Control plane | `virsh`/`virt-install` against `qemu:///system` only; no containers |
| SSH identity | `neuestar-lab/ssh/lab_ed25519` (ed25519), user `lab` in every guest |

## 3. Official media (verified)

Phase 2 guests were built from the official graphical desktop media. Phase 1
guests were built from official minimal/cloud media and remain relevant as the
preflight-rejection baseline.

| ISO | SHA-256 (verified on disk) |
|---|---|
| `nixos-minimal-26.05.7675.02e08985a27c-x86_64-linux.iso` (Phase 1) | `3fedd433b4b3af2ca2cf3913365a3a84a2a1364ad94496053a93eac20634a3c0` |
| `ubuntu-26.04-server-cloudimg-amd64.img` (Phase 1) | `9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05` |
| `nixos-graphical-26.05.7675.02e08985a27c-x86_64-linux.iso` (Phase 2) | `5c8d3ecef4cea793460c0a47c03c1db63b1e526beed8d4331bd57d459f26846f` |
| `ubuntu-26.04-desktop-amd64.iso` (Phase 2) | `487f87faaf547ea30e0aba4d5b53346292571256b25333a978db1692bcee9dd2` |

## 4. Phase 1 baseline — headless guests, preflight rejection

Two full VMs (`ubuntu-2604-lab`, `nixos-2605-lab`) from the minimal/cloud media,
headless (no display device), pristine external-QCOW2 overlays captured after
install+SSH verification, then the unchanged artifact executed once per guest as
ordinary user `lab` with declared cell `--distro … --gpu nvidia --display wayland`.

Both runs were clean **preflight rejections**:

- failure stage `preflight`, code `preflight-failed`, observed display `tty`,
  `PROBE_EXIT` 65, `L0.0= fail (preflight)`, `L0.1..L0.5 = not-run`.
- The launcher's declared-host guard worked as designed: a display-less host can
  never satisfy the wayland/x11 display vocabulary, so namespace construction was
  never attempted.
- A separate earlier staging run (extra unmanifested files in the extraction
  directory) failed at artifact verification (exit 65) before any gate; it is
  preserved as an honest record, not a gate result.

Evidence: `ubuntu-preflight-clean-report.json`, `nixos-preflight-clean-report.json`,
`ubuntu-run1-report-preserved.txt`, run logs, and the full state record.

## 5. Phase 2 — graphical guest recreation

The Phase 1 overlays were discarded as experiment evidence and two new guests
were created with a VirtIO virtual GPU (virtio-vga), SPICE virtual display, and a
logged-in GNOME Wayland session:

### 5.1 ubuntu-2604-wayland-preflight (192.168.122.102)

- Installed from the official **Ubuntu 26.04 Desktop ISO** via the GNOME/subiquity
  installer driven by an autoinstall seed (`ubuntu-desktop-seed.iso`): UEFI/OVMF
  guided layout on `/dev/vda` — `vda1` 1 GiB vfat ESP, `vda2` 2 GiB ext4 `/boot`,
  `vda3` LVM root (`ubuntu-vg/ubuntu-lv`, 19 GiB).
- autoinstall identity: hostname `ubuntu-2604-wayland-preflight`, user `lab`
  (sudo, lab-recorded password `gfqVrcpZ3PEadY`), `ssh.install-server: true` with
  the lab ed25519 key, package `gdm3`.
- Post-install lab provisioning (ordinary lab access only): `lab` added as GDM
  `AutomaticLogin` (`/etc/gdm3/custom.conf`) so the guest boots to a real logged-in
  desktop; everything else is stock Ubuntu 26.04 LTS.
- Final state: Ubuntu 26.04 LTS, kernel `7.0.0-29-generic`,
  `systemd-detect-virt` = `kvm`, virtio-gpu active (`/dev/dri/card1` +
  `renderD128`), `gnome-shell --mode=ubuntu` running.
- Final disk-only run config: `ubuntu-2604-wayland-run.xml` (ISOs detached; boot
  from vda only).

**Installer incident (recorded as evidence, no guest consequence):** the
transitional install domain kept the desktop/seed ISOs attached for reboot, and
the installer's restart path produced a repeatable loop — subiquity's shutdown
hung on `Job session-1.scope/stop` (90 s force-stop), the forced stop became a
warm reboot back into the live ISO, and `autoinstall` re-ran over the completed
install. This was resolved by ejecting the ISO media from the running domain
(`virsh change-media … --eject --live --config`) and redefining a disk-only
domain, after which the installed system booted normally. The result was several
deliberate, identical autoinstall runs; the final installed system is complete
and unmodified. `ubuntu-wayland-install-domain.xml` preserves the transitional
(ISO-attached) configuration.

### 5.2 nixos-2605-wayland-preflight (192.168.122.211)

- Installed from the official **NixOS 26.05 graphical ISO** with the GNOME
  profile; GRUB EFI installed as removable (`/boot/EFI/BOOT/BOOTX64.EFI` verified),
  booting under OVMF from disk.
- User `lab` (wheel), sshd password-auth disabled, lab key authorized; GDM
  auto-login for `lab` configured during provisioning.
- Final state: NixOS 26.05, kernel `6.18.44`, `systemd-detect-virt` = `kvm`,
  `gnome-shell` 50.4 `--mode=user` running.
- Final disk-only run config: `nixos-2605-wayland-final.xml`.

### 5.3 Guest hardware (both)

Q35 machine, OVMF pflash, CPU host-passthrough, 4 vCPU, 8 GiB RAM, VirtIO disk +
VirtIO net (DHCP), **VirtIO virtual GPU** (`virtio-vga`), SPICE display on
127.0.0.1 (5900/5901), serial TCP (2301/2302) for installer/console access, no
S3/S4. Provisioning stayed within ordinary lab access: nothing Neuestar-specific
was installed in either guest — no bundlewrap, nix-ld, AppArmor/sysctl changes,
compat packages, ELF patching, or special library paths.

## 6. Pre-Campaign proof: real Wayland session (both guests)

Captured fresh over SSH immediately before each campaign run
(`ubuntu-wayland-session.txt`, `nixos-graphical-session.txt`):

```
session 1: lab, seat0, tty2, Type=wayland, Class=user, State=active, Remote=no
socket:   /run/user/1000/wayland-0  EXISTS (lab-owned Unix socket)
compositor: gnome-shell running (--mode=ubuntu / --mode=user)
```

The graphical **session environment** (obtained via the session's own systemd
user manager) contains exactly the launcher's display vocabulary:

```
WAYLAND_DISPLAY=wayland-0
DISPLAY=:0
XDG_SESSION_TYPE=wayland
XDG_RUNTIME_DIR=/run/user/1000
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
XDG_SESSION_EXTRA_DEVICE_ACCESS=render:accel   (Ubuntu guest)
```

These are the values Campaign 001 was executed with.

## 7. Campaign 001 — unchanged specimen, from the graphical session environment

### 7.1 Artifact identity (unchanged, re-verified per guest)

- Source of truth: GitHub Actions run 31951274008 (`canonical-artifact`
  id 9264713287), commit `689760e3a1b6d4d1edde37f44f685d878a2158bd`, success.
- Outer archive SHA-256 `02a4b6d3b04b37e8c8284bee15746b8365d7cdb4561b7eab405ba381886a68e7`
  — matches the published check on the host and was re-verified on each guest
  before extraction; payload manifest `e0c2c60f81aaacdd53f79ede30ed52dfabda3e92c244b69f4bd5d66b8d8c9cc3`;
  `capture_rule_sha256` `6f71fc1be6700a767903a4509cbdcd5e7a8eee297e31e3df7ea390938edfc355`.
- `scripts/verify-artifact.sh` passed in Phase 1 (payload manifest, embedded
  artifact identity, controlled libc/interpreter, capture-rule hash byte-match at
  HEAD).
- Launcher invocation (identical to the README contract):

  ```sh
  ./neuestar-probe \
    --archive-sha256 02a4b6d3b04b37e8c8284bee15746b8365d7cdb4561b7eab405ba381886a68e7 \
    --distro ubuntu --gpu nvidia --display wayland \
    --report report.json
  ```

  run with the Section 6 session environment exported, as ordinary user `lab`.

### 7.2 Ubuntu 26.04 guest (graphical) — observed

- `observed_host.display_server` = `wayland`; `current_desktop` = `ubuntu:GNOME`;
  `desktop_session` = `ubuntu`. **Preflight passed.**
- Failure: `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`,
  `PROBE_EXIT` **71**.
- `gates.l0_0_containment` = `fail`, `l0_1..l0_5` = `not-run`; classification
  `fail`; failure stage `containment`, code `containment-failed`,
  "bubblewrap or child exited with status 1"; no namespace constructed, no host
  paths captured, no host glibc import, exactly 1 predeclared vendor rule
  (`nvidia-device-nodes`).
- Guest namespace policy at run time: `kernel.apparmor_restrict_unprivileged_userns`
  = `1` — Ubuntu 26.04 restricts unprivileged user-namespace creation for
  unprofiled processes, exactly the policy documented in
  [RESEARCH.md](RESEARCH.md). The denial is reported, not bypassed.

### 7.3 NixOS 26.05 guest (graphical) — observed

- `observed_host.display_server` = `wayland`; `current_desktop` = `GNOME`;
  `desktop_session` = `gnome`. **Preflight passed.**
- Failure: `bwrap: Can't create file at /app/probe: Read-only file system`,
  `PROBE_EXIT` **71**.
- Same gate shape as Ubuntu: `l0_0_containment` = `fail`, `l0_1..l0_5` =
  `not-run`, stage `containment`, no namespace constructed, no host paths
  captured, no host glibc import.
- Unlike Ubuntu, NixOS did not deny unprivileged user namespaces; bubblewrap
  advanced into mount/root construction and stopped at a filesystem-write step of
  its controlled root. This is a **different L0.0 sub-failure** from the Ubuntu
  policy denial, not a preflight rejection.

### 7.4 Summary

| Guest | observed display | failure (launcher stderr) | exit | failure stage | L0.0 | L0.1..5 |
|---|---|---|---|---|---|---|
| ubuntu-2604-wayland-preflight | `wayland` | `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` | 71 | containment | fail | not-run |
| nixos-2605-wayland-preflight | `wayland` | `bwrap: Can't create file at /app/probe: Read-only file system` | 71 | containment | fail | not-run |

## 8. Preflight rejection vs actual L0.0 namespace failure

The experiment now distinguishes the two outcomes operationally and by exit code:

| | Phase 1 (headless guests) | Phase 2 (graphical guests) |
|---|---|---|
| failure stage | `preflight` | `containment` |
| failure code | `preflight-failed` | `containment-failed` |
| observed display | `tty` | `wayland` |
| PROBE_EXIT | 65 | 71 |
| namespace construction attempted | no | yes (then failed) |
| report message | "declared matrix cell does not match the observed host: expected display wayland, observed tty" | "bubblewrap or child exited with status 1" |

- **Preflight rejection** means the launcher's declared-host guard stopped the
  run before any containment work: nothing constructed, artifacts untouched.
- **Actual L0.0 namespace failure** means the run passed preflight against a
  real observed Wayland session and bubblewrap failed during namespace/root
  construction.
- Two distinct genuine L0.0 modes were observed in phase 2: (1) Ubuntu-style
  AppArmor-mediated unprivileged-userns denial (`RTM_NEWADDR: EPERM`), and
  (2) a NixOS run where unprivileged userns was permitted but bubblewrap could
  not create a file in its own controlled root (`/app/probe: Read-only file
  system`). Both are reported verbatim; neither was engineered around.

Consistent with [KILL-CONDITIONS.md](KILL-CONDITIONS.md) and
[GATE-L0.md](GATE-L0.md), refusal by host policy is a recorded L0.0 result, never
a reason to change sysctls, install profiles, or use sudo:
- no `sudo` was used in either guest for the runs (the run user was ordinary
  `lab` in each case);
- no AppArmor/sysctl/userns change, no setuid installation, no distro compat
  packages, no manually installed bubblewrap, no driver preparation;
- no Neuestar source or rule change, and no rebuild: the exact canonical archive
  was re-executed in each phase.

## 9. Protocol compliance and evidence

Per protocol, both experiments **stopped immediately on L0.0 failure** (neither
reached L0.1), guests were **inspected, never repaired**, and both were powered
off as-is after their run (Ubuntu via `poweroff`, NixOS via ACPI). The graphical
installs were left untouched. Every report, run log, pre-run state file, session
proof, and domain config cited here is preserved under
[`full-vm-lab-evidence/`](full-vm-lab-evidence/), and the full working state
record is `full-vm-lab-evidence/STATE.md`.

Repository impact of this document: docs only. No Rust source, schema, rootfs,
build script, or workflow changed; the canonical artifact identity is untouched.

## 10. Implications for the physical plan

What the VMs established:

1. The unchanged-artifact pipeline and the launcher's declared-host guard behave
   as designed across two fresh graphical full-VM environments (exit 65
   preflight-only prefix; exit 71 containment failures after a real Wayland
   observation).
2. The matrix's Wayland cell vocabulary matches a real GNOME Wayland session
   (loginctl `Type=wayland` + live socket + session env); the "guest-headless"
   defeat that produced phase-1 rejections is now characterized and closed at the
   VM level.
3. First in-VM observations of genuine L0.0 namespace failures inside full VMs,
   in two distinct modes (Ubuntu userns policy denial; NixOS bubblewrap
   controlled-root write failure).

What the VMs cannot establish: physical Gate L0 evidence. Namespace/ABI/driver/
display behavior on physical NVIDIA hosts is not modeled by virtio-gpu guests.
Nothing in this document changes the gate contract: L0.0–L0.5 remain unproven on
physical hardware, and the closure of the physical matrix (Fedora, Ubuntu LTS,
Arch, NixOS × Intel/AMD/NVIDIA × Wayland/X11) with the canonical unchanged
archive remains the campaign's next falsifier (see [CI-LAB.md](CI-LAB.md),
[GATE-L0.md](GATE-L0.md), [STATUS.md](STATUS.md)).

Open item for the physical plan: the NixOS `.Read-only file system` failure
inside this VM is a bubblewrap/controlled-root construction issue that should be
re-derived from the Phase 1 report-level diagnostics on a physical NixOS cell
rather than investigated through VM-only instrumentation — it is not a reason to
relax any kill condition.