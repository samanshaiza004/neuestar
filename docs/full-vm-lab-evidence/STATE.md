# Neuestar FULL-VM preflight lab — state record

Date (local): 2026-08-16
Host: Fedora Kinoite 44 (44.20260801.0), kernel 7.1.5-201.fc44.x86_64, AMD Ryzen 5 7600X (AMD-V)
libvirt 12.0.0 / QEMU 10.2.2 / virt-install 5.1.0 / OVMF edk2-20260508 (enforcing SELinux)
Control plane: virsh/virt-install against qemu:///system only. No Docker/Podman/Vagrant/VirtualBox/nested containers.

## Scope per request
- Two persistent headless x86_64 full-VM environments: NixOS 26.05 (official minimal installer ISO) and Ubuntu 26.04 LTS (official QCOW cloud image, local cloud-init datasource).
- KVM acceleration, CPU host-passthrough, Q35, UEFI/OVMF, VirtIO disk+network, 4 vCPUs, 8 GiB RAM, 40 GiB persistent QCOW2 per guest.
- Provisioning limited to lab operation: ordinary non-root user, SSH access, basic networking. Nothing Neuestar-specific installed (no bubblewrap, nix-ld, AppArmor/sysctl/user-ns changes, compat packages, ELF patches, special library paths).
- Pristine snapshot (external QCOW2 overlay) taken for each guest after base OS install + SSH verification, before any Neuestar run.
- All results to be treated as FULL-VM PREFLIGHT only.

## Provisioning
Storage pool: `neuestar-lab` (dir, /var/lib/libvirt/images, autostart).
SSH identity: /var/home/samanshaiza/neuestar-lab/ssh/lab_ed25519 (ed25519) — used by both guests.

### Official media (verified)
- NixOS minimal ISO: nixos-minimal-26.05.7675.02e08985a27c-x86_64-linux.iso
  SHA-256 3fedd433b4b3af2ca2cf3913365a3a84a2a1364ad94496053a93eac20634a3c0 (official channels.nixos.org/nixos-26.05)
- Ubuntu cloud image: ubuntu-26.04-server-cloudimg-amd64.img (official cloud-images.ubuntu.com release SHA256SUMS)
  SHA-256 9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05

## Guest 1 — ubuntu-2604-lab (192.168.122.115)
- Base: official 26.04 LTS cloud image copied to 40 GiB QCOW2 (ubunt-26.04.qcow2), UEFI/OVMF, Q35, host-passthrough, 4 vCPU, 8 GiB, VirtIO net (DHCP), VirtIO disk; NoCloud seed ISO (ubuntu-seed.iso) with metadata/network-config and user `lab` (locked password, SSH key only).
- Install/status: cloud-init DataSourceNoCloud done; user lab; sshd; DHCP via enp1s0.
- State evidence: evidence/ubuntu-base/ (libvirt-domain.xml, dominfo, blocks, interfaces, snapshot.xml/info, base-volume-info, dhcp-leases).
- Base state (evidence/ubuntu-base-state.txt): Ubuntu 26.04 LTS (resolute), kernel 7.0.0-28-generic, systemd-detect-virt kvm, id lab uid=1000.
- Snapshot: `ubuntu-2604-pristine` external disk-only -> /var/lib/libvirt/images/ubuntu-2604-pristine.qcow2 (current). Base disk ubuntu-26.04.qcow2 preserved.
- Domain currently points at the pristine overlay; shut off.

## Guest 2 — nixos-2605-lab (192.168.122.200)
- Installer: official NixOS 26.05 minimal ISO booted headless via the ISO's own kernel/initrd (7.1.8 pair) with console=ttyS0 (GRUB-menu-less bootstrap; documented in libvirt XML history). Installer ran over serial; SSH key injected; unattended install via SSH.
- Install: GPT on /dev/vda; vda1 ESP vfat 512M (mounted /boot), vda2 ext4 (mounted /); nixos-generate-config; minimal configuration.nix; `nixos-install --no-root-passwd`.
- Final config (configuration.nix in evidence) uses GRUB EFI with efiInstallAsRemovable -> boots under OVMF from ESP /boot/EFI/BOOT/BOOTX64.EFI (verified present).
- Final domain: UEFI/OVMF, Q35, host-passthrough, 4 vCPU, 8 GiB, VirtIO net (DHCP), VirtIO disk, serial tcp 127.0.0.1:2300 (console.socat), boot dev hd; ISO detached.
- Base state (evidence/nixos-base-state.txt): NixOS 26.05 (Yarara), kernel 6.18.44, systemd-detect-virt kvm, user lab uid=1000 (wheel), sshd active PasswordAuthentication no, serial-getty@ttyS0 active, no swap, profile system-1-link.
- State evidence: evidence/nixos-base/ (libvirt-domain.xml, dominfo, blocks, interfaces, snapshot.xml/info, volumes, dhcp-leases).
- Snapshot: `nixos-2605-pristine` external disk-only -> /var/lib/libvirt/images/nixos-2605-pristine.qcow2 (current). Base disk nixos-26.05.qcow2 preserved.
- Domain currently points at the pristine overlay; shut off.

## Neuestar Campaign 001 — FULL-VM PREFLIGHT executed

### Artifact (unchanged, verified)
- Source of truth: GitHub Actions run 31951274008 (canonical-artifact id 9264713287), commit 689760e3a1b6d4d1edde37f44f685d878a2158bd, conclusion success.
- neuestar-probe-x86_64.tar.zst outer SHA-256 02a4b6d3b04b37e8c8284bee15746b8365d7cdb4561b7eab405ba381886a68e7 (matches published).
- scripts/verify-artifact.sh passed: payload manifest OK, embedded artifact.json identity consistent, controlled libc/interpreter present, capture_rule_sha256 6f71fc1b... matches repo rootfs/capture-rules.json at HEAD.

### Runs (one per VM, as ordinary user `lab`, declared adversarial cell nvidia+wayland)
Both runs: the unchanged binary executed, verified archive+payload, then its declared-host preflight REJECTED the cell because the observed display session is `tty` (headless VM; launcher's display vocabulary is wayland/x11 only, so a headless VM can never match a declared display cell). Result: schema-valid failure report, PROBE_EXIT=65, L0.0=fail (preflight), L0.1/L0.2/L0.3/L0.4/L0.5=not-run, classification=fail, no namespace constructed, no host paths captured, exactly 1 predeclared vendor rule (nvidia-device-nodes), no glibc import. Per protocol: experiment stopped immediately on L0.0 failure; no guest repair; guests left at their (now-dirty) pristine overlays as evidence.

- ubuntu-2604-lab (Ubuntu 26.04, kernel 7.0.0-28-generic, apparmor_restrict_unprivileged_userns=1): evidence/ubuntu-preflight-clean-report.json + run log. An earlier staging run (extra files in extraction dir) failed at artifact verification (exit 65) before any gate attempt; its report and the run logs are preserved (evidence/ubuntu-run1-report-preserved.txt, ubuntu-preflight-run*.log) and are NOT gate results.
- nixos-2605-lab (NixOS 26.05, kernel 6.18.44): evidence/nixos-preflight-clean-report.json + run log.

### Interpretation
- All results are FULL-VM PREFLIGHT only and are NEVER physical Gate L0 evidence.
- Preflight findings for the physical plan: (1) the preflight guard works as designed — a display-less host cannot be declared as a Wayland/X11 cell; (2) physical cells require a real session/display; (3) namespace/launch internals (L0.0/L0.1) were not exercised because the guard stops first, which is the campaign's documented behavior for a mismatched declaration.
- Provisioning restriction honored: nothing Neuestar-specific was installed in either guest.

## Open items
- Host account supplementary group `libvirt` still empty in this session (getent shows no member); current shell works via cached polkit session. Re-run `sudo usermod -aG libvirt samanshaiza` and start a fresh login/Herdr session before the experiment phase if access is lost.
- Campaign 001 artifact: operator must supply the canonical archive + SHA-256 (e.g., `gh auth login` then download run 31951274008 artifact `canonical-artifact`), then verify with scripts/verify-artifact.sh.
- Next step when artifact available: start each VM from its pristine overlay, run the archive as user `lab`, preserve report.json/logs, stop experiment on L0.0/L0.1 failure without repairing the guest; treat all output as FULL-VM PREFLIGHT, never physical Gate L0 evidence.
---

# Phase 2 — Graphical guest recreation + Campaign 001 (Wayland-session rerun) — 2026-08-16 (continued)

## Graphical guests (recreated, operator-headless / NOT guest-headless)
Two NEW full-VM guests `ubuntu-2604-wayland-preflight` and `nixos-2605-wayland-preflight` (per operator directive: discard overlays, rebuild from official graphical media):

| | ubuntu-2604-wayland-preflight | nixos-2605-wayland-preflight |
|---|---|---|
| media | official ubuntu-26.04-desktop-amd64.iso (verified SHA256SUMS) | official nixos-graphical-26.05-x86_64-linux.iso (verified sha256) |
| install | subiquity autoinstall (seed ISO; UEFI; ESP vda1 1G, boot vda2 2G, LVM root vda3) | GNOME profile; GRUB EFI removable |
| guest HW | Q35 + OVMF + host-passthrough, 4 vCPU, 8 GiB, VirtIO disk+net, **VirtIO virtual GPU (virtio-vga)** + SPICE (127.0.0.1:5901), serial tcp 2301 | same, SPICE 5900, serial 2302 |
| OS | Ubuntu 26.04 LTS, kernel 7.0.0-29-generic, systemd-detect-virt kvm, /dev/dri card1+renderD128 (virtio-gpu) | NixOS 26.05, kernel 6.18.44, kvm, gnome-shell 50.4 |
| user | lab (sudo, password gfqVrcpZ3PEadY, ssh key) | lab (wheel) |
| display manager | gdm3, **AutomaticLoginEnable + AutomaticLogin=lab** (custom.conf) | GDM autologin (configured during iso install phase) |

Post-install final run configs are disk-only (ISOs detached after install; no cdrom in final XML): `ubuntu-wayland-campaign/ubuntu-2604-wayland-run.xml`, `nixos-wayland-campaign/nixos-2605-wayland-final.xml`. The transitional install domains (ISOs attached) are preserved (`ubuntu-wayland-campaign/ubuntu-wayland-install-domain.xml`, earlier uefi2/3/pty/direct XMLs).

NB: the Ubuntu desktop autoinstall went through several installer runs because the iso-attached transitional domain rebooted back into the live installer (subiquity shutdown hang on session-1.scope/stop, 90s forced stop, warm reboot → autoinstall rerun). Resolved by ejecting ISO media (`change-media --eject --live --config`) then redefining disk-only. No effect on the final installed system; deliberate re-install runs treated as installer evidence.

## Pre-Campaign proof per operator checklist (both guests, fresh capture)
`ubuntu-wayland-session.txt`, `nixos-graphical-session.txt`:

- Session 1: lab, seat0, tty2, **Type=wayland, Class=user, State=active**, Remote=no
- `/run/user/1000/wayland-0` socket EXISTS (owned lab)
- gnome-shell running (`--mode=ubuntu` / `--mode=user`)
- graphical session env (via `systemctl --user show-environment`): WAYLAND_DISPLAY=wayland-0, DISPLAY=:0, XDG_SESSION_TYPE=wayland, DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus

## Campaign 001 (unchanged specimen, run FROM the graphical session env)
Same canonical artifact (outer sha256 02a4b6d3…a68e7; re-verified on each guest; payload manifest SHA256SUMS OK). Launcher invoked with the graphical session environment exported from the live wayland session, declared cell `--distro <os> --gpu nvidia --display wayland`:

| | ubuntu-2604-wayland-preflight | nixos-2605-wayland-preflight |
|---|---|---|
| observed display | **wayland** | **wayland** |
| current desktop | ubuntu:GNOME (session ubuntu) | GNOME (session gnome) |
| observed failure | `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` | `bwrap: Can't create file at /app/probe: Read-only file system` |
| PROBE_EXIT | 71 | 71 |
| failure stage | containment (not preflight) | containment (not preflight) |
| gates | l0_0=fail; l0_1..l0_5=not-run | l0_0=fail; l0_1..l0_5=not-run |
| namespace constructed | false | false |

### Preflight rejection vs actual L0.0 namespace failure — distinguished
- **Phase 1 (headless VMs)**: failure stage `preflight`, code `preflight-failed`, observed display `tty`, exit **65** — nothing ran.
- **Phase 2 (graphical VMs)**: preflight PASSES (observed display `wayland` from the real graphical session), then L0.0 containment fails at namespace construction — exit **71**, stage `containment`, code `containment-failed`.

Two distinct genuine L0.0 failure modes observed:
1. Ubuntu 26.04: kernel `apparmor_restrict_unprivileged_userns=1` → unprivileged userns creation denied → bwrap's netns RTM_NEWADDR EPERM.
2. NixOS 26.05: unprivileged userns permitted (no sysctl restriction) → bwrap started constructing but failed creating `/app/probe` on its read-only rootfs (a mount/bind setup failure) — a DIFFERENT L0.0 sub-failure, not a deny.

## Protocol
Per KILL-CONDITIONS: stopped both experiments immediately on L0.0 failure; **no guest repair performed**; both guests powered off as-is (ubuntu via `poweroff`, nixos via ACPI) leaving the graphical installs untouched; all reports/logs/prerun-state/domain XMLs preserved under `ubuntu-wayland-campaign/` and `nixos-wayland-campaign/`.

## Open items
- Physical-host implications unchanged: genuine L0.0/L0.1 probing requires physical NVIDIA+Wayland cell; VMs validated the preflight->containment transition and produced the first in-VM L0.0 namespace-failure observations (Ubuntu userns-deny, NixOS bwrap-rootfs) — FULL-VM PREFLIGHT evidence only, never physical Gate L0 evidence.
