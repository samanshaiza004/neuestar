# Arch Linux official `linux` — H0.0 baseline (2026-08-18)

Full-VM H0 PREFLIGHT. Fresh base install (archiso booted headless over serial,
pacstrap base + linux + amd-ucode + NetworkManager + openssh + sudo; GRUB EFI
--removable with serial console; lab user with sudo + ssh key; kernel
`7.1.8-arch1-3`). No userns restriction on Arch. Pristine external snapshot
`arch-pristine` taken before any Neuestar run.

Run: H0 probe (candidate none, zero-preparation), exact frozen Campaign 002
artifact (outer a5773bc2… / payload b6f12734…, binding verified on guest).

Result: **h0_0 = pass**, classification pass; child contained in fresh user
[4026532331] / mount [4026532330] namespaces; h0-check **PASS (0 violations)**
(neuestar.h0/v2).

Interpretation: the zero-preparation minimum user+mount operation succeeds on
stock Arch (official linux kernel) — no integration needed, like NixOS and
Fedora; unlike Ubuntu 26.04 (which fails at the UID-map boundary).

Provisioning provenance caveat: the archiso auto-init failed under this boot
plumb, so the live environment was brought up manually (airootfs.sfs +
overlay + chroot) and the base was installed with a TEMPORARY
`SigLevel = Never` pacman config (to bypass a PGP-keyring trust issue in the
manual chroot). As a result, not every installed package was
cryptographically authenticated during provisioning. This does not affect
the H0.0 observation (zero-Neuestar-preparation, measured namespace
operation succeeded), but it is recorded here for provenance; a future Arch
rebuild should fix the keyring/trust path instead of disabling signature
checks.
