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
