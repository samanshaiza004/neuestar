# Fedora 44 Workstation x86_64 — H0.0 baseline (2026-08-17)

Full-VM H0 PREFLIGHT. Fresh base install (unattended kickstart, Workstation
product: fedora-release-workstation-44-17, gnome-shell 50, kernel
6.19.10-300.fc44.x86_64), SELinux enforcing, no unprivileged-userns
restriction, lab user with sudo, SSH verified, pristine external snapshot
`fedora-44-pristine` taken before any Neuestar run.

Run: H0 probe (candidate none, zero-preparation), exact frozen Campaign 002
artifact (outer a5773bc2… / payload b6f12734…, binding verified on guest).

Result: **h0_0 = pass**, classification pass; child contained in fresh user
[4026532523] / mount [4026532522] namespaces; h0-check **PASS (0
violations)** (neuestar.h0/v2).

Interpretation: the zero-preparation minimum user+mount operation succeeds on
stock Fedora 44 Workstation — no integration needed on this substrate (like
NixOS; unlike Ubuntu 26.04, which fails at the UID-map boundary).
