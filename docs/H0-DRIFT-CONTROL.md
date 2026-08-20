# H0 DRIFT CONTROL — NixOS 26.05, fresh overlay (2026-08-17)

Status: **H0 PREFLIGHT** in a QEMU/KVM + libvirt VM, **fresh overlay**
(`nixos-2605-drift`, external overlay over the pristine base; verified clean
before the run). This is the frozen-order drift control after A2a
acceptance: re-run of the zero-integration H0.P on a fresh NixOS base with
the **exact frozen Campaign 002 artifact** and the new outer↔payload binding.

## Purpose

Confirm that the zero-preparation substrate result reproduces on a fresh
NixOS base with the mechanically-bound artifact — i.e., the apparatus has not
drifted and NixOS's native user/mount-namespace availability is unchanged.

## Run

| | value |
|---|---|
| distro / kernel | NixOS 26.05, kernel 6.18.44 (same release as the original H0.P run) |
| candidate | none (zero-preparation) |
| outer archive | `a5773bc2…` (sha verified on guest, `manifest.txt`) |
| payload / source / probe | `b6f12734…` / `06adad5e…` / 0.2.0 |
| binding | outer↔payload binding verified (tarball sha + embedded artifact.json/SHA256SUMS byte-equal), else apparatus failure |
| result | **h0_0 = pass**, classification pass |
| child | contained=true, launch_reached_main=true, user `[4026532382]`, mount `[4026532381]` (fresh, differ from parent) |
| h0-check | **PASS (0 violations)** (`neuestar.h0/v2`) |

## Interpretation

- The zero-preparation minimum user+mount operation still succeeds on fresh
  NixOS (no integration needed), exactly as in the original H0.P — **no
  drift** in the substrate result or the apparatus.
- The exact C002 payload identity is now mechanically bound into the record
  (the drift run exercises the new binding path for candidate none as well).

Evidence: [`docs/h0-drift-evidence/`](h0-drift-evidence/) (record,
manifest). Remaining frozen-order items, in order: Fedora 44 → Arch official
`linux` → Ubuntu 24.04 current-updates → generation/application independence
→ cross-release burden → H0.5 churn.
