# Ubuntu 24.04 current-updates — H0.0 baseline (2026-08-18)

Full-VM H0 PREFLIGHT. Fresh base (official noble server cloud image), brought
to **current-updates** (`apt update && apt full-upgrade`, kernel
`6.8.0-138-generic`, apparmor 4.0.1really4.0.1-0ubuntu0.24.04.7). Pristine
external snapshot `ubuntu-2404-current-updates` before any Neuestar run. lab
is key-only (new rotated credential `7oRxBvGNswQfGitMrGig` retired after the
Arch VM; key-based SSH, no password auth) with NOPASSWD sudo.

Run: H0 probe (candidate none, zero-preparation), exact frozen Campaign 002
artifact (outer a5773bc2… / payload b6f12734…, binding verified on guest).

## Result: h0_0 = FAIL

| | value |
|---|---|
| candidate | none (zero-preparation) |
| host | Ubuntu 24.04.4 LTS, kernel 6.8.0-138-generic |
| `apparmor_restrict_unprivileged_userns` | **1** (recorded in record) |
| helper_started / child_reached | true / **false** |
| failure | `bwrap: setting up uid map: Permission denied` |
| h0-check | **PASS (0 violations)** — the FAIL is schema-valid and correctly classified |
| identity | outer a5773bc2… / b6f12734… (binding verified) |

## Interpretation

Ubuntu 24.04 current-updates exhibits the **identical** zero-preparation
UID-map boundary failure as Ubuntu 26.04. The AppArmor unprivileged-userns
restriction is **on by default across the 24.04 → 26.04 family**, so the
Ubuntu/AppArmor integration burden is a single-family property, not
release-specific: both generations default to restricting unprivileged
user-namespace creation and both need the Neuestar integration (A2a) for the
minimum user+mount operation.

This answers the cross-family question on the negative side of the
zero-preparation baseline. The separate cross-release burden (whether the A2a
policy — `abi <abi/5.0>`, built for AppArmor 5.0 on 26.04 — loads unchanged on
24.04's AppArmor 4.0.1) is the H0.4R/H0.5 maintenance question and has not
been run here (that is an A2a-integration test, out of scope for this
zero-preparation baseline).

## Standing zero-preparation picture

```
NixOS 26.05   H0.0 PASS   (native)
Fedora 44     H0.0 PASS   (native)
Arch linux    H0.0 PASS   (native)
Ubuntu 26.04  H0.0 FAIL   (restriction ON)
Ubuntu 24.04  H0.0 FAIL   (restriction ON) — same family
```

Evidence: [`docs/ubuntu-2404-h0-baseline/`](ubuntu-2404-h0-baseline/)
(record, manifest).
