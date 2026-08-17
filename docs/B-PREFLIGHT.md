# B PREFLIGHT — Candidate B falsifier on Ubuntu 26.04 (2026-08-17)

Status: **focused adversarial falsifier** per review direction (the cheapest
test of the hostile-loader class against the distro substrate), not the full
frozen B campaign — no probe candidate-B records were produced; the B
apparatus is not built. Execution in the same QEMU/KVM + libvirt VM as A1.

## What was tested

Ubuntu 26.04 ships its own bwrap substrate:

| | value |
|---|---|
| distro helper | `/usr/bin/bwrap` 0.11.1-1ubuntu0.1, uid 0, mode 0755, 80,424 bytes, SHA-256 `0abea81db798ebf6b4742ac0664802d97521547a353c2a0dbdc21d76cbbfd2c0` |
| distro policy | `/etc/apparmor.d/bwrap-userns-restrict` (upstream bwrap-userns-restrict), SHA-256 `d61facde27707b9c47ffe47921b7273e788784484cb5530eb819e6daac1f1990`, loaded enforce |
| userns restriction | `kernel.apparmor_restrict_unprivileged_userns = 1` |
| hostile specimen | same `hostile.so` constructor as the A1 suite (SHA `8d44b220…`) |

## Results

### B functional (H0.1-class): PASS

The minimum user+mount containment through `/usr/bin/bwrap` succeeded:
`contained=true`, `launch_reached_main=true`, child in fresh user
`[4026532502]` and mount `[4026532501]` namespaces. The distro substrate
constructs the boundary on stock Ubuntu.

### B hostile loader: FAIL — same bypass class as A1

```text
hostile_preload: unshare=1 uid_map=1 mount=0 pivot=0
```

`LD_PRELOAD=hostile.so /usr/bin/bwrap …` — the user-controlled constructor
ran inside the distro `bwrap-userns-restrict` profile before bwrap's own
logic and created a nested user namespace with a successfully written
`uid_map`. Exactly the frozen H0.1S failure class. (The subsequent bwrap
invocation fails its own namespace creation; that is irrelevant to the
contract violation.)

### Attribution control: PASS (the restriction still works)

The same exact bytes copied to a user path and executed **unconfined**:

```text
hostile_preload: unshare=1 uid_map=0 mount=0 pivot=0
```

`unshare` succeeds but the `uid_map` write is denied — the
`apparmor_restrict_unprivileged_userns` restriction mediates the map write
for unconfined code. Only the profiled paths — Neuestar's `neuestar-bwrap`
(A1) **and Ubuntu's own `bwrap-userns-restrict` (B)** — grant the hostile
constructor uid-map authority. The bypass is not caused by Neuestar's policy
details; it is inherent to the upstream design.

## Why the distro policy has the same hole

`bwrap-userns-restrict` grants the bwrap process broad authority
(`allow capability`, `allow userns`, `allow mount`, `allow umount`,
`allow pivot_root`, `allow file rwlkm /{**,}`, …) and transitions children
with **lower-case** `pix`:

```text
allow pix /** -> &bwrap//&unpriv_bwrap,
```

Lower-case `pix` does not secure-exec the environment, so caller-controlled
`LD_PRELOAD`/`LD_LIBRARY_PATH` influence reaches the loaded helper. The
profile's own comment acknowledges this trade-off ("Ideally we would
sanitize the environment across a privilege boundary… flatpak etc use
environment glibc sanitized environment variables as part of the sandbox
setup"). Since `/usr/bin/bwrap` is dynamically linked, the dynamic loader
runs arbitrary user code **after** AppArmor has granted the profile's
authority and **before** any child stack-down.

## Gate table

| gate | verdict |
|---|---|
| H0.P | PASS |
| A1/H0.1 | PASS |
| A1/H0.1S | FAIL → **A1 REJECTED** |
| B functional (H0.1-class) | PASS on Ubuntu 26.04 |
| B hostile loader | FAIL → **B REJECTED on Ubuntu 26.04** |
| Installed Substrate overall | **unresolved** |

## Consequence

- Distro-provided execution substrate does **not** avoid the class: Ubuntu's
  own shipped policy is vulnerable to the identical attack. The trade-off B
  was designed to expose is answered on this base: distro-provided bwrap is
  not a security differentiator.
- The failure class now has a precise diagnosis: **no user-controlled
  executable code may run while the helper profile still owns setup
  authority.** That is a property of the helper process itself (dynamic
  loader + broad profile + lowercase transition), not of the policy file.
- A2's prerequisite is met (A1 demonstrably failed), and the A2 design must
  ensure the helper cannot execute user-controlled code before setup — e.g.,
  a static helper (no dynamic loader), or an equivalent non-injectable
  property. No A2 design has been started.

Evidence: [`docs/b-preflight-evidence/`](b-preflight-evidence/) (child
result, hostile result, stderr captures, manifest).
