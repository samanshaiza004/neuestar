# Campaign 002 — Frozen Specimen

Freeze date: 2026-08-16. This specimen supersedes Campaign 001 per
[`docs/CAMPAIGN-001-VERDICT.md`](CAMPAIGN-001-VERDICT.md): it carries the
minimum user+mount containment contract and the hardened evidence instrument.
Campaign 001 remains frozen and is not retroactively reclassified.

## Canonical identity (recorded once, never rebuilt)

| Identity | Value |
|---|---|
| Source commit (main) | `06adad5e83f1e31000bdbb44c693a3ece3dc5a6f` |
| Hosted build run | GitHub Actions `build-probe.yml` run `31979454518` (ref `main`) |
| Outer archive SHA-256 | `a5773bc2b1cec810a6767aa2eb561791f3ab6c312b90afa4dac11e103c9c10fe` |
| Payload manifest SHA-256 | `b6f127341d019da391e6cc60cc1d432fde12f8e27602a61ff5e288aafedd0f8e` |
| Runtime-root manifest SHA-256 | `08487e1d68fe1980e96edcb280ac52ec99e02f76b88cf1632d28116465929070` |
| Capture-rule SHA-256 | `6f71fc1be6700a767903a4509cbdcd5e7a8eee297e31e3df7ea390938edfc355` |
| Probe version | `0.2.0` |
| Build timestamp | `2026-08-16T23:33:09Z` |
| Architecture | `x86_64` |
| Controlled libc | Ubuntu GLIBC `2.39-0ubuntu8.8` (ld.so 2.39) |
| Bundled bubblewrap | 0.9.0, sha `52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712` |

The hosted workflow rebuilt the archive twice and byte-compared the outputs;
the recorded outer SHA-256 matches the published `.sha256` sidecar. The
runtime-root and capture-rule hashes are unchanged from Campaign 001 (the
controlled root and capture rules did not change).

## Containment contract (verified in the frozen binary)

```text
--die-with-parent --new-session --unshare-user
--ro-bind <artifact>/root /
--dev /dev --proc /proc --tmpfs /tmp
--ro-bind <artifact>/app /app
--bind <evidence> /evidence
… --chdir /app /app/probe --result /evidence/child-result.json
```

No `--unshare-net/--unshare-pid/--unshare-ipc/--unshare-uts`. The app directory
bind replaces the per-file `/app/probe` bind; the destination `root/app` is
builder-constructed. `--proc /proc` bind-mounts the shared host procfs
(bubblewrap reuses `oldroot/proc` when the PID namespace is not unshared), so
no hidden PID-namespace requirement is introduced.

## Evidence contract (report `neuestar.report/v2`)

- `containment.substage` ∈ `helper-preflight | helper-execution |
  child-result-missing | child-launch`, derived only from launcher-controlled
  evidence; never parsed from bubblewrap prose.
- `containment.process_stderr`: bounded UTF-8-lossy prefix (≤ 4096 chars) of
  the helper/child stderr, drained to EOF so capture is observational.
- V1 reports reject the diagnostics fields; `schema/report-v1.schema.json` is
  the frozen Campaign 001 schema.

## Execution procedure (FULL-VM PREFLIGHT)

1. Fresh external QCOW2 overlays over the pristine base disks
   (`ubuntu-2604-wayland.qcow2`, `nixos-2605-wayland.qcow2`).
2. Ordinary lab provisioning on the overlay only: rotate/lock the compromised
   `lab` credential (SSH-key-only access preferred); nothing Neuestar-specific.
3. Verify real logged-in Wayland session per guest (`loginctl` Type=wayland,
   live `wayland-0` socket, session env).
4. Verify the frozen archive SHA-256 on the guest; extract into a fresh
   evidence directory.
5. Run the unchanged specimen from the graphical session environment.
6. Stop immediately on L0.0/L0.1 failure without guest repair; preserve all
   evidence.
7. Ubuntu first, then NixOS, on the identical specimen.

The same artifact is used for both guests; no change between them regardless
of which runs first.

## Execution outcome (FULL-VM PREFLIGHT, 2026-08-16)

Evidence: [`docs/campaign-002-evidence/`](campaign-002-evidence/). Fresh overlays
over the pristine bases; lab credential rotated on the Ubuntu overlay (old
credential invalidated) as ordinary provisioning; SSH-key-only access; fresh
evidence directories; Wayland session verified on both overlays before the
runs. Ubuntu ran first; the specimen was not changed between guests.

| | ubuntu-2604-c2 | nixos-2605-c2 |
|---|---|---|
| observed display | `wayland` (ubuntu:GNOME) | `wayland` (GNOME) |
| PROBE_EXIT | 71 | 0 |
| substage | `helper-execution` | — |
| process_stderr | `bwrap: setting up uid map: Permission denied` | — |
| L0.0 containment | fail | **pass** (user+mount ns differ, controlled root) |
| L0.1 launch | not-run | **pass** (controlled glibc 2.39, no host glibc import) |
| L0.2–L0.5 | not-run | not-run |
| classification | fail (containment) | fail (graphics not implemented) |

- **NixOS 26.05**: the minimum user+mount containment contract succeeds
  zero-preparation as an ordinary user in the full VM — L0.0/L0.1 pass with
  controlled glibc and no host-glibc import. First clean minimum-containment
  milestone.
- **Ubuntu 26.04**: with the network-namespace over-scope removed, the minimum
  contract fails at the user-namespace boundary itself: stock AppArmor
  (`apparmor_restrict_unprivileged_userns=1`) denies the uid-map setup for an
  unprofiled ordinary download. Recorded, not bypassed (KILL-CONDITIONS).
- Both results are FULL-VM PREFLIGHT evidence, never physical Gate L0 evidence.
  Protocol: stopped on L0.0 failure with no guest repair; guests left as-is;
  identical specimen for both guests.

## Post-campaign cleanup list (non-blocking, from review)

- Reject reused output paths before writing any evidence files, or create
  attempt-unique evidence directories automatically (launcher-side hardening;
  the runner temp dir and the VM procedure already mandate fresh evidence
  directories).
- Shellcheck/actionlint are exercised only by hosted CI on this host.
