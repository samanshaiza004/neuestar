# Campaign 001 Verdict — apparatus failure, specimen superseded

Date: 2026-08-16. Applies to the canonical Campaign 001 artifact: source commit
`689760e3a1b6d4d1edde37f44f685d878a2158bd`, outer archive SHA-256
`02a4b6d3b04b37e8c8284bee15746b8365d7cdb4561b7eab405ba381886a68e7`, payload
manifest `e0c2c60f81aaacdd53f79ede30ed52dfabda3e92c244b69f4bd5d66b8d8c9cc3`,
probe `0.1.0`.

## Verdict

Campaign 001 successfully validated artifact identity, cross-distro execution
through launcher preflight, real Wayland-session observation, failure reporting,
and experimental provenance. The full-VM run then **falsified Campaign 001 as a
suitable L0.0/L0.1 specimen before physical testing**: it tests more than its
frozen hypothesis and contains a deterministic setup defect.

Two probe-design issues were discovered. **Neither currently falsifies the Linux
Substrate hypothesis.** Both justify a new immutable Campaign 002 specimen.
Campaign 001 remains permanently preserved as evidence and must never be
retroactively reclassified. It is not to be run on physical machines.

Lab method, raw evidence, and the full-VM run: [docs/full-vm-lab.md](full-vm-lab.md)
and [docs/full-vm-lab-evidence/](full-vm-lab-evidence/).

## Defect 1 — Ubuntu 26.04: namespace isolation over-scoped beyond L0

`crates/neuestar-probe-launcher/src/main.rs` asks bubblewrap for
`--unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net`.

Gate L0 (docs/GATE-L0.md, L0.0) requires evidence only that the **user and mount
namespaces** differ from the launcher's pre-containment identities. PID, IPC,
UTS, and network isolation are not Gate L0 requirements; containment at L0 is
ABI/environment control, not a security sandbox.

Observed on Ubuntu 26.04 (graphical guest, `apparmor_restrict_unprivileged_userns=1`):

```
bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
```

bubblewrap's `--unshare-net` constructs an isolated network namespace with a
loopback interface; the failure occurred during that loopback configuration.
This is consistent with Ubuntu's AppArmor-mediated user-namespace/capability
restrictions, but it does **not** establish that the user+mount namespace
boundary required by L0 is impossible.

Attribution: specimen over-scope interacting with host security policy. Not a
platform-compatibility falsifier at the L0 boundary.

## Defect 2 — NixOS 26.05: bind destination missing inside the read-only root

The launcher's mount plan is:

```text
--ro-bind <artifact>/root /
--dev /dev  --proc /proc  --tmpfs /tmp
--ro-bind <artifact>/app/probe /app/probe
--bind <report_parent> /evidence
```

`scripts/build-rootfs.sh` constructs `root/app/` but never places a `probe`
entry inside it (the probe binary lives at `app/probe` in the outer staging
tree, not in `root/app/probe`). bubblewrap creates destination paths for setup
operations when they do not exist; after the controlled root is mounted
read-only at `/`, creating `/app/probe` fails.

Observed on NixOS 26.05 (graphical guest, unprivileged userns permitted):

```
bwrap: Can't create file at /app/probe: Read-only file system
```

The identical bind shape reproduces on the host:

```
bwrap: Can't mkdir parents for /app/probe: Read-only file system
```

Attribution: deterministic Campaign 001 mount-plan defect. Not evidence about
NixOS compatibility, and not worth a bare-metal NixOS run to reproduce. No
dummy file should be added to satisfy bubblewrap; the mount plan itself is
fixed (below).

## Why neither defect falsifies the hypothesis

- The Ubuntu result concerns isolation the frozen L0 contract does not ask for.
  Whether the minimum user+mount boundary works under stock Ubuntu policy is
  unresolved — precisely what Campaign 002 must measure.
- The NixOS result is a self-inflicted root-construction error with a
  mechanical fix, independent of the distribution.
- The experiment apparatus was shown to test more than its frozen hypothesis
  and to contain a deterministic setup defect — the legitimate reason to start
  a new campaign.

## Campaign 002 charter (minimum user+mount containment)

Make exactly the changes necessary to restore alignment between the probe and
the frozen gate. Do not move into Vulkan yet.

Containment plan:

```text
bwrap
├── new mount namespace       ← inherent/required
├── --unshare-user            ← required by L0
│
├── --ro-bind root /
├── --ro-bind app /app        ← destination /app already exists in the root
├── --bind evidence /evidence
├── --dev /dev
├── --proc /proc
├── --tmpfs /tmp
└── /app/probe
```

Removed unless one is demonstrated required by the compatibility experiment:
`--unshare-net`, `--unshare-pid`, `--unshare-ipc`, `--unshare-uts`.

Application mount: `--ro-bind <artifact>/app /app` replaces
`--ro-bind <artifact>/app/probe /app/probe` — `root/app` is already constructed
by the builder, eliminating the missing-file mountpoint without adding a dummy.

Failure diagnostics (report schema): `neuestar.report/v1` remains the frozen
Campaign 001 schema (`schema/report-v1.schema.json`); Campaign 002 emits
`neuestar.report/v2` (`schema/report.schema.json`), which adds
`containment.substage` enumerated `helper-preflight | helper-execution |
child-result-missing | child-launch` — derived only from launcher-controlled
evidence (helper start, exit status, child-result presence), never from
helper-stderr string matching — and a bounded `containment.process_stderr`
(UTF-8-lossy prefix, ≤ 4096 chars). V1 reports carrying the diagnostics fields
are rejected. The Campaign 001 schema collapses every containment failure to
`stage: containment / code: containment-failed / "bubblewrap or child exited
with status 1"`, which forced correlating `report.json` with external logs; a
later investigator should not have to do that.

Execution flow:

```text
Campaign 001 (frozen, this verdict)
    ↓
Campaign 002 — new source commit, new artifact, new hashes
    ↓
same pristine base disks (untouched by Campaign 001) → NEW external overlays
    ↓
FULL-VM PREFLIGHT — exactly these two VMs first
    ↓
only after L0.0/L0.1 pass in both VMs → physical NixOS/Ubuntu cells
```

The Campaign 001 VMs are not repaired or rerun with a changed probe; their state
stands as evidence. The Ubuntu and NixOS base disks
(`ubuntu-2604-wayland.qcow2`, `nixos-2605-wayland.qcow2`) were not modified by
the campaign run and remain pristine bases for Campaign 002 overlays.

If Campaign 002 passes L0.0/L0.1 in both VMs, physical NixOS/Ubuntu execution is
worth pursuing. If Ubuntu still fails with only the minimum required user+mount
namespace model, that is the much more serious Ubuntu compatibility result the
campaign is designed to hunt for.