# Gate L0

Gate L0 asks whether Neuestar can maintain a small controlled Linux userspace
that consumes host GPU userspace drivers without inheriting a Flatpak- or
Steam-Runtime-sized maintenance obligation.

## Fixed campaign rules

One campaign uses one unchanged Linux x86_64 archive. Every runner verifies its
expected outer archive SHA-256 before extraction and the embedded canonical
payload manifest after extraction. Mixed hashes invalidate aggregation.

Machines are inspected, never repaired. No sudo, sysctl/AppArmor changes,
setuid installation, distro compatibility packages, nix-ld, manually installed
bubblewrap, driver symlinks, per-host ELF patching, or Neuestar-specific driver
preparation is permitted.

Generic driver discovery may use ICD manifests, `VK_DRIVER_FILES`, ELF
`DT_NEEDED`, `DT_RPATH`/`DT_RUNPATH`, and optionally `ld.so.cache`. Correctness
must not depend on the cache. There are no distro/vendor/version path tables.
Exactly one vendor-specific rule is predeclared: `nvidia-device-nodes`, limited
to exposing already-existing NVIDIA device nodes. The hard cap is one.

## Gates

- L0.0 containment: an ordinary extracted download constructs the required
  controlled namespace without forbidden preparation.
- L0.1 launch: the native child reaches its entry point without ELF interpreter
  or unresolved-symbol failure.
- L0.2 acceleration: the selected Vulkan device is real hardware. llvmpipe,
  lavapipe, and other software rasterizers are failures.
- L0.3 present: exactly 300 frames, no validation error/device loss, complete
  elapsed and median/p95/p99/max timing, and no obviously pathological behavior.
- L0.4 churn: the same archive hash runs before and after a normal supported
  graphics-driver change on at least one Intel, AMD, and NVIDIA machine.
- L0.5 maintenance: capture-rule hash and source remain unchanged across churn;
  only generically discovered concrete files may change.

The eventual matrix is Fedora, Ubuntu LTS, Arch, and NixOS crossed with Intel,
AMD, and NVIDIA and Wayland/X11 (24 cells). Adversarial order starts with NixOS
NVIDIA Wayland/X11 and Ubuntu NVIDIA Wayland/X11. No cell may be omitted and
every attempt should emit a report.

## glibc classification

- `clean-pass`: controlled Neuestar libc remains authoritative.
- `conditional-pass`: all functional gates pass only with host glibc or an
  equivalent host C-runtime closure assimilated.
- `fail`: workload failure or any hard kill condition.

Host-libc assimilation can never be a clean pass and triggers a separate
architecture review rather than permission to build UI architecture.

## Exit contract

Success requires a schema-valid report. A missing/malformed report is failure.
Containment or launch failures use distinct nonzero exit codes and still write
the most complete report technically possible. Physical evidence, not hosted
CI, decides the gates.

