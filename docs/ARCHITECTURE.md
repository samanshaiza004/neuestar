# Architecture

Status: Gate L0 experiment; no stable application or scene ABI exists.

## Thesis under test

The Linux Substrate hypothesis is that an immutable Neuestar-controlled
userspace can execute the same trusted native AOT application generation on
otherwise incompatible Linux distributions while consuming the host's actual
accelerated Vulkan driver. Gate L0 is designed to reject that hypothesis
cheaply if namespace policy, ELF/glibc collision, driver capture, or operational
maintenance makes it untenable.

## Current boundary

The only product is one Linux x86_64 probe artifact. It contains a static musl
launcher, a pinned bubblewrap helper when the canonical builder can produce it,
a glibc-linked child, a controlled root, and evidence metadata. The launcher
constructs a mount/user namespace; it does not expose the host `/usr`, `/lib`,
`/lib64`, `/etc`, or home directory wholesale. Refusal by host policy is a
recorded L0.0 result, never a reason to change sysctls, install profiles, or use
sudo.

Runtime files may eventually be content-addressed and shared on disk, but
runtime state is per application. Immutable runtime generations must remain
live while referenced by an installed application's exact generation pin or by
an active process lease. This invariant is documented only; no store exists.

An eventual runtime would normally be one process per application, not a
machine-global daemon. Arbitrary application native code never executes inside
the renderer process. Process topology remains experimental and is not an ABI.

## Protocol constraints reserved for later

Trusted applications are native AOT. Future protocols must be pointer-free,
bounded, explicitly owned, serializable, and expressed in resource/capability
identifiers so a future untrusted Wasm extension could participate. Gate L0
implements no Wasm, scene graph, widgets, text, input protocol, or IPC profile.

If a later per-application runtime is built, latency-sensitive input and scene
commits use one-way shared rings; synchronous request/response RPC is reserved
for coarse control operations. Gate L1 must measure OS-event-to-app, wake,
commit-to-present, percentiles, CPU overhead, and idle behavior before this
becomes architecture.

Typography is not promised deterministic. Future deterministic layout tests
must use explicit test-owned fonts rather than platform font metrics.

## Phase 0/1 choices

1. Rust crates stay narrow: reporting, host inspection, launcher, child, and a
   future ELF module. Vulkan and window-system code do not exist yet.
2. The distribution object is a normalized `tar.zst`. `artifact.json` embeds a
   payload-manifest identity; the outer archive checksum is published beside
   the archive and supplied to every run. An archive cannot embed its own hash
   without a circular definition, so both hashes are verified and reported.
3. The canonical build pins source and Rust, records the exact bubblewrap bytes
   and controlled-root manifest, and normalizes timestamps, ownership, modes,
   path ordering, and archive compression. The first campaign prioritizes one
   immutable, auditable build; independent bit-for-bit reconstruction of the
   distribution-provided helper remains an explicit unresolved reproducibility
   risk rather than a hidden claim.
4. The launcher invokes an artifact-bundled bubblewrap and its dependency
   closure. Before execution it clears the outer loader environment, disables
   `ld.so.cache`, asks the bundled loader to list eager dependency resolution,
   and rejects every resolved path outside `libexec`. It does not accept a host
   `bwrap` or helper-library fallback. If bundling is not viable, L0.0 is
   unresolved/failing rather than silently host-dependent.
5. Physical matrix workflows are manual and label-routed. They download and
   verify one canonical archive and always upload evidence; they never build.

Alternatives rejected for falsifiability: `$ORIGIN`/`LD_LIBRARY_PATH`-only
packaging, host filesystem passthrough, Flatpak/Steam/AppImage runtimes,
per-distro builds, automatic driver upgrades, software-renderer acceptance, and
containerized fake matrix cells.
