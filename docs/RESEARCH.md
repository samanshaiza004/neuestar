# Upstream Research

**Historical record — research frozen 2026-08-20.** These facts supported the
experiment; they are not an active implementation roadmap.

Accessed 2026-08-15. Links are upstream specifications, project source/docs, or
vendor documentation; downstream blogs are not used as implementation truth.

## Containment

- [bubblewrap README](https://github.com/containers/bubblewrap/blob/main/README.md):
  bubblewrap constructs an initially empty mount namespace and exposes only
  caller-selected paths. It relies on unprivileged user namespaces; historical
  setuid mode has been removed. It is a namespace construction tool, not a
  complete security policy. Neuestar therefore bundles/pins the helper and owns
  every mount decision.
- [Canonical on restricted unprivileged user namespaces](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces):
  Ubuntu's AppArmor mediation can deny user namespaces to unprofiled downloaded
  programs. Requiring a shipped system AppArmor profile or policy change is
  non-clean under L0.0, so denial must be reported rather than bypassed.
- [AppArmor `bwrap-userns-restrict` profile](https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor/profiles/extras/bwrap-userns-restrict)
  (verified 2026-08-16): the profile is attached to `profile bwrap
  /usr/bin/bwrap` and explicitly grants `userns`, `mount`, `umount`,
  `pivot_root`, and capabilities, then stacks the `unpriv_bwrap` profile on
  children to deny capabilities inside the namespace. The permission is bound
  to the system-installed executable path, not to an arbitrary downloaded
  bubblewrap.
- [Ubuntu unprivileged userns restriction is enabled by default since
  24.04](https://wiki.ubuntu.com/Security/Features) and the
  `bwrap-userns-restrict` profile ships in Ubuntu's AppArmor packaging since
  25.04 so the distro bubblewrap can run. An artifact-relative bundled
  bubblewrap receives none of that policy; under the frozen zero-preparation
  extracted-artifact contract this is a recorded L0.0 denial, not a policy
  change request (verified against the Campaign 002 full-VM run on Ubuntu
  26.04: `bwrap: setting up uid map: Permission denied`).

## Vulkan and driver boundary

- [Khronos Vulkan Loader driver interface](https://github.com/KhronosGroup/Vulkan-Loader/blob/main/docs/LoaderDriverInterface.md):
  Linux discovery is manifest-based. `VK_DRIVER_FILES` overrides default
  discovery, supersedes deprecated `VK_ICD_FILENAMES`, accepts absolute manifest
  paths, and is ignored for elevated execution. A manifest path alone does not
  guarantee that its shared library closure resolves. Neuestar remains
  unprivileged and records explicit manifests and captured libraries.
- [NVIDIA Linux driver FAQ 580.82.09](https://download.nvidia.com/XFree86/Linux-x86_64/580.82.09/README/faq.html):
  NVIDIA userspace communicates through character device files and may rely on
  distribution setup or `nvidia-modprobe` for creation. Gate L0 only exposes
  already-existing device nodes; it does not load modules, create nodes, or run
  privileged helpers. This is the sole vendor-specific rule.

## ELF, glibc, and NixOS

- [System V ELF gABI dynamic linking](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html):
  `DT_NEEDED` entries name ordered dependencies; `DT_RPATH` is superseded by
  `DT_RUNPATH`; `DT_BIND_NOW` requests eager relocation. Phase 3 must traverse
  the dynamic metadata rather than scrape distro paths.
- [Linux dynamic linker manual](https://man7.org/linux/man-pages/man8/ld.so.8.html):
  slash-containing dependencies are paths; otherwise the resolver considers
  RPATH, `LD_LIBRARY_PATH`, RUNPATH, cache, and defaults in a defined order.
  RUNPATH applies only to direct children. `LD_BIND_NOW` resolves symbols at
  startup and `--inhibit-cache` permits cache-independent diagnostics.
- [glibc `elf/dl-version.c`](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-version.c;hb=HEAD):
  the dynamic loader walks `DT_VERNEED` requirements and the dependency's
  `DT_VERDEF` records, matching both version hash and string and raising a
  version-lookup error for an unavailable non-weak version. A captured driver
  closure can therefore resolve every filename yet still fail against an older
  controlled glibc; L0 diagnostics must preserve that as ABI evidence rather
  than retry with host libc invisibly.
- [Nixpkgs reference manual, fixup phase](https://nixos.org/manual/nixpkgs/stable/#ssec-fixup-phase):
  Nixpkgs post-processes Linux ELF RPATHs with `patchelf`, and runtime inputs live
  in store paths. Generic RPATH/RUNPATH traversal—not `/etc/ld.so.cache`—is a
  design requirement for NixOS.

## CI evidence

- [GitHub self-hosted runners in workflows](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/use-in-a-workflow):
  labels are cumulative; a runner must match all requested labels. This supports
  explicit distro/GPU/display routing, but labels are operator assertions and
  every report must also record observed host metadata.

## Findings deferred to their implementing phase

Before Phase 3/4 code, re-check the loader manifest format/version, glibc symbol
version records, Wayland/X11 WSI requirements, Vulkan validation setup, and the
current NVIDIA node surface. Before physical lab enrollment, re-check each
target's current user-namespace policy and GitHub runner security guidance.
Contradictions update this file and gate status; they do not create exceptions.
