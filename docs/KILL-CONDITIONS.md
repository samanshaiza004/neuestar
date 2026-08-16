# Predeclared Kill Conditions

These rules were committed before physical Gate L0 execution. They must not be
relaxed after observing failures.

The Linux Substrate hypothesis is rejected if successful operation requires:

1. Neuestar artifacts built per NVIDIA driver version.
2. Mesa built or maintained per Neuestar runtime branch.
3. Distribution-specific graphics compatibility patches.
4. Maintained host-capture path/rule tables that grow with distro or driver
   churn.
5. More than the one predeclared `nvidia-device-nodes` device-exposure rule.
6. Manual per-machine graphics preparation.
7. Reclassifying or omitting failed cells after results are known.

A new driver that works through the unchanged generic algorithm is evidence for
L0.5 even if its concrete dependency set changes. A new driver that requires a
Neuestar source/rule change and rebuild is L0.5 failure.

On a kill, architecture expansion stops. Work is limited to reproduction,
machine-readable evidence, an explicit verdict, and implications for the
predeclared fallback: Vertical Native—conventional native desktop distribution
plus reusable Neuestar native libraries and an optional Wasm sandbox for future
untrusted plugins.

Ambiguity is interpreted against the Linux Substrate hypothesis.

