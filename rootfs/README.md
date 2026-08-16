# Controlled root

`scripts/build-rootfs.sh` constructs the Phase 1 root from the exact ELF
dependency closure of the trusted glibc-linked child. It preserves absolute
interpreter/library paths inside `root/` and separately captures the bundled
bubblewrap helper closure under `libexec/` for pre-namespace execution.

The root intentionally does not contain or bind the host's complete `/usr`,
`/lib`, `/lib64`, `/etc`, or home. Graphics/display paths are absent until Gate
L0.0 succeeds. The generated root manifest is evidence and an input to the
artifact identity.

`capture-rules.json` is also hashed into artifact metadata. It predeclares the
generic future discovery categories and the sole permitted vendor rule,
`nvidia-device-nodes`; Phase 1 records that identity but performs no GPU
capture.
