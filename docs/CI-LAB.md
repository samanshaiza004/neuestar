# CI and Physical Lab

## Hosted CI

Hosted runners format, lint, test, validate schemas, inspect ELF metadata,
exercise deterministic root construction, build the canonical artifact, hash
it, and publish it. A hosted Ubuntu VM is not matrix evidence.

The canonical workflow records source commit, exact toolchains, architecture,
runtime-root manifest identity, payload identity, outer archive checksum, and
build time derived from the source commit. The archive is uploaded once for a
campaign. A failed physical cell does not authorize a rebuild.

## Physical runs

Physical self-hosted runners use cumulative labels:

`self-hosted`, `linux`, `x64`, one `distro-*`, one `gpu-*`, and one
`display-*`. Each manually dispatched cell downloads the canonical archive,
checks the caller-supplied archive SHA-256, executes it without rebuilding, and
uploads `report.json`, logs, capture plan, loader diagnostics, host metadata,
and both hashes even after failure.

The matrix workflow is deliberately a manual scaffold until machines actually
exist. Containers on hosted Ubuntu cannot stand in for target host namespace,
ABI, driver, or display policy.

## Churn

Churn is two manual runs, `baseline` and `post-driver-change`, on the same
physical machine. Between them an operator changes the driver only through the
distribution's normal supported mechanism. CI never upgrades drivers. The
comparison requires identical outer archive and capture-rule hashes, changed
driver identity, and no Neuestar changes. Captured concrete files may differ.

## Aggregation

Aggregation rejects missing or invalid reports, mixed archive/payload hashes,
duplicate cell identities, vendor-rule count above one, any distro rule, and a
clean classification with host glibc imported. Unrun cells remain `not-run`;
they are never inferred successful.

