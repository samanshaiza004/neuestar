# A2 adversarial acceptance suite (precommitted)

Derived directly from the frozen H0.1S contract and from the observed A1/B
failure class (hostile loader executed after setup authority was granted,
before the intended child stack-down). This suite is the acceptance gate for
any A2 design on a mandatory target (Ubuntu 26.04). It is precommitted: A2a
is not accepted on the basis of functional launch, only on the basis of these
negatives.

Failing condition in all cases: **any user-controlled code acquires
namespace-setup authority** — concretely, a successful `uid_map` write from
code the ordinary user controls. `unshare=1 uid_map=0` (the unconfined
restriction behavior) is the SAFE outcome. `unshare=1 uid_map=1` is FAIL.

## 1. Entry injection (environment)

Execute the privileged entry path with each hostile loader/env variable set
by the ordinary user; the constructor must never run under setup authority:

- `LD_PRELOAD`
- `LD_LIBRARY_PATH`
- `LD_AUDIT`
- `GLIBC_TUNABLES`
- `GCONV_PATH`

Acceptance: the hostile constructor either does not run, or runs with
`uid_map=0`. Any `uid_map=1` is FAIL.

## 2. Direct-path bypass

- `exec /usr/libexec/neuestar/bwrap-real` directly (the private setup
  binary, outside the entry).
- Copy the entry helper to a user path and execute it.
- Copy `bwrap-real` to a user path and execute it (with hostile env).

Acceptance: all three fail to acquire uid-map authority (restriction
applies; the profile is not path-granted to any user-reachable location).

## 3. Argument abuse

Attempt to make the entry stage:

- execute a different helper than the fixed `bwrap-real`;
- execute a user-writable program before the child stack-down;
- bypass the child profile transition;
- perform an unsupported mount/namespace operation.

Acceptance: entry rejects unknown operations (fixed operation vocabulary:
outcome run / security-evidence run only, fixed mount set); any deviation is
a hard error with no namespace authority acquired.

## 4. FD inheritance

Invoke the entry with hostile inherited file descriptors (including
memfds / eventfds / pipes) open. Acceptance: the setup process closes all
inherited FDs > 2 before constructing the namespace; no inherited FD can
influence privileged execution.

## 5. Child authority (contained hostile child)

Through the trusted entry path, run user-controlled child code and actively
attempt nested userns + uid_map + mount + pivot_root inside the boundary:

- child `CapEff` raw == 0, decoded set empty;
- nested `uid_map` denied;
- `mount` denied;
- `pivot_root` denied;
- child profile label is the restricted stack
  (`neuestar-bwrap-real//&neuestar-unpriv (enforce)` class), not unconfined.

## 6. Static-property evidence (mechanical)

- `PT_INTERP` absent from the entry helper ELF (readelf-verified and
  probe-verified), and no dynamic dependencies;
- recorded in the H0 record (`trusted_helper.elf_interpreter == null`).

## 7. Mechanized record invariants

The H0 record must carry (schema `neuestar.h0/v2`):

- `trusted_helper`: uid 0, regular file, group/world-write clear, parent not
  user-writable, `elf_interpreter` null, SHA pinned;
- `apparatus.security_evidence_argv` frozen (the invocation responsible for
  the H0.1S evidence);
- carried component (bwrap-real) SHA pinned, `neuestar_specific_patches == 0`,
  `carried_components <= 1`;
- `h0-check` PASS means evidence admissibility only; the suite above is the
  verdict.

## Stop conditions

- Any `uid_map=1` from user-controlled code under a privileged path: the A2
  design fails H0.1S; record and stop (no repair-in-place).
- If A2 requires > 2,000 first-party helper LOC, setuid, file capabilities,
  a daemon, policy special-case growth, private patches, or significant
  distro branching: stop Installed Substrate; move to the predeclared
  Vertical Native architecture.
