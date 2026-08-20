# Neuestar / Instar Research Closure

**Date:** 2026-08-20  
**Status:** Frozen, concluded research; no product commitment

## Decision

The Neuestar/Instar research phase is over for now. The repository remains as
an auditable record of the experiments, implementation checks, hypotheses,
security work, and negative results. It is not being advanced into a general
desktop framework, deployment platform, or compatibility substrate.

This is not a claim that desktop infrastructure has no gaps. The durable
conclusion is narrower:

> **Desktop infrastructure is not solved. We simply have not yet found pain
> severe and repeated enough to justify another compatibility platform.**

The old test, “valuable + non-composable,” was too absolute. The better test is:

> **valuable + not cheaply, reliably, and repeatedly composable at the scale of
> the intended users.**

Integration can be valuable. A central primitive earns its compatibility cost
when multiple real consumers repeatedly need it and composition is no longer
cheap, reliable, or maintainable—not when an architecture diagram makes the
integration look elegant.

## What the experiments established

### Instar

Instar demonstrated that a Wasm Component boundary can support meaningful
desktop machinery: typed capabilities, asynchronous execution, retained UI,
resource generations, input, text, rendering, and teardown.

It also demonstrated the cost of putting trusted, latency-sensitive,
first-party application code behind that boundary: serialization, ABI and WIT
versioning, resource identity, generation teardown, scheduling, hostcall
admission, copying, text/IME ownership, resynchronization, and more difficult
performance attribution.

The surviving rule is not “Wasm was a mistake.” It is:

> **Use Wasm where distrust, portability, or crash/resource containment is
> real. Do not make trusted applications pay an isolation boundary merely
> because portability is attractive.**

The likely shape is a native application with a Wasm extension boundary, not a
whole trusted application implemented as a guest.

### Neuestar

Neuestar moved the question down a layer: could an immutable native Linux
artifact carry a controlled userspace while consuming the host's real GPU and
window-system stack?

The research showed that the hard part is not only libc. Portability reaches
through:

```text
application/runtime
        ↓
controlled userspace and loader
        ↓
kernel security policy
        ↓
distribution integration
        ↓
host GPU userspace and driver ABI
```

Ubuntu's user-namespace/AppArmor policy made OS cooperation a real boundary.
The A2a design—a small static entry, sanitized transition, pinned upstream
Bubblewrap, and adversarial loader/FD/ptrace checks—became a technically
interesting security result. It was not evidence that every desktop
application should traverse that boundary.

The controlled-glibc/host-GPU interaction remains unresolved. It is a useful
research question, but it no longer justifies keeping a platform effort alive.

### The broader platform proposals

The review also removed several tempting product wedges:

- A generic native “Tauri without a WebView” layer has no one-sentence
  differentiator yet; existing crates and service/plugin ecosystems cover much
  of the proposed composition.
- A cross-platform deployment framework overlaps heavily with Velopack and
  native OS machinery. Safe rollback becomes application-semantic as soon as
  migrations or user data are involved.
- A content-addressed shared runtime store imports machine-global lifecycle,
  leases, garbage collection, and recovery concerns. Flatpak, OSTree, and
  Nix-style systems are strong prior art.
- A UI adapter spanning GPUI, Qt, Xilem, or future toolkits would recreate the
  expensive UI intermediate representation that Instar already made visible.
  If GPUI is chosen, use GPUI directly.
- An extension ABI should come from actual extension requests, not from the
  assumption that a framework ought to have plugins.

These are not universal claims that the underlying ideas are worthless. A2a,
reproducible release verification, a Wasm extension host, and a focused updater
or GPUI contribution may each be useful in isolation. They are simply not a
reason to maintain Neuestar as a general platform today.

## What this repository contains—and does not prove

The repository contains a careful Phase 0/1 apparatus: a Rust workspace,
canonical artifact scripts, a static launcher, controlled-root manifests,
report schema and aggregation, and hosted/manual workflow definitions. Local
formatting, linting, tests, schema checks, shell checks, workflow checks, and
preflight smoke tests pass.

The development host is macOS arm64. No canonical Linux x86_64 artifact was
physically built and exercised here. The physical matrix, driver churn, and
later graphics gates were not run. Therefore:

- L0.0 and L0.1 are implemented in the apparatus, not physically proven.
- L0.2 and L0.3 were not implemented.
- No overall Gate L0 pass is claimed.
- The absence of physical evidence is an explicit boundary, not an invitation
  to quietly upgrade implementation checks into platform proof.

Completing the Fedora/Arch/NixOS/Ubuntu matrix or long churn campaign merely
to make the research package prettier would risk turning the falsification
apparatus into the deliverable. The premise that made that work product-critical
has changed, so the experiment is allowed to stop.

## Operating rule going forward

The next work is application-first:

```text
Punks + Scratchpad
        ↓
direct native stack
        ↓
record friction literally
        ↓
solve locally first
        ↓
second app hits same problem?
        ↓
extract a small primitive
        ↓
outside users hit same problem?
        ↓
stabilize it
        ↓
only much later: framework/platform?
```

The strongest rule to carry forward is:

> **Never freeze a compatibility surface ahead of evidence from multiple real
> consumers.**

Applications can have value with one user. Frameworks need leverage across
developers. Two demanding native applications and outside users are stronger
evidence than another month of architecture search.

## Disposition of the work

- **Instar:** concluded research; preserve the Wasm-boundary lessons and
  potentially salvage extension-host or sandbox work later.
- **Neuestar:** frozen systems research; do not treat the current crates and
  manifests as a product SDK or roadmap.
- **A2a:** preserve as a possible narrowly scoped security contribution,
  write-up, or upstream technique; no application-framework critical path.
- **Controlled glibc/GPU test:** optional future research if curiosity or a real
  distribution requirement makes it worthwhile.
- **Punks and Scratchpad:** serious engineering priority; ordinary native
  applications first, using existing toolkit, OS, packaging, and update
  machinery.

The result is a map of where novelty was not justified. That is a successful
research outcome: it prevents attractive boundaries from becoming permanent
compatibility obligations before applications prove they create more value
than cost.
