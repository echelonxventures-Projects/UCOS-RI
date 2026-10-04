# ADR 0004: ucos-context-runtime in Go and TypeScript, differentially tested

- Status: accepted (2026-10-05)
- Traces: CIC-011-001, CR-011-001-01..04, CR-030-001-05, CIC-001-001 §1.1 rule 4, AR-0002

## Context
Every context resolves facts with CIC-011-001, so the context runtime is the most widely embedded platform
library. CR-011-001-01 demands byte-identical results across all certified implementations, in any language.
CR-030-001-05 demands a second-language implementation in S1.

## Decision
- The runtime is specified once, language-neutrally, in `contracts/context-runtime/semantics.md`. It is
  exercised only through a JSON Lines **runner protocol**.
- There are two independent implementations:
  - `platform/context-runtime/go`, used by Go modules;
  - `platform/context-runtime/typescript`, on Node 24 native type stripping, with zero dependencies and no build step.
- `./ucos ctx-conformance [N]` runs three things against every runner:
  - hand-derived golden vectors, plus the CR-011-001-03 fallback-order suite derived from the `ucos.std` dimensions;
  - an N-case seeded differential with metamorphic twins (CR-011-001-01/02);
  - the 1,000-candidate benchmark (CR-011-001-04).
- A third, independent context-digest computation in the suite (Python) cross-checks both implementations.
- The suite was mutation-tested: three injected single-line bugs (tie order, depth factor, drop order) were
  each caught by both the golden vectors and the differential.

## Consequences
- Adding a runtime in another language means writing a runner and listing it with `conformanceRunner: true`.
- The second implementation now covers conformance for a platform library. The "swapped into `ucos-lite`" part of
  CR-030-001-05 applies to a service module, so it completes when the S1 metadata service has a second implementation.
