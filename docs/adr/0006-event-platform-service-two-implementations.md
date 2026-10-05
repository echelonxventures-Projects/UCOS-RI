# ADR 0006: event-platform-service in Go and TypeScript, swappable in ucos-lite

- Status: accepted (2026-10-05)
- Traces: CR-030-001-05, DOM-EVT, CIC-006-001, ADR 0001, AR-0003

## Context
CR-030-001-05 needs at least one S1 module whose second implementation, in a different language, passes the
identical conformance and scenario suites and is swapped into `ucos-lite` with no change to any other module.
S1a gave the context runtime two implementations, but it is a library rather than a deployable.

## Decision
- The DOM-EVT event registry is a separate deployable, `event-platform-service`. It has two independent
  implementations of one contract (`contracts/eventing-registry/semantics.md`) and one SQL schema
  (`services/eventing/migrations`):
  - `services/eventing/go`: Go, pgx;
  - `services/eventing/typescript`: Node 24 type stripping, `pg` as the only dependency, lockfile committed.
- `compose.yaml` builds `eventing` from `services/eventing/${UCOS_EVENTING_IMPL}`. Nothing else references the
  implementation.
- `./ucos conformance` runs the **complete** black-box suite (S0 + S1 + S1c) once per implementation. Each run uses
  a fresh stack, and the suite asserts that the served implementation (`UCOS-Implementation` header) is the
  selected one.
- Compatibility semantics are specified independently of both codebases, with golden vectors. The suite is
  mutation-tested: an injected bug in either rule family fails it.

## Consequences
- Either implementation can serve production traffic. Choosing one is an operational decision, not an architectural one.
- Contract changes must land in both implementations in the same change. CI enforces this by running both.
