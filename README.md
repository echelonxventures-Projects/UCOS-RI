# UCOS-RI: Reference Implementation

This is the executable reference implementation of the UCOS-COM corpus. The corpus is vendored at
`corpus/` and pinned in `corpus.lock` (CIC-030-001).

The RI is **contract-first, polyglot, and container-only** (AMD-0001, CIC-001-001 §1.1):
- **Contract-first:** contracts and black-box conformance suites are the normative executable artifacts.
- **Polyglot:** each module picks its language.
- **Container-only:** the only host prerequisite is an OCI runtime with the Compose spec (Docker, Podman or nerdctl).

## Quick start

```sh
./ucos verify        # corpus lock + corpus validation + contract drift + contract lint + module manifests
./ucos test          # every module's unit + architecture tests (in its build container)
./ucos conformance   # start ucos-lite and run the black-box conformance suites
./ucos ctx-conformance [N]   # context-runtime suites across every runtime implementation (default N = 20000)
./ucos ci            # all of the above, then tear down
```

`./ucos up` starts the lite profile. Then `echo-service` answers on `http://127.0.0.1:18080`:

```sh
curl -s -X POST localhost:18080/v1/echo/messages -H 'UCOS-Tenant: acme' -H 'Idempotency-Key: demo-0001' \
     -H 'Content-Type: application/json' -d '{"text":"hello"}'
```

## Layout

```
ucos                    POSIX sh entry point (drives the OCI runtime only)
corpus/  corpus.lock    vendored UCOS-COM corpus at cic-1.1.0 (content-hash verified)
contracts/              language-neutral contracts
  kernel/               shared JSON Schemas: Urn, Ulid, Money, Decimal, Quantity, Interval, LocalizedText,
                        ProblemDetails, CloudEvent envelope, CommandResult, Page; tenancy rules
  <context>/DOM-*.yaml  OpenAPI 3.1 + AsyncAPI 3.0 generated from every specified DOM spec (do not edit)
  echo/                 hand-authored S0 echo contracts
  persistence/          standard tables + tenancy contract (CIC-003-001 §4–5)
  context-runtime/      executable semantics of CIC-011-001 + runner protocol (semantics.md)
conformance/            black-box suites (HTTP, CloudEvents, SQL only; never import implementation code)
  context-resolution/   golden vectors + fixture hierarchies for the context runtime
platform/context-runtime/{go,typescript}   two independent ucos-context-runtime implementations
kernel/                 S1 metadata-service (Go): ontology, lifecycle, contextreg, policy, governance, evidence,
                        registry contexts + governed ports + platform; one schema per context
domains/echo/           S0 echo context (Go): api / domain / application / infrastructure / service / cmd
deploy/lite/            ucos-lite database roles
tools/                  containerized toolchain: contract generator + linter, migrator, corpus lock, manifest checks
docs/adr/               architecture decisions; docs/amendment-requests.md — deviations raised to the corpus
compose.yaml            ucos-lite composition
```

## Status: slice S0 (Platform)

S0 exit demonstration (CIC-030-001 §3): **echo context with event round-trip, plus RLS isolation test green.**

| Area | State |
|------|-------|
| Contract toolchain | 99 DOM specs → 198 generated contracts (OpenAPI 3.1 + AsyncAPI 3.0), linted against the `ucos-api-rules` subset, VR-006-001-01/02 and CR-006-001-02 |
| Eventing | Transactional outbox, relay (`FOR UPDATE SKIP LOCKED`, ordered, at-least-once), idempotent consumer (`processed_messages`), event replay API |
| Persistence | Standard tables per context schema, forced RLS on every tenant table, least-privilege roles, checksum-verified migrator |
| API | `UCOS-Tenant`, `Idempotency-Key` (24 h replay, mismatch → 422), ETag, `UCOS-Correlation-Id`, RFC 9457 problems |
| Conformance | 13 black-box tests: round-trip, idempotency, redelivery, problems, API tenant hiding, RLS catalog/data/write/fail-closed/grants, standard tables |
| Interim adapters | Dev-header security, HTTP bus, static tenant directory (ADR 0003). Each is replaced behind its port in a later slice |

## Status: slice S1 (metadata kernel), in progress

| Batch | State |
|-------|-------|
| S1a context runtime | Done. CIC-011-001 is specified as executable semantics (AR-0002 lists the 13 clarifications). There are two implementations, Go and TypeScript. Results: 328/328 golden and fallback-order vectors, a byte-identical 10⁶-case differential, metamorphic twins, and p99 < 0.6 ms with 1,000 candidates (limit 2 ms). The suite catches injected bugs. |
| S1b metadata service | Done. `kernel/` composes ONT, LFC, CTX, POL (PDP with cel-go), GOV, EVD and META (ADR 0005). **`ucos.std` installs through one governed ChangeSet:** 519 items, risk `critical`, a 2-stage plan from the pack's own policies, SoD and AAL2 approvals with evidence in an RFC 6962 ledger, 24 h cool-off, and a compensating apply saga. 16 black-box tests cover it, and effective schemas are checked against the corpus's own pack checker. |
| S1c | Next: the EVT registry (event-type schemas, CR-006-001-04 compatibility), LFC instance runtime, and the second-language swap of an S1 module into `ucos-lite` (CR-030-001-05) |

Remaining for S1 (metadata kernel: ONT, CTX, POL, LFC, EVT registry, EVD, GOV ChangeSets). Its exit criteria are
that `ucos.std` installs via ChangeSet and the context-resolution conformance suite is green.
