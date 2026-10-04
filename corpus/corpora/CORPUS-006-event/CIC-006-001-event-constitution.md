---
id: CIC-006-001
title: Event Constitution and Event Standards
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-006
dependencies: [CIC-000-002, CIC-003-001]
traces: [PRIN-008, PRIN-015, PRIN-022, DOM-EVT]
certification: [CR-006-001-01, CR-006-001-02, CR-006-001-03, CR-006-001-04]
validation: [VR-006-001-01, VR-006-001-02]
---

# CIC-006-001 — Event Constitution

## 1. Event categories

| Category | Purpose | Topic pattern | Retention |
|----------|---------|---------------|-----------|
| Domain event | Fact about an aggregate state change (published language) | `ucos.<context>.<aggregate>.v<major>` | 30 days log + compacted snapshot topic |
| Integration event | Coarse, cross-context or external notifications derived from domain events | `ucos.integration.<context>.<name>.v<major>` | 7 days |
| Command message | Async command to a specific context (process managers) | `ucos.cmd.<context>.v<major>` | 7 days |
| Telemetry/audit | Non-domain | outside event bus (OTLP / audit pipeline) | per CIC-003-001 §8 |

## 2. Envelope (CloudEvents 1.0)

```json
{
  "specversion": "1.0",
  "id": "01J9Z3…",                                   
  "source": "urn:ucos:svc:pricing-service:eu-west-1",
  "type": "ucos.pricing.price-list.published.v1",
  "subject": "urn:ucos:acme:pricelist:01J9…",
  "time": "2026-10-04T10:00:00.123Z",
  "datacontenttype": "application/json",
  "dataschema": "urn:ucos:ucos.std:schema:ucos.pricing.price-list.published@1.2.0",
  "ucostenant": "acme",
  "ucosaggregatetype": "price-list",
  "ucosaggregateid": "01J9…",
  "ucossequence": 42,
  "ucosversion": 1873,
  "ucoscorrelationid": "01J9…",
  "ucoscausationid": "01J9…",
  "ucosprincipal": "urn:ucos:acme:party:01J8…",
  "ucoshomeregion": "eu-west-1",
  "ucoscontext": "<base64url canonical context, optional>",
  "data": { }
}
```

`ucossequence` = per-aggregate sequence; `ucosversion` = per-(tenant, fact kind, subject) store
version used for cache invalidation (CIC-011-003 §2).

## 3. Payload rules

1. Domain events carry the **changed facts** plus aggregate identity and revision; consumers needing
   full state call the owner's query API or maintain a projection.
2. No personal data in clear for sensitivity ≥ sensitive-personal; personal fields are either omitted
   (consumers fetch with authorization) or encrypted per subject key.
3. Schemas: JSON Schema 2020-12 registered in the schema registry under `dataschema`; compatibility
   mode FULL_TRANSITIVE within a MAJOR.
4. Event names are past tense; events never describe intent ("PriceRequested" is a command, not an event).

## 4. Delivery semantics

- Producer: transactional outbox (CIC-003-001 §4) → relay publishes in outbox order per partition key.
- Ordering guaranteed per `tenant_id:aggregate_id`; no global ordering is promised or relied on.
- At-least-once delivery; consumers MUST be idempotent via `processed_messages` (event_id) or
  natural idempotency (`ucossequence ≤ lastApplied` → skip).
- Consumers detect gaps (`ucossequence > lastApplied + 1`) and pause the key, re-fetching from the
  owner's event replay API `GET /v1/{context}/events?aggregateId=&fromSequence=`.
- Poison messages: 5 retries with exponential backoff (1 s → 16 s), then DLQ topic
  `<topic>.dlq.<consumer>`; DLQ depth > 0 alerts Sev-3; redrive via ops API.

## 5. Outbox relay

Relay polls `outbox WHERE published_at IS NULL ORDER BY id LIMIT 500` with `FOR UPDATE SKIP LOCKED`,
publishes with idempotent producer (`enable.idempotence=true`, `acks=all`), then sets `published_at`.
Lag SLO: p99 ≤ 500 ms from commit to broker ack. Alternative CDC relay (logical decoding of outbox)
is a certified adapter.

## 6. Cross-region

Each region has its own bus. Aggregates are written only in their `homeRegion`. Events replicate to
other regions via mirrored `ucos.*` topics (MirrorMaker 2 / equivalent) with region-prefixed topic
names; consumers in non-home regions build read projections only. Re-homing an aggregate is a
governed operation that freezes writes, transfers the stream, and emits `ucos.runtime.aggregate.rehomed.v1`.

## 7. AsyncAPI requirement

Each context publishes `asyncapi.yaml` (3.0) listing every channel, message, and schema it produces
and consumes; the AsyncAPI document is the contract tested in CR-006-001-02.

## 8. Certification Rules

- **CR-006-001-01** Every produced event validates against its registered schema in contract tests and in production sampling (1 % sample, zero tolerance alerting).
- **CR-006-001-02** AsyncAPI contract coverage: every produced event type appears in the context's AsyncAPI document and DOM-*.yaml `events`.
- **CR-006-001-03** Consumer idempotency test: delivering every event twice and out-of-order across aggregates yields identical projections.
- **CR-006-001-04** Schema registry rejects incompatible schema within a MAJOR (FULL_TRANSITIVE).

## 9. Validation Rules

- **VR-006-001-01** Every event type in the corpus matches CIC-000-002 VR-000-002-02 and its `<context>` segment equals the bounded context of the declaring domain.
- **VR-006-001-02** No two domains declare the same event type.
