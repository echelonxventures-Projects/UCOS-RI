# ADR 0003 — S0 interim adapters: dev-header security, HTTP event bus, static tenant directory

- Status: accepted for S0. The authentication and authorization rows are **superseded by ADR 0007/0008 (S2)**; the bus, tenant-directory and observability rows still apply
- Traces: CIC-030-001 §2–3, CIC-005-001 §3, CIC-006-001 §4–5, CIC-021-001 §3

| Concern | S0 adapter | Replaced by |
|---------|------------|-------------|
| Authentication | `UCOS_SECURITY_MODE=dev-header`: the `UCOS-Tenant` header establishes the tenant. The principal is `urn:ucos:<tenant>:principal:dev`. The service refuses to start in any other mode. | S2: OIDC/OAuth 2.1 bearer tokens (DOM-IDN) |
| Authorization (PEP) | `DevAuthorizer`, which allows every permission. The `Authorizer` port is already on every endpoint. | S1/S2: embedded PDP client (DOM-POL, CIC-009-001 §5) |
| Event bus | CloudEvents HTTP structured-mode push to configured sinks. It keeps outbox semantics: order per batch, at-least-once delivery, idempotent consumers. | Kafka-protocol adapter for `ucos-cell` |
| Tenant directory | UUIDv5 of the tenant slug (`contracts/kernel/tenancy.yaml`) | DOM-RTM tenant directory |
| Observability | JSON logs carrying `correlationId` and `traceparent`. Prometheus counters on `/metrics`. | OpenTelemetry SDK + OTLP (CIC-022-001) |

## Not yet implemented in S0
These are deferred deliberately and tracked for S1:
- Consumer gap detection (`ucossequence > lastApplied + 1`) and the DLQ.
- Rate limiting.
- SBOM and SLSA provenance (CR-001-001-05).
- The mutation-score gate (CR-001-001-04).
