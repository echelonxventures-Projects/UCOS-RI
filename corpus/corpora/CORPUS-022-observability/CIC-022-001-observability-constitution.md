---
id: CIC-022-001
title: Observability Constitution — Telemetry, SLOs, Audit Signals
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-022
dependencies: [CIC-001-001, CIC-006-001, CIC-014-001, CIC-020-001]
traces: [PRIN-015, PRIN-022, DOM-OBS, DOM-MON, DOM-RLB]
certification: [CR-022-001-01, CR-022-001-02, CR-022-001-03, CR-022-001-04]
validation: [VR-022-001-01, VR-022-001-02]
---

# CIC-022-001 — Observability Constitution

## 1. Signals

All telemetry is emitted via OpenTelemetry SDKs over OTLP to a per-cell collector, which enforces
redaction, sampling, and routing. Backends are adapters (PRIN-022).

| Signal | Mandatory content |
|--------|-------------------|
| Traces | W3C trace context end-to-end incl. through events (`traceparent` CloudEvents extension); spans for every inbound request, outbound call, DB query (statement fingerprint only), event publish/consume, policy decision, resolution |
| Metrics | RED per endpoint (rate, errors, duration histograms), USE per resource, consumer lag, outbox age, cache hit ratio, PDP latency, resolution latency, business KPIs (§4) |
| Logs | Structured JSON; fields `ts, level, service, cell, tenant (hashed for shared dashboards), traceId, spanId, correlationId, event, message, errorCode`; no personal data, no secrets |
| Profiles | Continuous profiling (pprof/JFR) sampled 1 % for CPU-heavy services |

## 2. Standard resource attributes

`service.name`, `service.version`, `deployment.environment`, `ucos.region`, `ucos.cell`, `ucos.context`,
`ucos.module.digest`. Tenant ID is a **span/metric attribute only where cardinality-safe**: metrics use
`ucos.tenant.tier` (plan class) by default; per-tenant metrics only for dedicated cells or top-N exports.

## 3. Sampling and redaction

- Head sampling 5 % default; tail sampling at collector keeps 100 % of errors, slow (> SLO p99) traces, and traces of regulated decision types.
- Collector redaction processors: drop attributes matching personal-data key patterns and values matching DLP detectors (email, phone, PAN, IBAN, national IDs); any detection increments `ucos_telemetry_redactions_total` and alerts if > 0 sustained (indicates an emitting bug).

## 4. SLOs and error budgets

Each domain's `runtimeBehavior.slo` is codified as SLO definitions (OpenSLO format) under
`deploy/slo/<context>.yaml`. Rules:
- SLIs measured at the gateway (user-facing) and at service boundary (internal).
- 28-day rolling windows; multi-window multi-burn-rate alerts (1 h/5 m at 14.4×, 6 h/30 m at 6×).
- Error budget policy: budget exhausted → feature releases for that context frozen until recovered (except fixes); enforced by the deployment pipeline reading SLO status.

Business KPIs as metrics (no personal data): orders accepted/rejected by reason, checkout conversion,
price resolution failures (`E-PRC-NO-PRICE` rate), entitlement denies, invoice issuance rate, payment
authorization rate, DLQ depth by context.

## 5. Health model

- `/health/live` (process), `/health/ready` (dependencies needed to serve; excludes optional ones), `/health/startup`.
- Dependency status exported as `ucos_dependency_up{dependency}`; synthetic probes per cell execute golden journeys (browse → price → cart → order with test tenant) every minute.

## 6. Audit vs telemetry

Audit records (CIC-015-001 §7) are **not** telemetry: they go through the audit pipeline with
guaranteed delivery and sealing. Telemetry may be sampled and lossy; audit may not.

## 7. Dashboards and alerts as code

Dashboards (Grafana JSON / Perses) and alert rules (Prometheus rules) are versioned per context in
`deploy/observability/<context>/`, generated from SLO definitions and module manifests. Every alert
links to a runbook (CORPUS-025) and has an owner team.

## 8. Certification Rules

- **CR-022-001-01** Trace continuity test: a checkout journey produces a single trace spanning gateway, ≥ 6 services, and ≥ 3 asynchronous event hops.
- **CR-022-001-02** Every module exposes RED metrics for every API operation in its contract (contract-to-metrics coverage = 100 %).
- **CR-022-001-03** Redaction test: seeded personal values in attributes/logs never reach the backend.
- **CR-022-001-04** Every alert rule references an existing runbook and owner.

## 9. Validation Rules

- **VR-022-001-01** Every DOM-*.yaml `runtimeBehavior.slo` has a matching OpenSLO definition.
- **VR-022-001-02** Metric names follow CIC-001-001 §7 naming.
