---
id: CIC-020-001
title: Runtime Constitution — Cells, Tenancy Routing, Execution Model
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-020
dependencies: [CIC-001-001, CIC-003-001, CIC-006-001, CIC-009-001, CIC-011-003, CIC-014-001]
traces: [PRIN-015, PRIN-022, PRIN-010, DOM-RTM, DOM-EXE, DOM-CFG]
certification: [CR-020-001-01, CR-020-001-02, CR-020-001-03, CR-020-001-04, CR-020-001-05]
validation: [VR-020-001-01, VR-020-001-02]
---

# CIC-020-001 — Runtime Constitution

## 1. Topology: regions, cells, tenants

```
Global control plane (tenant directory, metadata replication, certification registry)
└── Region (e.g. eu-west-1)           — data residency boundary; independent failure domain
    └── Cell (cell-eu-w1-03)          — full UCOS stack instance; blast-radius boundary
        └── Tenants (1..N)            — logically isolated (RLS, keys, quotas)
```

- A **cell** contains every bounded context service, its own databases, broker, caches, search,
  and graph projection. Cells share nothing at runtime except the regional event mirror and the
  global control plane (read-mostly).
- Tenant placement: shared cells (default, ≤ 2,000 tenants or 70 % capacity), dedicated cells
  (large/regulated tenants). Placement is recorded in the **tenant directory**
  `{tenant → homeRegion, cellId, residencyConstraints, plan}`.
- Cell sizing target: ≤ 20 % of a region's tenants per cell; a cell failure must never affect more.

## 2. Request routing

1. Edge resolves tenant from host (`{tenant}.api…`) or `UCOS-Tenant` header.
2. Edge looks up the tenant directory (cached 60 s, invalidated by `ucos.runtime.tenant.relocated.v1`) and
   routes to the cell gateway.
3. Requests for an aggregate whose `homeRegion` ≠ current region: reads served from replicated
   projections if consistency class allows (`UCOS-Consistency: eventual`), otherwise proxied to the home
   region (writes always proxied).
4. Internal service-to-service calls never leave the cell except via declared cross-cell ports
   (control plane, regional mirror).

## 3. Execution model (per service)

| Concern | Rule |
|---------|------|
| Process | Stateless replicas; state only in ports (DB, cache, broker) |
| Concurrency | Non-blocking I/O for request handling; bounded worker pools for CPU work (pricing, rules) |
| Timeouts | Every outbound call has a deadline derived from the inbound deadline minus 10 % (deadline propagation via `grpc-timeout` / `UCOS-Deadline`) |
| Retries | Only idempotent operations; exponential backoff with jitter; retry budget ≤ 10 % of requests per client |
| Circuit breaking | Per dependency; open at 50 % failures over 20 requests in 10 s; half-open probes |
| Bulkheads | Separate pools for commands, queries, consumers, admin |
| Backpressure | Consumers pause partitions when processing lag > threshold; gateways shed load with 503 + Retry-After by priority class (admin < batch < interactive < checkout) |
| Graceful shutdown | Stop accepting → drain in-flight (≤ 30 s) → commit consumer offsets → exit |

## 4. Configuration (DOM-CFG)

Three layers, strictly separated:
1. **Deployment configuration** (ports, pool sizes, endpoints) — Helm values per environment, immutable per release.
2. **Runtime configuration** (feature flags, kill switches, rate limits) — OpenFeature-compatible flag service; changes audited; flags have owners and expiry dates (max 90 days for release flags).
3. **Behavioral configuration** — policies and metadata (CORPUS-009, DOM-ONT, etc.), governed by ChangeSets. Feature flags MUST NOT encode business behavior (lint: flags referenced only in `-service` / `-infrastructure` layers).

## 5. Background execution

- Jobs (bill runs, re-materialization, migrations, archival) run as **resumable jobs**: `{jobId, kind, cursor, checkpointEvery, owner lease}`, leases renewed every 10 s, takeover after 30 s.
- Schedules (cron) defined as metadata; scheduler is leader-elected per cell (Kubernetes Lease).
- Timers (CIC-007-001 §4) are not cron jobs; they are per-aggregate durable timers.

## 6. Multi-region and disaster recovery

| Tier | Contexts | RPO | RTO | Strategy |
|------|----------|-----|-----|----------|
| T0 | identity, policy, pricing, catalog, entitlement checks | ≤ 1 min | ≤ 15 min | Warm standby cell in paired region (same residency zone), continuous replication |
| T1 | order, billing, payment, inventory, contract | ≤ 1 min | ≤ 1 h | Warm standby + event log mirror |
| T2 | analytics, search, graph, recommendations | ≤ 24 h | ≤ 4 h | Rebuild from events |

Failover is a governed runbook (CORPUS-025) with automated checks; tenants re-home by tenant-directory
update; the home region flag on aggregates is updated by the `rehome` operation (CIC-006-001 §6).

## 7. Certification Rules

- **CR-020-001-01** Cell isolation chaos test: killing an entire cell affects only tenants placed in it (synthetic probes in other cells stay green).
- **CR-020-001-02** Deadline propagation test: no downstream call outlives its inbound deadline (tracing assertion).
- **CR-020-001-03** Load-shedding test: at 200 % capacity, checkout-priority requests keep ≥ 99 % success while batch is shed.
- **CR-020-001-04** DR exercise per quarter meets RPO/RTO per tier (evidence captured).
- **CR-020-001-05** Resumable job test: killing a job worker at random points never repeats non-idempotent effects or loses progress beyond one checkpoint.

## 8. Validation Rules

- **VR-020-001-01** Every bounded context in the registry is assigned a DR tier.
- **VR-020-001-02** Every feature flag in the flag registry has an owner and expiry.
