---
id: CIC-025-001
title: Operations Constitution — Incidents, Runbooks, Capacity, Tenancy Operations
version: 1.0.0
status: normative
authority: Chief Systems Engineer
corpus: CORPUS-025
dependencies: [CIC-020-001, CIC-021-001, CIC-022-001, CIC-024-001, CIC-015-001]
traces: [PRIN-011, PRIN-015, DOM-RLB, DOM-MON]
certification: [CR-025-001-01, CR-025-001-02, CR-025-001-03, CR-025-001-04]
validation: [VR-025-001-01, VR-025-001-02]
---

# CIC-025-001 — Operations Constitution

## 1. Severity model

| Sev | Definition | Response | Comms |
|-----|-----------|----------|-------|
| 1 | Checkout/order placement, identity, or billing issuance unavailable or incorrect for ≥ 1 cell; data integrity or security breach; evidence verification failure | Page immediately; IC assigned ≤ 5 min | Status page ≤ 15 min; exec + regulator timers per policy |
| 2 | Major degradation (SLO burn ≥ 6×), single context down in a cell, DLQ growth in financial contexts | Page ≤ 15 min | Status page ≤ 30 min |
| 3 | Minor degradation, non-financial DLQ, single-tenant issue | Business hours | Ticket |
| 4 | Cosmetic / no user impact | Backlog | — |

## 2. Incident process

Roles: Incident Commander, Operations Lead, Communications Lead, Scribe; domain owners on call per
bounded context (on-call rota per `owningRole` team in the registry). Lifecycle:
`detected → triaged → mitigating → monitoring → resolved → postmortem-complete`. Postmortems are
blameless, due within 5 business days for Sev-1/2, with action items tracked to closure; postmortem
documents are captured as Evidence.

## 3. Runbooks

Every alert, every DR failover, every governed operational action has a runbook in
`ops/runbooks/<context>/<id>.md` with: trigger, impact, diagnosis queries (dashboards, traces, SQL
read-only), mitigation steps (exact commands/API calls), rollback, verification, escalation. Runbooks
with automatable steps are implemented as **operations workflows** (DOM-WFL definitions) executed via
the ops API with approvals and evidence — not ad-hoc shell.

Mandatory runbooks (minimum set): cell failover, tenant re-home, broker outage / outbox backlog,
DLQ redrive (per financial context), projection rebuild (graph, search, catalog membership), policy
bundle rollback, key rotation/compromise, crypto-shred verification, bill run failure recovery,
payment provider outage, inventory reconciliation, certificate expiry, data subject request backlog.

## 4. Operational APIs (Z4 only)

`/ops/v1/...`: tenant placement and relocation, cell drain/undrain, job control (pause/resume/abort),
DLQ inspection and redrive (delegates to DOM-EVT), cache flush (by tenant/key prefix), projection
rebuild trigger, feature flag/kill switch changes. Every call: SSO + device posture, PDP authorization,
reason + ticket reference required, audited, Evidence for destructive operations.

## 5. Tenant operations

| Operation | Procedure |
|-----------|-----------|
| Onboard | Create tenant in directory → place in cell → provision keys (KEK), RLS context, quotas → install packs per plan → baseline policies → smoke journey on tenant |
| Re-home / relocate | Freeze writes (per tenant) → replicate final events → switch directory → rehome aggregates → unfreeze; target write freeze ≤ 5 min per 10⁷ aggregates |
| Suspend | Directory flag → gateways reject except billing/export endpoints |
| Offboard | Export (data portability package) → retention hold per policy → crypto-shred tenant KEK → directory tombstone; evidence of destruction |

## 6. Capacity management

Monthly capacity review per cell: forecast (DOM-FCS on platform metrics) vs capacity model; actions:
scale, re-place tenants, open new cell (lead time ≤ 1 day via IaC). Peak events (sales seasons) require
a load test at 1.5× forecast in staging and a pre-scaled production plan approved 7 days ahead.

## 7. Reconciliation operations

Scheduled reconciliations (daily) with results as control test results (CIC-015-001 §5):
order↔billing charges, billing↔payments↔settlements, inventory ledger↔positions, entitlement ledger↔balances,
event store↔projections (counts/digests), evidence ledger checkpoints↔anchors.

## 8. Certification Rules

- **CR-025-001-01** Every alert rule maps to a runbook; every mandatory runbook in §3 exists and was exercised (game day) within the last 180 days.
- **CR-025-001-02** Tenant re-home exercise meets the write-freeze target on a 10⁷-aggregate synthetic tenant.
- **CR-025-001-03** All §7 reconciliations run daily with zero unexplained breaks over 30 days in staging soak.
- **CR-025-001-04** Ops API rejects calls lacking reason/ticket and records audit for 100 % of calls.

## 9. Validation Rules

- **VR-025-001-01** Every owningRole in the domain registry maps to an on-call rota.
- **VR-025-001-02** Every runbook declares trigger, verification, and escalation sections.
