---
id: CIC-026-001
title: Migration Constitution — Schema, Event, Metadata, and Legacy Migration
version: 1.0.0
status: normative
authority: Chief Data Architect
corpus: CORPUS-026
dependencies: [CIC-003-001, CIC-006-001, CIC-007-001, CIC-015-001, CIC-024-001]
traces: [PRIN-001, PRIN-008, PRIN-011, PRIN-013, DOM-EVO, DOM-DXC, DOM-MDM]
certification: [CR-026-001-01, CR-026-001-02, CR-026-001-03, CR-026-001-04, CR-026-001-05]
validation: [VR-026-001-01, VR-026-001-02]
---

# CIC-026-001 — Migration Constitution

## 1. Migration classes

| Class | Example | Mechanism |
|-------|---------|-----------|
| M1 Physical schema | Add column, new index, partition change | Versioned SQL, expand/contract (CIC-003-001 §10, CIC-024-001 §4) |
| M2 Event schema | Event MAJOR version | Upcasters for reads; dual-publish for consumers (RUL-EVT-1) |
| M3 Metadata | TypeDefinition MAJOR, LifecycleModel MAJOR, dimension deprecation | Migration definitions (§2) executed as resumable jobs |
| M4 Tenant data transformation | Re-scope prices, split catalogs, merge taxonomies | Migration definitions with CEL transforms over aggregates via commands |
| M5 Legacy onboarding | Import from ERP/commerce/billing systems | Migration programs (§3) through DOM-DXC anti-corruption mappers |
| M6 Relocation | Tenant re-home, cell split | Ops procedure (CIC-025-001 §5) |

## 2. Migration definition (M3/M4)

```yaml
Migration:
  urn: urn:ucos:<ns>:migration:<name>@<semver>
  class: M3|M4
  subject: {kind: commercial-object|price-entry|contract|…, selector: CEL}
  from: {typeRef|modelRef|dimensionRef: urn@version}
  to:   {…}
  transform: CEL                       # pure: (aggregate view) -> command payload
  command: <context command used to apply, e.g. RetypeCommercialObject>
  stateMapping: map?                   # for lifecycle MAJOR
  verification: [CEL]                  # post-conditions checked per migrated aggregate
  batch: {size: 500, maxRatePerSecond: 2000, pauseOnErrorRatio: 0.001}
  dryRun: required
  rollback: {strategy: inverse-transform|restore-from-events, inverse?: CEL}
```

Execution rules:
1. **Dry run** is mandatory: executes transform + verification without applying, producing a report (counts, failures, sample diffs) attached to the ChangeSet as Evidence.
2. Apply runs as a resumable job (CIC-020-001 §5) issuing normal domain commands (so events, policies, and invariants apply — no direct table writes).
3. Each migrated aggregate records `migrationRef` in the emitted event metadata (lineage, DOM-LIN).
4. Throttling protects SLOs: job pauses automatically when the context's error budget burn > 2×.

## 3. Legacy migration programs (M5)

Phases, each a governed checkpoint:
1. **Profile**: extract legacy schema and data profiles; map to ontology (DOM-IOP mapping metadata); identify gaps → new TypeDefinitions/attributes via ChangeSet (never hardcoded columns).
2. **Map**: declarative mapping specs (source field → attribute/relationship/scope), code lists → taxonomy terms, legacy IDs → `ExternalReference` (scheme = legacy system) to preserve traceability.
3. **Trial loads** into staging tenant with synthetic-masked data; reconciliation reports (counts, sums of money fields per currency, referential completeness).
4. **Cutover strategy** per domain: big-bang (small tenants) or **strangler** with CDC from legacy → UCOS (DOM-DXC connectors) and dual-run comparison of key outputs (prices, invoices) until mismatch rate < policy threshold (default 0.01 %) for 2 billing cycles.
5. **Cutover** with freeze window, final delta, reconciliation sign-off (Finance for financial data), and legacy read-only archive.

Financial open items (unpaid invoices, balances) migrate as **opening balance** documents with
references to legacy documents, never re-issued as new invoices.

## 4. Certification Rules

- **CR-026-001-01** Every M3/M4 migration has a dry-run report attached to an approved ChangeSet before apply.
- **CR-026-001-02** Migration job crash/resume test: no aggregate migrated twice (idempotency via migrationRef) and none skipped.
- **CR-026-001-03** Post-migration verification CELs pass for 100 % of migrated aggregates or the job ends failed with a rollback executed.
- **CR-026-001-04** Legacy cutover reconciliation: record counts and per-currency money sums match within zero tolerance for financial entities.
- **CR-026-001-05** Dual-run price/invoice comparison below threshold for 2 consecutive cycles before legacy decommission.

## 5. Validation Rules

- **VR-026-001-01** Every MAJOR TypeDefinition/LifecycleModel version with live instances on its predecessor has a registered migration.
- **VR-026-001-02** Every migration declares verification post-conditions and a rollback strategy.
