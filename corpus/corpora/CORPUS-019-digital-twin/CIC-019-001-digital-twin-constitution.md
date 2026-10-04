---
id: CIC-019-001
title: Digital Twin Constitution — Commercial Twins and Simulation
version: 1.0.0
status: normative
authority: Chief Systems Engineer
corpus: CORPUS-019
dependencies: [CIC-004-001, CIC-006-001, CIC-011-001, CIC-011-004, CIC-030-001]
traces: [PRIN-001, PRIN-006, PRIN-008, DOM-DTW, DOM-SIM, DOM-PLN, DOM-OPT]
certification: [CR-019-001-01, CR-019-001-02, CR-019-001-03, CR-019-001-04]
validation: [VR-019-001-01, VR-019-001-02]
---

# CIC-019-001 — Digital Twin Constitution

## 1. Definitions

- **Asset twin**: live state model of a physical or digital asset (DOM-AST instance) fed by telemetry
  (IoT, usage, service events): `{assetRef, stateVector, health, telemetry streams, lastSyncedAt}`.
  Used for service delivery, usage-based pricing inputs, predictive maintenance offers.
- **Commercial twin**: a sandboxed, time-shifted **replica of a tenant's commercial configuration**
  (types, objects, prices, catalogs, offers, policies, rules, entitlements) plus synthetic or
  anonymized demand, on which "what-if" changes are simulated before governance approval.
- **Process twin**: event-driven model of an operational process (order-to-cash, procure-to-pay)
  built from event logs for bottleneck and SLA analysis (process mining over CloudEvents).

## 2. Commercial twin mechanics

```
Create twin(tenant, asOf, scope)  → snapshot metadata + selected aggregates at asOf (event replay to asOf)
                                  → isolated twin tenant in the simulation cell (no external effects:
                                    payment/tax/carrier/e-sign plugins replaced by certified simulators)
Apply candidate ChangeSet         → publish into twin only
Run scenario(demand model)        → replay recorded (anonymized) or synthetic requests through real
                                    resolvers/PDP/pricing/availability on the RI (CIC-030-001)
Compare                           → KPI deltas vs baseline twin: revenue, margin, conversion proxies,
                                    price-resolution failures, eligibility changes, entitlement costs
Attach results                    → Evidence on the ChangeSet (CIC-015-001 §3 step 3)
```

Twins use the **same code and metadata interpreters** as production (no separate simulation
logic), which is why simulation results are trustworthy. Determinism: same twin snapshot + same
scenario seed ⇒ identical results.

## 3. Asset twin mechanics

- Telemetry ingested via DOM-DXC connectors (MQTT/OPC UA/HTTP) into a time-series store; twin state
  derived by declarative state mappings (CEL over telemetry windows) defined per asset type (ontology facet `Twinnable`, delivered by industry packs).
- Twin state changes publish `ucos.digital-twin.asset.state-changed.v1` consumed by service delivery,
  entitlement (usage meters), and recommendations (e.g. upgrade offers).
- Commands to physical devices are never issued by the twin directly; they go through service delivery with authorization.

## 4. Simulation and optimization (DOM-SIM/PLN/OPT)

Simulation scenarios, forecasts (DOM-FCS), and optimizers (pricing optimization, assortment,
sourcing) produce **recommendations as draft ChangeSets**, never direct changes; optimizers declare
objective, constraints (policies), and run on twins for validation.

## 5. Privacy and isolation

Twins never contain production personal data in clear: party data is pseudonymized with a
twin-specific key destroyed when the twin is deleted; twins expire (default 30 days, policy
`twin.ttl`) and are crypto-shredded.

## 6. Certification Rules

- **CR-019-001-01** Twin determinism: two runs of the same scenario on the same snapshot produce byte-identical KPI reports.
- **CR-019-001-02** Twin isolation: no event, API call, or plugin call from a twin reaches production endpoints or external providers (egress test).
- **CR-019-001-03** Snapshot fidelity: twin at `asOf` resolves prices/catalog/availability identically to production replay at `asOf` for 10⁴ sampled requests.
- **CR-019-001-04** Twin deletion crypto-shreds pseudonymization keys and removes all twin stores.

## 7. Validation Rules

- **VR-019-001-01** Every simulator plugin replacing a provider declares the provider port it simulates and passes that port's conformance suite in simulation mode.
- **VR-019-001-02** Every optimizer declares objective, constraints, and output ChangeSet item kinds.
