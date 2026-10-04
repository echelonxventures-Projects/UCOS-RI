---
id: CIC-002-001
title: Domain Constitution and Context Map
version: 1.0.0
status: normative
authority: Chief Architect
corpus: CORPUS-002
dependencies: [CIC-000-001, CIC-000-002, CIC-001-001]
traces: [PRIN-001, PRIN-002, PRIN-003, PRIN-007, PRIN-013, PRIN-019]
certification: [CR-002-001-01, CR-002-001-02, CR-002-001-03]
validation: [VR-002-001-01, VR-002-001-02]
---

# CIC-002-001 — Domain Constitution and Context Map

## 1. Domain vs bounded context

- A **domain** (DOM-*) is a unit of constitutional knowledge with exactly one owner (PRIN-001).
- A **bounded context** is a deployable model boundary owning one or more domains. Each bounded
  context maps to one module tree (CIC-001-001 §3) and one database schema `ucos_<context>`.
- The authoritative domain→context mapping is `domains/registry.yaml` (CIC-002-002).

## 2. Tiers

| Tier | Realization | Change authority |
|------|-------------|------------------|
| kernel | Kernel bounded contexts under `kernel/`; aggregates listed in CIC-000-001 K-1 | Constitutional amendment |
| core | Bounded contexts under `domains/`, composed from kernel aggregates | Chief Architect ChangeSet |
| pack | **No code.** TypeDefinitions, LifecycleModels, Policies in `ucos.std` Type Pack interpreted by DOM-COB | Pack release (CORPUS-029) |
| extension | Certified plugin bounded context (CORPUS-028) | Plugin certification |

`pack`-tier is how PRIN-002 and PRIN-019 are realized: Products, Services, Subscriptions,
Memberships, Experiences — and any future commercial model — are `TypeDefinition`s:

```
urn:ucos:ucos.std:type:CommercialObject@1.0.0         (abstract root, kernel)
├── urn:ucos:ucos.std:type:Product        facets: [Classifiable, Priceable, Fulfillable, Stockable?, Shippable?]
├── urn:ucos:ucos.std:type:Service        facets: [Priceable, Fulfillable, Deliverable, Schedulable?]
├── urn:ucos:ucos.std:type:Subscription   facets: [Priceable, Recurring, Renewable, Entitling, Metered?]
├── urn:ucos:ucos.std:type:Membership     facets: [Entitling, Tiered, Recurring?]
├── urn:ucos:ucos.std:type:License        facets: [Entitling, Priceable, Metered?, Transferable?]
├── urn:ucos:ucos.std:type:Experience     facets: [Schedulable, CapacityBound, Priceable]
├── urn:ucos:ucos.std:type:Bundle         facets: [Composite, Priceable]
└── urn:ucos:com.acme.telco:type:MobilePlan  extends Subscription, facets +[Metered, NumberBound]

(`?` = optional facet. Normative definitions: `packs/ucos.std/types.yaml`, CIC-029-001 §4.)
```

## 3. Bounded contexts and context map

| Context | Domains | Upstream of | Relationship pattern |
|---------|---------|-------------|---------------------|
| identity | IDN, REF | all | Open Host Service + Published Language (URN, ExternalReference) |
| party | PTY, ORG, AUTH | all | OHS |
| evidence | EVD, TRST, PRV, LIN | governance, all | OHS; all contexts are Conformist to Evidence schema |
| ontology | ONT, TXO, KNW, KLC, ATTR, CLS, META | all | OHS; Published Language = TypeDefinition schema |
| graph | KGR, REL, HIER | catalog, intelligence | OHS; projection consumer of all relationship events |
| commercial-object | COB, PRD, SVC, SUB, MBR, BDL, PKG, AST, EXP, CAP, CMPS | catalog, offer, pricing, entitlement, transaction | OHS |
| context | CTX, LOC, GEO, TER, TIM | all | Shared Kernel (ContextVector, ApplicabilityScope are kernel VOs) |
| policy | POL, RUL, DEC | all | OHS (PDP API); all contexts are PEPs |
| lifecycle | LFC, VER | all | Shared Kernel (LifecycleModel interpreter library) |
| eventing | EVT | all | Shared Kernel (envelope), infrastructure |
| catalog | CAT, PFL | offer, intelligence, transaction | Customer/Supplier |
| offer | OFR, CMP | pricing, transaction | Customer/Supplier |
| pricing | PRC | transaction, billing | OHS (ResolvePrice) |
| entitlement | ENT, LIC, RGT | service delivery, billing | Customer/Supplier |
| contract | CTR | pricing, entitlement, billing | Customer/Supplier |
| transaction | QTE, ORD | fulfillment, billing, entitlement | Customer/Supplier |
| supply | AVL, SUPN, MFG, PKGN, INV | transaction, catalog | OHS (ResolveAvailability) |
| fulfillment | FUL, LOG, SDL | transaction | Customer/Supplier |
| billing | BIL | revenue, settlement | Customer/Supplier |
| revenue | REV | finance | Customer/Supplier |
| settlement | STL, PAY | finance | Customer/Supplier; external PSPs via Anti-Corruption Layer |
| marketplace | MKT, DST | catalog, settlement | Partnership |
| finance | CST, PRF, ACC, TAX, FCT | — | Conformist to billing/revenue events; ACL to external ERP |
| governance | GOV, CRT, CMPL, AUD, TRC, EVO, SOV | all (approval) | OHS (ChangeSet API) |
| data | MDM, DQL, DXC, FED, IOP | all | ACL for every external system |
| content | DOC, MED | catalog, contract | OHS |
| intelligence | DSC, SRC, RCM, INT, ANL, FCS, SIM, PLN, OPT | catalog, offer | Conformist (read-model consumer) |
| risk | FRK, FRD, CFT, CYR, ORK | transaction, settlement | OHS (risk decision as PDP input) |
| security | SEC, PRI | all | Shared Kernel (security runtime) |
| automation | WFL, AUT, ORC, AGT, ACM | — | Customer of all command APIs |
| digital-twin | DTW | intelligence | Conformist |
| sustainability | SUS | catalog, intelligence | Conformist + attribute contributions |
| runtime | RTM, EXE, OBS, MON, RLB, CFG | all | Infrastructure |
| extension | EXT, CUS, FUT | all | Kernel extension points |

## 4. Domain specification contract

Every domain reaching `status: specified` provides `domains/DOM-<CODE>.yaml` validating against
`schemas/domain-spec.schema.json` with all 25 sections: purpose, scope, responsibilities, principles,
boundaries, ownership, capabilities, services, aggregates, entities, valueObjects, commands, queries,
apis, events, stateMachines, rules, policies, decisions, security, governance, runtimeBehavior,
persistenceModel, extensionModel, certificationCriteria.

Pack-tier domains specify `aggregates` as the TypeDefinitions they contribute and `persistenceModel.store: commercial-object`.

## 5. Cross-domain interaction rules

1. Synchronous calls only through another context's published API; max synchronous fan-out depth 2.
2. State propagation between contexts only via published events.
3. References across contexts are URNs pinned to a version where semantics depend on it.
4. Long-running cross-context processes are process managers (sagas) in the initiating context or DOM-ORC; compensation is mandatory for every step.

## 6. Certification Rules

- **CR-002-001-01** Each deployable module's `ucos-module.yaml.domains` contains only domains whose `boundedContext` matches the module's context.
- **CR-002-001-02** Contract scan: no published API or event of context A exposes an aggregate owned by context B except as URN reference.
- **CR-002-001-03** Pack-tier domains have zero code modules; they are verified by type-pack certification (CORPUS-029).

## 7. Validation Rules

- **VR-002-001-01** Every bounded context named in the registry appears in §3.
- **VR-002-001-02** Every domain in the registry has exactly one bounded context and one owning role.
