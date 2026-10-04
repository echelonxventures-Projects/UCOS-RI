---
id: CIC-000-001
title: UCOS Ω∞ Constitution
version: 1.0.0
status: normative
authority: UCOS Constitutional Authority
corpus: CORPUS-000
dependencies: []
traces: []
certification: [CR-000-001-01, CR-000-001-02, CR-000-001-03]
validation: [VR-000-001-01, VR-000-001-02]
---

# CIC-000-001 — UCOS Ω∞ Constitution

## 1. Normative language

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted per RFC 2119 / RFC 8174 when in capitals.
An artifact with `status: normative` binds every implementation claiming UCOS conformance.
`status: informative` artifacts explain but do not bind.

## 2. The Substrate Thesis

UCOS is a **substrate**, not an application. It provides a small fixed kernel (identity, ontology,
commercial object, relationship graph, context, policy, event, lifecycle) and expresses every
commercial model — product, service, subscription, licence, telecom plan, insurance policy, government
benefit, AI-agent capability — as **data interpreted by the kernel**. A new commercial model is
introduced by publishing ontology, policy, and lifecycle definitions, never by changing kernel code.

Kernel invariant (K-1): the set of kernel aggregate types is closed:
`Identity, Party, TypeDefinition, CommercialObject, Relationship, ContextDimension, Policy, Rule,
LifecycleModel, Event, Evidence`. Every other domain composes these.

## 3. Constitutional Principles

Each principle has an enforceable invariant and a certification check. Principles are referenced by ID.

| ID | Principle | Enforceable invariant |
|----|-----------|----------------------|
| PRIN-001 | Knowledge Once | Every fact has exactly one owning domain (registry `owner`). Non-owners hold only references or read-model projections tagged `projectionOf`. |
| PRIN-002 | Commercial Object Once | Every sellable/grantable/consumable thing is a `CommercialObject` instance typed by a `TypeDefinition`. No domain defines its own product-like table. |
| PRIN-003 | Single Source of Truth | Each aggregate has one write path (its owning service's command API). Direct writes to another domain's store are forbidden. |
| PRIN-004 | Metadata Driven | Types, attributes, facets, relationships, lifecycles, dimensions, and UI forms are defined as versioned metadata and interpreted at runtime. |
| PRIN-005 | Policy Driven | Any behavior that can differ by tenant, market, jurisdiction, or time is externalized as a `Policy` or `Rule` evaluated by the Policy Decision Point (PDP). |
| PRIN-006 | Context Driven | Every contextual fact (price, availability, text, catalog membership, rule) carries an `ApplicabilityScope` and is selected by the Context Resolution Algorithm (CIC-011-001). |
| PRIN-007 | Graph Native | All inter-object associations are first-class `Relationship` records with a `RelationshipType`; foreign keys between domains are forbidden. |
| PRIN-008 | Event First | Every state change of an aggregate is recorded as an immutable domain event before any projection is updated (event-sourced or transactional-outbox). |
| PRIN-009 | API First | Every capability is reachable through a published, versioned API contract (OpenAPI 3.1 / gRPC proto / AsyncAPI 3.0) before any UI consumes it. |
| PRIN-010 | Security First | Every request is authenticated, every decision authorized by the PDP, deny-by-default. |
| PRIN-011 | Governance First | Every metadata change (type, policy, rule, dimension) passes through a governed ChangeSet with approval workflow and evidence. |
| PRIN-012 | Certification First | No artifact, plugin, type pack, or release is activated without a passing Certification Record. |
| PRIN-013 | Infinite Extensibility | Extension occurs only through declared extension points: type inheritance, facets, attribute extension, policy packs, plugins (CORPUS-028). |
| PRIN-014 | Infinite Localization | Every human-readable value is a `LocalizedText` resolved through the Localization Resolution Algorithm; no human text in code. |
| PRIN-015 | Infinite Distribution | Every aggregate is partitionable by `tenantId` and `homeRegion`; no global locks; cross-region via events. |
| PRIN-016 | No Hardcoding | Code MUST NOT contain literals naming industries, markets, channels, categories, currencies, tax rates, or type names other than kernel types. Lint rule `UCOS-L001`. |
| PRIN-017 | No Fixed Hierarchies | Hierarchies are `Relationship` subgraphs of a hierarchical `RelationshipType`; an object MAY participate in unlimited hierarchies. |
| PRIN-018 | No Fixed Categories | Classification uses `Taxonomy` metadata; taxonomies are tenant-definable. |
| PRIN-019 | No Fixed Industries | Industry specifics are delivered as Type Packs (CORPUS-029), never as kernel branches. |
| PRIN-020 | No Fixed Markets | Markets are values of the `market` context dimension. |
| PRIN-021 | No Fixed Channels | Channels are values of the `channel` context dimension. |
| PRIN-022 | No Vendor Lock-In | Every infrastructure dependency is behind a port interface with ≥ 2 certified adapters or a documented open standard (SQL:2016, openCypher/GQL, CloudEvents, OpenTelemetry, OCI, OIDC). |

## 4. Constitutional hierarchy and precedence

1. CIC-000-* (this corpus) overrides all others.
2. Lower corpus number overrides higher on conflict (CORPUS-003 overrides CORPUS-020).
3. Within a corpus, higher artifact sequence MAY refine but MUST NOT contradict lower.
4. A detected contradiction is a Constitutional Defect: raised as `ucos.governance.defect.raised.v1`,
   resolved by an amendment ChangeSet to the lower-precedence artifact.

## 5. Amendment process

An amendment is a ChangeSet (CIC-015) containing: affected artifact IDs, diff, rationale, impact
analysis (all artifacts whose `dependencies` transitively include the amended one), and version bump
per CIC-000-003 §4. Constitutional (CORPUS-000) amendments require approval by the Constitutional
Authority role plus two distinct Chief Architect roles.

## 6. Certification Rules

- **CR-000-001-01** Every implementation module declares in its manifest the principle IDs it implements; the certification suite runs the principle checks below for each.
- **CR-000-001-02** PRIN-016 check: static analysis rule `UCOS-L001` reports zero violations.
- **CR-000-001-03** PRIN-003/PRIN-007 check: schema scan shows no cross-schema foreign keys and no write grants outside the owning service role.

## 7. Validation Rules

- **VR-000-001-01** Every principle referenced anywhere in the corpus resolves to a row in §3.
- **VR-000-001-02** The kernel aggregate list in K-1 equals the set of domains with `tier: kernel` aggregates marked `kernel: true` in the domain registry.
