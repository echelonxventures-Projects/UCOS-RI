---
id: CIC-015-001
title: Governance Constitution — ChangeSets, Approvals, Controls
version: 1.1.0
status: normative
authority: Chief Governance Architect
corpus: CORPUS-015
dependencies: [CIC-000-001, CIC-000-004, CIC-009-001, CIC-007-001, CIC-010-001]
traces: [PRIN-011, PRIN-012, PRIN-004, DOM-GOV, DOM-CRT, DOM-CMPL, DOM-AUD, DOM-EVD]
certification: [CR-015-001-01, CR-015-001-02, CR-015-001-03, CR-015-001-04, CR-015-001-05]
validation: [VR-015-001-01, VR-015-001-02]
---

# CIC-015-001 — Governance Constitution

## 1. Governed subjects

Everything that changes system **behavior without a code deployment** is governed (PRIN-011):
TypeDefinitions, Facets, Attributes, RelationshipTypes, LifecycleModels, ContextDimensions, Policies,
Rules, ProjectionMappings, named KG queries, PriceLists (per policy), Catalog definitions, Offer
publications, Type Packs and Plugins (activation), tenant configuration, and corpus amendments.
Instance data (orders, parties) is not governed by ChangeSets; it is governed by lifecycle
transitions, policies, and controls (§5).

**Owners.** Each governed kind has exactly one owning context, which stores drafts and published definitions and
enforces their invariants. Governance (DOM-GOV) is the only publisher, whichever service hosts the owner. An owner
hosted outside the governance service implements the *remote owner protocol* (AMD-0004):
- list and get definitions, with the content digest that approvals bind to (INV-GOV-1) and the risk facts;
- validate a draft at submit time;
- publish a draft bound to the applying ChangeSet, idempotently;
- compensate a publication;
- remove a definition.

Only governance may call the protocol, with a sender-constrained platform service credential. Governance checks its
publication Gate before every publish (CR-015-001-01). Drafts are created through the owning context's own API, into
a draft ChangeSet of their author. Examples: DOM-AUTH SoD conflict sets, authority limits and tenant role definitions.

## 2. ChangeSet (aggregate, DOM-GOV)

```yaml
ChangeSet:
  id: urn:ucos:<tenant>:changeset:<ulid>
  title, description, rationale: LocalizedText/string
  author: PartyUrn
  items: [{subjectKind, subjectRef (draft URN), operation: create|revise|publish|deprecate|retire|activate|deactivate, compatibility: MAJOR|MINOR|PATCH|n/a}]
  impact: ImpactReport              # §3, computed
  riskClass: low|medium|high|critical   # computed by policy governance.risk-classification
  approvalPlan: [{stage, approverRoles[], quorum, sod: [constraints]}]   # computed by policy governance.approval
  approvals: [{stage, approver, decision: approve|reject|abstain, comment, at, evidenceRef}]
  schedule: {effectiveAt?, freezeWindowsRespected: bool}
  rollbackPlan: {strategy: deprecate-new|reactivate-previous|data-migration, ref?}
  state: draft|submitted|in-approval|approved|rejected|scheduled|applying|applied|failed|rolled-back|cancelled
```

## 3. Impact analysis (mandatory, automated)

`ImpactReport` is computed at submission and recomputed on revision:
1. **Dependency closure**: KG impact query (CIC-004-001 §4) from each item: dependent types, objects
   pinned (counts per tenant), policies/rules referencing, catalogs/offers affected.
2. **Compatibility**: CompatibilityClassifier (DOM-ONT), event schema compatibility (DOM-EVT), contract diff.
3. **Behavioral simulation**: for policies/rules/dimensions/price lists — shadow evaluation over
   sampled recorded decisions/requests (CIC-009 simulation) reporting changed-outcome ratio and
   monetary delta (price lists).
4. **Certification status** of plugins/packs involved.
5. **Regulatory flags**: items touching regulated fact kinds or regulatory policy layer.

## 4. Approval algorithm

```
plan ← PDP.decide('governance.approval', {items, impact, riskClass, tenant}, ctx)   # configuration policy
for stage in plan (sequential):
    wait until approvals(stage, decision=approve) ≥ stage.quorum   or any reject → state rejected
    enforce SoD: approver ∉ {author} ∪ stage.sod.excluded ; no approver counted twice across stages unless allowed
    each approval captures Evidence (approver identity, assurance level acr ≥ AAL2, ChangeSet digest)
approved ← all stages satisfied and ChangeSet digest unchanged since first approval (any revision resets approvals)
```

ucos.std default plan: low → 1 approver (domain role); medium → 2 incl. domain owner; high → 2 + Governance;
critical (constitutional, regulatory layer, security policies) → 3 incl. Constitutional Authority or
Compliance, plus 24 h cool-off before apply.

## 5. Controls framework

A **Control** (DOM-CMPL) is `{id, objective, frameworkMappings[], kind: preventive|detective|corrective,
implementation: policyRef|ruleRef|certRuleRef|monitorRef, testProcedure, frequency, owner}`.
Controls are evaluated continuously where `implementation` is machine-checkable (policies, CR rules,
monitors); results are ControlTestResults with Evidence. Compliance dashboards are projections of
control results per framework mapping (ISO 27001, SOC 2, PCI DSS, GDPR Art. 30/32, SOX ITGC).

Key financial controls (SOX-relevant, enforced by DOM-FCT): segregation of duties on price
publication, credit memo issuance, write-offs, payment release, journal posting; dual control on DLQ
discard for financial events (RUL-EVT-3); immutable financial event stores.

## 6. Apply and rollback

Applying an approved ChangeSet executes item operations in dependency order (topological sort over item
dependencies), each as the owning context's command with `changeSetRef`, inside a saga: on failure,
completed items are compensated per `rollbackPlan` (e.g. deprecate newly published versions and
reactivate previous). Freeze windows (policy `governance.freeze-windows`) block apply except for
`critical` hotfix ChangeSets approved under emergency plan.

## 7. Audit (DOM-AUD)

Every command, authorization deny, personal-data read, ChangeSet transition, break-glass action, and
configuration change produces an AuditRecord `{who, onBehalfOf, what (operation, resource), when,
where (region, client), why (purpose, changeSetRef), outcome, correlationId}`. Audit streams are sealed
hourly into Evidence (DOM-EVD) segments with digests in the ledger. Audit records are immutable and
queryable for 24 months hot, then archive per retention policy.

## 8. Certification Rules

- **CR-015-001-01** No governed subject can reach a published/active state without an `applied` ChangeSet reference (negative tests per subject kind).
- **CR-015-001-02** SoD tests: author approval, duplicate approver, and same-person-different-identity (identities bound to same party) are all rejected.
- **CR-015-001-03** Any revision after first approval resets approvals (digest test).
- **CR-015-001-04** Apply saga failure injection at each item leaves the system in the pre-apply or fully-applied state per rollbackPlan.
- **CR-015-001-05** Audit completeness: for 10⁵ random operations, every one has exactly one audit record sealed into Evidence within 2 h.

## 9. Validation Rules

- **VR-015-001-01** Every DOM-*.yaml declares `governance.changeControl`.
- **VR-015-001-02** Every subject kind in §1 maps to an owning domain whose publish command requires `changeSetRef` or `approvalRef`.
