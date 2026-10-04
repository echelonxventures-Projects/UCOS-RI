---
id: CIC-008-001
title: Rules Constitution and Rule Resolution Algorithm
version: 1.0.0
status: normative
authority: Chief Governance Architect
corpus: CORPUS-008
dependencies: [CIC-011-001, CIC-000-003]
traces: [PRIN-004, PRIN-005, PRIN-016, DOM-RUL]
certification: [CR-008-001-01, CR-008-001-02, CR-008-001-03]
validation: [VR-008-001-01, VR-008-001-02]
---

# CIC-008-001 — Rules Constitution and Rule Resolution Algorithm

## 1. Rules vs Policies vs Decisions

| Concept | Answers | Output | Owner |
|---------|---------|--------|-------|
| **Rule** (DOM-RUL) | "Given facts, what derived fact or effect follows?" | Effect (value, adjustment, derived context, validation result) | Business domain authors |
| **Policy** (DOM-POL) | "Is this action permitted / which configuration applies?" | allow/deny/obligations or configuration document | Governance |
| **Decision** (DOM-DEC) | "Record of a specific evaluation" | DecisionRecord with inputs, outputs, trace | Kernel (automatic) |

## 2. Rule aggregate

```yaml
Rule:
  urn: urn:ucos:<ns>:rule:<name>@<semver>
  factKind: string            # registered fact kind: price-adjustment, sellability-rule, context-derivation,
                              # configuration-constraint, validation, eligibility, catalog-ordering, routing, …
  scope: ApplicabilityScope
  validFrom / validTo / priority
  condition: CEL              # boolean; inputs declared in inputSchema
  effect: {kind: <registered effect kind for factKind>, params: json}
  inputSchema: JSON Schema    # facts the condition and effect may read
  salience: integer           # order within a ruleset evaluation
  ruleSetRef: urn?            # optional grouping with hit policy
  state: draft|in-review|published|deprecated|retired
```

`RuleSet` = `{urn, factKind, hitPolicy: first|priority|collect|collect-sum|unique|any, rules[]}` —
hit policies follow DMN 1.4 semantics. Decision tables (DMN) compile to RuleSets.

## 3. Rule resolution and evaluation

```
function EvaluateRules(factKind, subject, facts, ctx):
    R ← Resolve(factKind, subject, '-', ctx, cfg{cardinality: many})     # CIC-011-001 (scope, time)
    R ← group by ruleSetRef (null group = implicit set with hitPolicy from policy <factKind>.hit-policy)
    for each group G (ordered by min salience):
        hits ← []
        for r in G ordered by (salience desc, specificity desc, priority desc, urn):
            if CEL(r.condition, facts ⊕ ctx) = true: hits += r
            if G.hitPolicy ∈ {first} and hits ≠ ∅: break
        if G.hitPolicy = unique and |hits| > 1: fail E-RUL-UNIQUE-VIOLATION
        effects += ApplyHitPolicy(G.hitPolicy, hits)
    return effects + trace
```

Chaining: an effect MAY produce facts consumed by rules of another fact kind; chaining depth ≤ 8,
cycle detection on (factKind, subject) pairs → `E-RUL-CYCLE`.

## 4. Execution constraints

- CEL only (no Turing-complete scripts in rules). Cost limit per rule 10,000; per evaluation 1,000,000.
- No side effects in conditions; effects are data returned to the calling domain, which applies them.
- Rules are compiled at publish time; compiled form cached by pinned URN.

## 5. Certification Rules

- **CR-008-001-01** DMN TCK (hit policies subset) passes for RuleSet evaluation.
- **CR-008-001-02** Rules with conditions exceeding cost limit are rejected at publish time (static cost estimation).
- **CR-008-001-03** EvaluateRules for 1,000 candidate rules p99 ≤ 5 ms.

## 6. Validation Rules

- **VR-008-001-01** Every published rule's condition type-checks against its inputSchema.
- **VR-008-001-02** Every factKind used is registered with its permitted effect kinds.
