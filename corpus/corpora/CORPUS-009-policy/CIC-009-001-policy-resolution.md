---
id: CIC-009-001
title: Policy Constitution and Policy Resolution Algorithm
version: 1.0.0
status: normative
authority: Chief Governance Architect
corpus: CORPUS-009
dependencies: [CIC-011-001, CIC-008-001]
traces: [PRIN-005, PRIN-010, PRIN-011, DOM-POL, DOM-DEC]
certification: [CR-009-001-01, CR-009-001-02, CR-009-001-03, CR-009-001-04]
validation: [VR-009-001-01, VR-009-001-02]
---

# CIC-009-001 — Policy Constitution and Policy Resolution Algorithm

## 1. Policy kinds

| Kind | Output | Example |
|------|--------|---------|
| `authorization` | `allow \| deny` + obligations + advice | `cob.transition` |
| `configuration` | JSON document validated by a config schema | `pricing.rounding`, `price-entry.resolution` |
| `constraint` | `satisfied \| violated` + violations | `ontology.sensitivity-floor` |
| `selection` | chosen option(s) from candidates | conflict strategy `policy:<urn>` |

## 2. Policy aggregate

```yaml
Policy:
  urn: urn:ucos:<ns>:policy:<context>.<name>@<semver>
  kind: authorization|configuration|constraint|selection
  layer: constitutional|platform|regulatory|tenant|organization|delegated
  scope: ApplicabilityScope
  validFrom / validTo / priority
  body: {language: cel|rego|static, source: string|json}
  outputSchema: JSON Schema
  combining: deny-overrides|permit-overrides|first-applicable|only-one-applicable|merge   # for this policy's layer stack
  obligations: [{id, kind: log|notify|redact|require-mfa|require-approval|attach-evidence, params}]
  state: draft|in-review|published|deprecated|retired
```

## 3. Layering

Layers are evaluated in **fixed constitutional order**: `constitutional → platform → regulatory →
tenant → organization → delegated`. A higher layer MAY mark a policy `final: true`, after which lower
layers for the same policy name are not evaluated. For authorization, a deny in `constitutional`,
`platform`, or `regulatory` cannot be overridden by any lower layer regardless of combining algorithm.

## 4. Algorithm (Policy Decision Point)

```
function Decide(policyName, input, ctx):
    D ← DecisionCache.get(policyName, inputDigest, ctxDigest, policyVersion(policyName))  ;  if hit: return
    results ← []
    for layer in LAYERS:
        P ← Resolve('policy', policyName, layer, ctx, cfg{cardinality: many})    # CIC-011-001 per layer
        if P = ∅: continue
        r ← Combine(P.combining, [Evaluate(p.body, input, ctx) for p in P ordered by rank])
        results += (layer, r)
        if any p ∈ P with final: break
        if kind = authorization and r = deny and layer ∈ {constitutional, platform, regulatory}: break
    out ← CombineLayers(kind, results)
          # authorization: deny if any deny; allow only if ≥1 allow and no deny; else default (deny)
          # configuration: deep-merge from constitutional to delegated, lower layers override unless field locked by higher layer (`$locked`)
          # constraint: union of violations
    record ← DecisionRecord{id, policyName, versions, inputDigest, ctxDigest, out, obligations, trace, at}
    persist record if kind = authorization and (out = deny or policy.audit = always) or regulated
    DecisionCache.put(...)   # TTL = min(policy.cacheTtl, 60 s) for authorization; version-keyed for configuration
    return out
```

Default for missing authorization policy: **deny** (PRIN-010). Default for missing configuration
policy: `E-POL-NO-CONFIG` (fail closed), never an in-code default (PRIN-016).

## 5. Enforcement points (PEP)

- Every command handler calls `Decide(<context>.<command>, {principal, resource, action, attrs}, ctx)`
  before loading the aggregate for write (cheap fail) and MAY re-check after load with resource attributes.
- Every query applies field-level obligations (`redact`) to responses.
- PDP is embedded (library, bundle sync) in every service; remote PDP only for policies marked `remoteOnly`.
- Bundle distribution: policies compiled into signed bundles per tenant; services pull on
  `policy.published` events, verify signature (cosign/Sigstore), and hot-swap atomically.

## 6. Certification Rules

- **CR-009-001-01** Layer precedence test suite: regulatory deny is never overridden by tenant allow across all combining algorithms.
- **CR-009-001-02** Every command endpoint in every service is covered by a PEP call (static route scan + runtime test with deny-all bundle → 100 % of commands return 403).
- **CR-009-001-03** Embedded Decide p99 ≤ 1 ms (cache hit) and ≤ 5 ms (miss).
- **CR-009-001-04** Bundle signature verification failure causes the service to keep the last-good bundle and raise a Sev-2 alert.

## 7. Validation Rules

- **VR-009-001-01** Every policy body compiles and its output validates against outputSchema for the policy's test vectors.
- **VR-009-001-02** Every policy URN referenced anywhere in the corpus exists in ucos.std pack or is declared as tenant-supplied.
