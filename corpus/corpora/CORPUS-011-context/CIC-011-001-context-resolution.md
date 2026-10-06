---
id: CIC-011-001
title: Context Model and Context Resolution Algorithm
version: 1.2.0
status: normative
authority: Chief Architect
corpus: CORPUS-011
dependencies: [CIC-000-001, CIC-000-002]
traces: [PRIN-006, PRIN-017, PRIN-020, PRIN-021, DOM-CTX]
certification: [CR-011-001-01, CR-011-001-02, CR-011-001-03, CR-011-001-04]
validation: [VR-011-001-01, VR-011-001-02]
---

# CIC-011-001 — Context Model and Context Resolution Algorithm

This is the single algorithm by which UCOS selects *which contextual fact applies*. Attribute values,
prices, catalog membership, availability rules, localized text, policies, and rules are all
"contextual facts" and are all resolved here (PRIN-006). Specialized resolvers (CIC-011-002…006)
call this algorithm and only add fact-kind-specific post-processing.

Annex CIC-011-007 (normative, AMD-0004) restates this algorithm as executable semantics. It decides the details that
would otherwise make implementations disagree byte-for-byte: canonical JSON output, integer-only arithmetic,
instant format, specificity evaluation order, fallback order and the conformance runner protocol. Where this text
leaves a detail open, the annex governs.

## 1. Model

### 1.1 ContextDimension (aggregate, DOM-CTX)

```yaml
ContextDimension:
  urn: urn:ucos:<ns>:dim:<code>@<semver>      # e.g. urn:ucos:ucos.std:dim:market@1.0.0
  code: string                                 # ^[a-z][a-z0-9-]{1,31}$
  valueType: enum | hierarchical-enum | range | instance-ref | boolean
  valueSource: {kind: taxonomy|party|geo|registry|instance|inline|plugin, ref: urn}   # where valid values live
  hierarchy: {relTypeRef: urn}?                # for hierarchical-enum: parent edges (e.g. geo: city→region→country→continent)
  weight: integer 1..1000                      # specificity weight (higher = more specific when matched)
  defaultPrecedence: integer                   # tie-break ordering among dimensions (lower = considered first)
  required: boolean                            # if true, resolution fails when absent and no default
  default: value?                              # used when absent and required=false
  sensitivity: DataClassification             # e.g. party-segment may be personal
```

`ucos.std` dimensions (data, not code — PRIN-020/021): `tenant, market, territory, jurisdiction,
geo, channel, touchpoint, locale, currency, party, party-segment, organization, contract, role,
device, time, campaign, fulfillment-node, sales-org, price-list-tier`. Tenants add dimensions freely.

### 1.2 ContextVector (kernel VO)

An immutable map `dimensionCode → ContextValue` plus `asOf: Instant` (the evaluation instant; the
`time` dimension). `ContextValue = {value, source: explicit|derived|default, confidence: 0..1}`.

Canonical form: keys sorted, values normalized (locale BCP-47 canonical, geo codes uppercase).
`contextDigest = sha256(canonical-JSON(vector without asOf)) || floor(asOf / cacheGranularity)`.

### 1.3 ApplicabilityScope (kernel VO)

A conjunction of constraints; empty = universal.

```
Scope      := Constraint*            (AND)
Constraint := {dimension, op, values}
op         := eq | in | not-in | descendant-of | range | exists
```

Each scoped fact also has `validFrom`, `validTo` (half-open `[from, to)`), `priority` (int, default 0),
and `factKind`.

## 2. Context assembly (before resolution)

`AssembleContext(request) → ContextVector`

1. Start with explicit values from the `UCOS-Context` header / API parameters (§6).
2. Add principal-derived values: `tenant`, `party`, `organization`, `role` from the authenticated token.
3. Apply **derivation rules** (Rules of factKind `context-derivation`, DOM-RUL) in topological order of
   their declared input→output dimensions, e.g. `geo → territory`, `territory → jurisdiction`,
   `territory → currency` (if absent), `party → party-segment`, `channel+territory → price-list-tier`.
   Derived values never override explicit values unless the rule is marked `authoritative: true`
   (e.g. `jurisdiction` derived from verified ship-to always overrides caller-supplied jurisdiction).
4. Apply dimension defaults for absent non-required dimensions.
5. Fail with `E-CTX-REQUIRED-MISSING` if a required dimension is absent.
6. Validate each value against the dimension's `valueSource`; invalid → `E-CTX-INVALID-VALUE`.
7. Return vector with `asOf` = request `asOf` or server now.

## 3. Resolution algorithm

`Resolve(factKind, subjectRef, key, ctx: ContextVector, cfg: ResolutionConfig) → Resolution`

`ResolutionConfig` comes from the policy `urn:ucos:…:policy:<factKind>.resolution` (PRIN-005) and contains:
`dimensionPrecedence[]`, `conflictStrategy`, `fallbackChains`, `cardinality: one|many`, `relaxationAllowed`.

```
function Resolve(factKind, subject, key, ctx, cfg):
    C ← CandidateStore.fetch(factKind, subject, key)                 # index lookup, §5
    # Phase 1 — temporal filter
    C ← { c ∈ C | c.validFrom ≤ ctx.asOf < c.validTo }
    # Phase 2 — scope match
    M ← { c ∈ C | Matches(c.scope, ctx) }
    # Phase 3 — fallback / relaxation
    if M = ∅ and cfg.relaxationAllowed:
        for step in FallbackSequence(ctx, cfg):                      # §3.3
            M ← { c ∈ C | Matches(c.scope, step.ctx) }
            if M ≠ ∅: record fallbackPath ← step.path; break
    if M = ∅: return NotFound(trace)
    # Phase 4 — rank
    for c ∈ M: c.rankKey ← ( Specificity(c.scope, ctx), c.priority, c.validFrom, -Ordinal(c.id) )
    sort M by rankKey descending (lexicographic)
    # Phase 5 — conflict handling
    if cfg.cardinality = many: return Many(M, trace)
    top ← { c ∈ M | (Specificity, priority) of c equals that of M[0] }
    if |top| = 1: return One(M[0], trace)
    return ApplyConflictStrategy(cfg.conflictStrategy, top, trace)   # §3.4
```

### 3.1 Matching

```
Matches(scope, ctx) = ∀ k ∈ scope: Satisfies(k, ctx[k.dimension])
Satisfies(k, v):
   v absent              → false (except op = not-in → true)
   eq                    → v = k.values[0]
   in                    → v ∈ k.values
   not-in                → v ∉ k.values
   descendant-of         → v = x or IsDescendant(v, x) for some x ∈ k.values   (dimension hierarchy, PRIN-017)
   range                 → k.values[0] ≤ v < k.values[1]
   exists                → true
```

### 3.2 Specificity

```
Specificity(scope, ctx) = Σ_{k ∈ scope} dim(k).weight × OpFactor(k) × DepthFactor(k, ctx)
OpFactor:      eq = 1.00, in = 1.00 / |values|^0.5, range = 0.75, descendant-of = 0.50, not-in = 0.10, exists = 0.05
DepthFactor:   descendant-of only: (depth(x) + 1) / (depth(v) + 1)   where x is the matched ancestor
               (matching the leaf itself = 1.0; matching a country when ctx is a city = smaller)
```

Specificity is computed as an integer by multiplying by 10⁶ and truncating, so comparisons are exact
and portable across implementations. Universal scope has specificity 0.

**Dimension precedence override**: if `cfg.dimensionPrecedence` is non-empty, ranking uses the
lexicographic tuple `(matched?(d₁), matched?(d₂), …, Specificity, priority, …)` instead of the plain
sum — i.e. a fact matching the first-precedence dimension always beats one that does not, regardless of
weights. This is required for regulated fact kinds (e.g. tax: jurisdiction first).

### 3.3 Fallback sequence

`FallbackSequence(ctx, cfg)` yields relaxed contexts in this exact order:

1. For each dimension `d` in `cfg.fallbackChains` order, for each ancestor `a` of `ctx[d]` (nearest first):
   yield `ctx[d := a]` with path `d:<value>→<a>`. (Example locale: `fr-CA → fr → und`; geo:
   `FR-75056 → FR-IDF → FR → EU`.)
2. Then, for each dimension `d` in **reverse** precedence order with `required=false`: yield `ctx \ {d}`
   (drop the least important dimension first).
3. Stop at the first step producing a non-empty match. The total number of steps is bounded by
   `cfg.maxFallbackSteps` (default 32); exceeding → `NotFound` with `E-CTX-FALLBACK-EXHAUSTED`.

### 3.4 Conflict strategies

| Strategy | Behavior | Default for |
|----------|----------|-------------|
| `error` | Return `E-CTX-AMBIGUOUS` with candidate IDs; data defect raised to DOM-DQL | price-entry, tax-rate, policy |
| `most-recent` | Choose greatest `validFrom`, then greatest ULID | attribute-value |
| `lowest-value` / `highest-value` | Numeric comparison of fact value (money-aware) | promotion amounts (customer-favorable) |
| `merge` | Deep-merge objects in rank order; scalars from first | UI layout, configuration |
| `all` | Return all tied candidates | catalog membership, eligibility |
| `policy:<urn>` | Delegate to PDP decision with candidates as input | custom |

Determinism requirement: for identical (store snapshot, ctx, cfg), Resolve MUST return identical output
on every node (CR-011-001-01).

## 4. Resolution trace (explainability)

Every `Resolution` carries a trace when `explain=true` (always captured internally, sampled 1 % to
telemetry, 100 % when the fact kind is regulated):

```json
{"factKind":"price-entry","contextDigest":"…","candidates":42,"afterTemporal":17,"matched":3,
 "fallbackPath":["locale:fr-CA→fr"],"ranking":[{"id":"…","specificity":1850000,"priority":0}],
 "conflict":null,"selected":"…","configRef":"urn:ucos:ucos.std:policy:price-entry.resolution@1.2.0"}
```

## 5. Candidate indexing

Candidate stores MUST index scoped facts so that `fetch` returns ≤ 1,000 candidates for p99 subjects:

- Primary key `(tenant, factKind, subject, key)`.
- Secondary bitmap/inverted index on `(dimension, value)` per constraint with `eq`/`in`; facts with
  hierarchical constraints indexed under each listed node; facts with no constraint on a dimension
  indexed under `*`. Fetch = union over `*` and the context's value + ancestors for each dimension,
  intersected across dimensions.
- When candidates exceed 10,000 for a subject, the store MUST pre-partition by the highest-weight
  dimension.

## 6. Context transport

- HTTP header `UCOS-Context: <base64url(canonical JSON)>`; optional `UCOS-As-Of: <RFC3339>`.
- gRPC metadata `ucos-context-bin`.
- Events carry the resolved context digest and the full vector in extension `ucoscontext` when the
  event's meaning depends on it (e.g. `order.placed`).
- Personal-data dimensions (`party`, `party-segment`) MUST NOT be logged in clear; telemetry records
  only the digest.

## 7. Caching

Specified in CIC-011-003. Summary: result cache keyed `(factKind, subject, key, contextDigest,
storeVersion(subject))`; `storeVersion` is a per-subject monotonic counter incremented by every fact
write event; therefore no TTL-based staleness for correctness, TTL only for memory pressure.

## 8. Certification Rules

- **CR-011-001-01** Determinism: the module under test produces Resolutions byte-identical (excluding timing) to the published golden vectors and to every certified `ucos-context-runtime` implementation (any language, CIC-001-001 §1.1) for 10⁶ generated (store, ctx, cfg) cases.
- **CR-011-001-02** Metamorphic test: adding a candidate with universal scope never changes the result when a more specific candidate matched.
- **CR-011-001-03** Fallback test suite: every ucos.std dimension hierarchy fallback order matches §3.3 exactly.
- **CR-011-001-04** Performance: Resolve p99 ≤ 2 ms in-process with ≤ 1,000 candidates; ≤ 8 ms including candidate fetch from a warm cache.

## 9. Validation Rules

- **VR-011-001-01** Every ResolutionConfig policy references only dimensions that exist and declares a conflict strategy from §3.4.
- **VR-011-001-02** Every hierarchical-enum dimension's hierarchy relationship type is acyclic (DOM-ONT reltype `acyclic: true`).
