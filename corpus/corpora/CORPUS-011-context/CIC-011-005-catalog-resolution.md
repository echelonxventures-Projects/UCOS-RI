---
id: CIC-011-005
title: Catalog Resolution Algorithm
version: 1.0.0
status: normative
authority: Chief Product Architect
corpus: CORPUS-011
dependencies: [CIC-011-001, CIC-011-002, CIC-011-003]
traces: [PRIN-006, PRIN-017, PRIN-018, PRIN-021, DOM-CAT]
certification: [CR-011-005-01, CR-011-005-02, CR-011-005-03]
validation: [VR-011-005-01]
---

# CIC-011-005 — Catalog Resolution Algorithm

## 1. Model (owned by DOM-CAT)

- **Catalog** (aggregate): `{id, label, scope: ApplicabilityScope, sources: [CatalogSource],
  structure: [NavigationNodeRef], inclusionRules, exclusionRules, eligibilityPolicyRef, state}`.
- **CatalogSource**: `{kind: explicit|selector|catalog, ref, includeDescendants}` —
  `selector` is a CEL predicate over resolved CommercialObject views and taxonomy classifications;
  `catalog` composes another catalog (DAG, acyclic).
- **NavigationNode**: a node in a navigation hierarchy (a HIER subgraph, PRIN-017) with its own
  selector and scope; a catalog may expose any number of navigation hierarchies.
- No catalog stores prices or stock; it references them at resolution time.

## 2. Algorithm

```
function ResolveCatalog(catalogRef?, ctx, page):
    # Step 1 — select applicable catalogs
    cats ← catalogRef ? [catalogRef] : Resolve('catalog', tenant, '-', ctx, cfg{cardinality: many})
    # Step 2 — eligibility (PDP)
    cats ← { c ∈ cats | PDP.decide(c.eligibilityPolicyRef, {party, ctx}) = allow }
    # Step 3 — membership (materialized, §3)
    members ← ⋃_{c ∈ cats} Membership(c, ctx.asOf)
    # Step 4 — lifecycle & sellability filters
    members ← { m | m.lifecycleState ∈ policy(catalog.visible-states) (default: active, end-of-sale-if-owned) }
    # Step 5 — contextual exclusions
    members ← members \ Resolve('catalog-exclusion', tenant, '-', ctx, cfg{cardinality: many})
    # Step 6 — enrichment (parallel, batched; each optional per request)
    views  ← COB.BatchResolveView(members, ctx)                 # attributes, localization
    prices ← PRC.Price(minimal lines, ctx)        if request.include ∋ price
    avail  ← AVL.Resolve(members, ctx)            if request.include ∋ availability
    # Step 7 — visibility rules on enriched data (e.g., hide if not available and policy says so)
    # Step 8 — ordering: merchandising rules (factKind 'catalog-ordering') then requested sort
    return page of results + facets (from search index when filtering/faceting is requested)
```

## 3. Membership materialization

Selector evaluation over 10⁹ objects at request time is forbidden. DOM-CAT maintains
`catalog_membership(catalog_id, object_id, valid_from, valid_to, source)` incrementally:

- On `commercial-object.*` and `classification.*` events: re-evaluate selectors of catalogs whose
  selector references a changed attribute/taxonomy (dependency index from compiled CEL AST).
- On catalog definition change: full re-materialization job, double-buffered (new generation
  swapped atomically when complete).
- Membership lag SLO: p99 ≤ 5 s from object change.

## 4. Fallback

If no catalog matches the context: fall back per CIC-011-001 §3.3 with `catalog.resolution` policy
fallback chains (typically `channel → default channel`, `territory → parent`). If still none, return
an empty catalog with `UCOS-Catalog-Fallback: none` — never a global unscoped catalog.

## 5. Certification Rules

- **CR-011-005-01** Membership produced incrementally equals full re-materialization on 10⁵ randomized change sequences.
- **CR-011-005-02** No catalog response contains an object whose lifecycle state is outside `catalog.visible-states` for that context.
- **CR-011-005-03** ResolveCatalog page (50 items, with price and availability) p99 ≤ 150 ms.

## 6. Validation Rules

- **VR-011-005-01** Catalog composition graph is acyclic; every selector compiles and references existing attributes/taxonomies.
