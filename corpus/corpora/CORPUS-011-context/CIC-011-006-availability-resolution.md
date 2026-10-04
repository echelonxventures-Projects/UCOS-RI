---
id: CIC-011-006
title: Availability Resolution Algorithm
version: 1.0.0
status: normative
authority: Chief Systems Engineer
corpus: CORPUS-011
dependencies: [CIC-011-001, CIC-011-003]
traces: [PRIN-006, PRIN-015, DOM-AVL, DOM-INV]
certification: [CR-011-006-01, CR-011-006-02, CR-011-006-03]
validation: [VR-011-006-01]
---

# CIC-011-006 — Availability Resolution Algorithm

Availability unifies physical stock, capacity (services, experiences, seats), licence pools, and
regulatory/commercial sellability. Each object's type facets determine which **availability sources**
apply: `Stockable → inventory`, `CapacityBound → capacity calendar`, `Entitling → licence pool`,
all types → `sellability rules`.

## 1. Output

```
AvailabilityResult = {objectRef, status: available|limited|backorder|preorder|unavailable|not-sellable,
                      atp: Quantity?, promiseDate?: Date, nodes?: [{nodeRef, atp, leadTime}],
                      reasons: [ReasonCode], validUntil: Instant}
```

## 2. Algorithm

```
function ResolveAvailability(objects, ctx, qty?):
    for o in objects:
        # 1 Sellability (cheap; may short-circuit)
        s ← Resolve('sellability-rule', o, '-', ctx, cfg{cardinality: many, conflict: all})
        if any rule in s has effect=deny: emit not-sellable(reasons); continue
        # 2 Composite: availability of a composite = min over required components of (ATP_c / qty_per_parent)
        if o.composition: result ← combine(children results, min) ; continue
        # 3 Sources by facet
        if Stockable:
            nodes ← SourcingNodes(ctx)        # fulfillment-node dimension or sourcing policy (geo radius, ship-to territory)
            atp_n ← OnHand_n − Reserved_n − SafetyStock(n, o, ctx) + Σ InboundBefore(horizon)_n
            atp   ← Σ_n atp_n  (or best-node only when policy single-node-fulfillment)
        if CapacityBound:
            atp ← CapacityCalendar.free(o, ctx.timeWindow)
        if Entitling and pooled:
            atp ← Pool.remaining(o, ctx.organization)
        status ← classify(atp, qty, backorderPolicy, preorderPolicy)
        promiseDate ← earliest date where cumulative atp ≥ qty (inbound schedule + lead time + transit)
```

ATP read model is updated from inventory events (DOM-INV) with p99 ≤ 2 s lag. Order placement MUST
make a **reservation** (`ReserveInventory`, owned by DOM-INV, strongly consistent per (node, object))
— ResolveAvailability is advisory and never reserves.

## 3. Conflict & fallback

Sellability rules use conflict `all` with deny-overrides. Node selection fallback follows the
`fulfillment-node` dimension hierarchy (store → region DC → national DC → drop-ship partner).

## 4. Caching

ATP results cached with version key = inventory version per (object, node); `validUntil` = now + 30 s
for `limited` status, 5 min otherwise.

## 5. Certification Rules

- **CR-011-006-01** Oversell test: under 1,000 concurrent orders for an object with ATP = 100, committed reservations never exceed 100.
- **CR-011-006-02** Composite availability equals brute-force minimum over components on 10⁴ random BOMs.
- **CR-011-006-03** ResolveAvailability(50 objects) p99 ≤ 40 ms.

## 6. Validation Rules

- **VR-011-006-01** Every Stockable type has a sourcing policy resolvable in every active market context.
