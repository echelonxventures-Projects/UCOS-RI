---
id: CIC-011-004
title: Pricing Resolution Algorithm
version: 1.0.0
status: normative
authority: Chief Product Architect
corpus: CORPUS-011
dependencies: [CIC-011-001, CIC-011-003]
traces: [PRIN-005, PRIN-006, PRIN-016, DOM-PRC]
certification: [CR-011-004-01, CR-011-004-02, CR-011-004-03, CR-011-004-04, CR-011-004-05]
validation: [VR-011-004-01, VR-011-004-02]
---

# CIC-011-004 — Pricing Resolution Algorithm

## 1. Inputs and outputs

```
PriceRequest  = {ctx: ContextVector, lines: [PriceLineRequest], options: {explain, includeTax, roundingStage}}
PriceLineRequest = {lineId, objectRef: InstanceUrn, offerRef?: InstanceUrn, quantity: Quantity,
                    configuration?: {slot → [PriceLineRequest]}, term?: {duration, billingPeriod},
                    usage?: [{meter, quantity}], contractRef?: InstanceUrn}
PriceResult   = {lines: [PricedLine], totals: Totals, currency, pricingSnapshotId, trace?}
PricedLine    = {lineId, components: [PriceComponent], subtotal, discountTotal, taxTotal, total,
                 recurring: [RecurringCharge], usageRating: [RatedUsage]}
PriceComponent = {kind: base|adjustment|tax|fee|rounding, chargeType: one-time|recurring|usage,
                  amount: Money, sourceRef, phase, reasonCode, label: LocalizedText}
```

## 2. Model (owned by DOM-PRC)

- **PriceList** (aggregate): set of PriceEntries with a default ApplicabilityScope and currency.
- **PriceEntry**: `{subject: objectRef|typeRef|selector, chargeType, priceModel, scope, validFrom,
  validTo, priority}`.
- **PriceModel** (VO, extensible): `flat{amount}`, `per-unit{amount, unit}`,
  `tiered{tiers:[{upTo, unitAmount, flatAmount}], mode: graduated|volume}`,
  `stair-step{steps}`, `percentage-of{baseRef, percent}`, `formula{cel}`,
  `plugin{pluginRef, config}`. Formula CEL has access to `line`, `ctx`, `object` (resolved view), and
  `quantity`; cost limit 5,000; no I/O.
- **PriceAdjustment** (Rule of factKind `price-adjustment`, DOM-RUL): `{phase, condition: CEL,
  effect: percent|amount|override|fixed-price|free-units, target: line|order|component-kind,
  stackingGroup, exclusive, maxApplications, budgetRef?}`.
- **Phases** are metadata (policy `pricing.phases`); ucos.std order:
  `10 LIST → 20 CONTRACT → 30 SEGMENT → 40 PROMOTION → 50 BUNDLE → 60 LOYALTY → 70 MANUAL → 80 FEES → 90 TAX`.

## 3. Algorithm

```
function Price(req):
    ctx ← AssembleContext(req.ctx)                                     # CIC-011-001 §2
    currency ← ctx.currency  (required for pricing)
    snapshot ← PricingStore.snapshotVersion(tenant)                    # consistent read
    lines ← expand(req.lines)                                          # flatten configuration tree; child lines tagged parent
    for line in lines (post-order: children before parents):
        # Step 1 — base price
        base ← Resolve('price-entry', line.objectRef, line.chargeType*, ctx ⊕ {contract: line.contractRef},
                       cfg = policy(price-entry.resolution))           # conflict default: error
        if base NotFound: base ← Resolve('price-entry', typeOf(line.objectRef), …)   # type-level price
        if base NotFound and line.parent ≠ ∅ and parentIncludesChildren(line): base ← zero(currency)
        if base NotFound: fail E-PRC-NO-PRICE(line)
        if base.currency ≠ currency: base ← Convert(base, currency, ctx)       # §4
        line.components += Evaluate(base.priceModel, line, ctx)
    # Step 2 — adjustments, by phase
    for phase in Phases(ctx) where phase < TAX:
        A ← Resolve('price-adjustment', tenant, phase, ctx, cfg{cardinality: many})
        A ← { a ∈ A | CEL(a.condition, {lines, ctx, order}) = true }
        A ← ApplyStacking(A)                                            # §3.1
        for a in A ordered by (exclusive desc, priority desc, id):
            apply a to targets; append adjustment components; decrement budget (reservation, §5)
        Clamp: no line subtotal below floor policy(pricing.floor) (default 0); record clamps in trace
    # Step 3 — rounding (§3.2)
    # Step 4 — tax (if includeTax): delegate to DOM-TAX Tax Calculation API with taxable lines;
    #          append tax components returned (TAX phase)
    totals ← Sum(lines)
    return PriceResult(lines, totals, currency, pricingSnapshotId = hash(snapshot, ctxDigest, req), trace)
```

### 3.1 Stacking

Within a phase: adjustments sharing a `stackingGroup` are mutually exclusive — keep the one with the
best value for the customer unless the group's policy says `best-for-seller` or `highest-priority`.
An adjustment with `exclusive: true` removes every other adjustment in the same phase targeting the
same line. Across phases, adjustments compound in phase order (percentages apply to the running
subtotal after the previous phase).

### 3.2 Rounding

Policy `pricing.rounding` per currency and scope: `{mode: half-even|half-up|down|up|cash(increment),
stage: component|line|total, psychological?: {endings: [0.99, 0.95], applyTo: list-phase-only}}`.
Default: half-even at `line` stage to the currency's ISO-4217 minor units; intermediate calculations
use 18-digit scale decimal. Rounding differences are emitted as explicit `rounding` components so
`Σ components = total` exactly.

## 4. Currency conversion

Only if no price entry exists in the requested currency and policy `pricing.conversion.allowed` is true.
Rate source: DOM-ACC FX rate table, `rateType` from policy (spot|daily-close|contract), as of `ctx.asOf`.
Converted prices are marked `converted: true` with `rateRef` in the component.

## 5. Determinism, quotes, and budgets

- `Price` is a pure function of (snapshot, ctx, req) except budget reservations; given the same
  `pricingSnapshotId`, the price is reproducible indefinitely (snapshots retained ≥ 10 years for
  audit, CIC-003 retention).
- Quotes (DOM-QTE) persist `pricingSnapshotId` + result; order placement re-prices against the
  quote's snapshot if the quote is valid, otherwise against current snapshot.
- Budgeted adjustments (promotion budgets, coupon redemption limits) use a reservation
  (`reserve → commit|release`, TTL 30 min) against DOM-CMP; simulation calls (`options.simulate`) never reserve.

## 6. Recurring and usage

- Recurring charges carry `{period, alignment: anniversary|calendar, prorationPolicyRef}`.
- Usage rating: for each usage meter, resolve `price-entry` with `chargeType=usage` and evaluate the
  priceModel against the period-to-date cumulative quantity (graduated tiers are period-scoped).

## 7. Certification Rules

- **CR-011-004-01** Golden-file suite (≥ 500 scenarios across flat, tiered, volume, bundle, contract, promotion stacking, multi-currency, proration) matches expected results exactly.
- **CR-011-004-02** Property test: Σ(components) = total for every line and the order, in minor units, for 10⁶ random requests.
- **CR-011-004-03** Replay test: re-pricing with a stored `pricingSnapshotId` reproduces the original result byte-for-byte.
- **CR-011-004-04** Price(100 lines) p99 ≤ 80 ms excluding external tax; ≤ 250 ms including tax adapter.
- **CR-011-004-05** No floating-point types in pricing code paths (UCOS-L002).

## 8. Validation Rules

- **VR-011-004-01** Every price-adjustment rule references an existing phase and a stackingGroup or `exclusive` flag.
- **VR-011-004-02** Every PriceList currency is a registered currency in DOM-ACC.
