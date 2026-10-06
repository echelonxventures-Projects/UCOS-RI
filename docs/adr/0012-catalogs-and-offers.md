# ADR 0012 — Catalogs (DOM-CAT) and offers (DOM-OFR) in commerce-service

- Status: accepted
- Date: 2026-10-06
- Slice: S3d (CIC-030-001 §3), which completes S3
- Related: ADR 0011 (commerce-service, COB, REL, PRC), AR-0005 G7–G12

## Context

S3 closes with DOM-CAT and DOM-OFR and the exit demonstration: create a Product and a Subscription from pack types,
then resolve a catalog with prices in 3 markets × 2 channels without code changes. Both contexts depend on COB, REL
and PRC, and both name rule fact kinds (catalog-exclusion, catalog-ordering, eligibility, configuration-constraint)
that DOM-RUL owns. DOM-RUL is not built yet.

## Decisions

1. **Two more contexts in commerce-service.**
   - `cat/` and `ofr/` each have their own package, schema (`ucos_catalog`, `ucos_offer`) and migrations directory.
   - They reach COB, REL and PRC only through ports wired in `cmd/commerce-service` (`ports.go`). The architecture
     test forbids cross-imports and type-name literals in both (UCOS-L001).

2. **Selectors are compiled CEL with a dependency set (INV-CAT-2).**
   - A selector sees `object` (`id`, `typeRef`, `lineage`, `values`: the universal-context view, RUL-CAT-2),
     `relations` (current outgoing relationships by type) and `classifications` (empty until DOM-CLS).
   - The PDP gained `References`: it walks the checked CEL AST and returns the maximal field paths a selector reads.
     Those become `selector_dependencies` (attribute, relation, type, classification, variant). Unknown attributes
     and relationship types are rejected when the selector is defined.

3. **Membership is materialized two ways under one lock (CIC-011-005 §3).**
   - PublishCatalog moves the catalog to `materializing` and emits `materialization-requested`. Its consumer
     evaluates the pending definition over all objects into the next generation. It also rebuilds every serving
     catalog that composes it, because their membership derives from its definition. The swap happens in the same
     transaction.
   - Object and relationship events re-evaluate one object, in place in the current generation, against the
     serving catalogs whose dependency set the change touches.
   - Both paths take one per-tenant advisory lock and read facts inside it, so an event applies either before a
     rebuild reads the object or after it commits.
   - The consumer is an in-process subscriber of the outbox relay. `svc.Relay` gained `Subscribers`, which run
     after HTTP sinks; a row is marked published only when all accepted it. `processed_messages` makes the consumer
     idempotent. In the cell profile the same handler sits behind the bus.
   - The unit test `TestIncrementalEqualsFull` checks CR-011-005-01 at domain level: 2,000 random sequences of 50
     changes (10⁵ changes) give the same membership incrementally as by full evaluation. The black-box test
     compares event-maintained membership with a full re-materialization.

4. **Generations and page sequences (CR-CAT-02, INV-CAT-3).**
   - A catalog row keeps the working definition (`body`), the frozen serving version with its navigation
     (`serving`) and the version being built (`pending`).
   - Editing a published catalog (definition or navigation) opens a draft of the next version. The serving version
     keeps serving until the next swap. This realizes INV-CAT-3 ("edits create a new version") although DOM-CAT's
     state machine has no `published → draft` edge (AR-0005 G11).
   - Cursors carry the generation of every applicable catalog. Superseded generations stay readable for 24 h
     (`ucos_catalog.generations`); after that a cursor answers `410 E-CAT-CURSOR-EXPIRED`.

5. **ResolveCatalog (CIC-011-005 §2).**
   - Steps 1–2: serving catalogs are resolved through the context runtime under `catalog.resolution`
     (cardinality many, fallback chains). Eligibility is checked with the PDP (`catalog.eligibility` by default,
     with resource `{audience, contractParty}`).
   - Step 3 reads materialized membership.
   - Step 4 filters by lifecycle category per `catalog.visible-states`. The owner branch needs DOM-ENT and owns
     nothing until S5.
   - Step 6 enriches with the request-context view and, with `include=price`, a one-unit DOM-PRC price per member
     (`null` when none resolves).
   - When nothing applies, the response is empty with `UCOS-Catalog-Fallback: none`. There is never a global
     catalog (RUL-CAT-3).
   - Not built: step 5 exclusions and step 8 merchandising rules (DOM-RUL); availability (DOM-AVL, S4) answers
     `null`; facets come from DOM-SRC.

6. **Offers use the interpreted ucos.std `offer` lifecycle and immutable versions.**
   - Offers are versioned rows (`(tenant, id, version)`). Revising a published or withdrawn version opens the next
     version as a draft, and published versions never change (INV-OFR-3).
   - Transitions fire through the lifecycle runtime: `submit`, `revise`, `approve`, `schedule`, `publish`,
     `withdraw`. The `go-live` timer is evaluated at read, as for price lists.
   - Withdraw targets the selling version, so a newer draft is not affected.

7. **Configurator (DEC-OFR-1, RUL-OFR-1).**
   - Slot usage is a boolean CSP: `requires`, `excludes`, `minQty > 0`, plus partial selections (2-SAT with unit
     clauses). It runs arc consistency with deterministic backtracking that prefers defaults.
   - Options per slot (can it be used, can it be left out) come from one solve per slot and value. Quantities and
     domains are checked exactly by `Check`.
   - CR-OFR-01 is a unit test: on 10⁴ random offers of up to 8 slots, consistency, options and validity equal
     brute-force enumeration, and every valid configuration passes `Check`.
   - Nested `children` configurations are refused with a violation until bundles of offers are modelled.

8. **Price coverage scan and approval plan (INV-OFR-4, CR-OFR-02).**
   - The scan prices every object of every chargeable slot, with the `offer` dimension, in every context of the
     scope lattice (the product of `eq`/`in` constraints).
   - Currency comes from the context when the scope fixes it. Otherwise any currency of the referenced price lists
     counts, or of all published lists when none is referenced.
   - Gaps block submission. The report stays on the offer as evidence.
   - The same scan measures `maxDiscountVsListPercent` (offer-scoped price against list price), which selects the
     `offer.publish-approval` tier.

9. **Approval as a domain command (AR-0005 G8).**
   - DOM-CAT and DOM-OFR say `in-review → approved` is triggered by an approved ChangeSet. The RI's governance
     plans approvals from `governance.approval` by risk class, whereas `offer.publish-approval` plans by discount.
     No governed kind is defined for catalogs or offers either.
   - Like PRC's ApprovePriceList, the RI therefore serves `POST …:approve` with `{decision, comment}`. Offers
     follow the `offer.publish-approval` stages (route permission `offer.read`; the stage roles decide). Catalogs
     need one approver with `catalog.publish`.
   - Author and submitter never approve. RI events `ucos.catalog.catalog.{approved,rejected,materialization-requested}.v1`
     and `ucos.offer.offer.{approved,rejected,approval-recorded}.v1` record the decisions.

10. **Rules wait for DOM-RUL (AR-0005 G7).**
    - Catalog inclusion and exclusion rules, offer constraints, eligibility rules and transition eligibility rules
      are RuleUrns of DOM-RUL fact kinds. Until DOM-RUL exists they are refused with `E-…-RULES-UNAVAILABLE`
      rather than silently ignored.
    - Slot-level `requiresSlots` and `excludesSlots`, which are part of OfferSlot itself, are fully enforced.
    - Eligibility (RUL-OFR-2) collects deny reasons with registry codes (`R-OFR-NOT-ELIGIBLE`): not published or
      not yet live, withdrawn, outside validity, outside scope. Entitlement conflicts wait for DOM-ENT.

## Consequences

- The S3 exit demonstration passes with metadata, price lists, a catalog and a selector only.
- Materialization blocks the commerce relay while a catalog rebuilds. This is acceptable for ucos-lite volumes.
  The L2 path (CR-CAT-03, 5,000 changes/s) needs the cell-profile bus consumer and partitioned membership (S6).
- Time-driven relationship validity (`validFrom` in the future) is not an event. A relationship that becomes
  active by time alone is seen at the next change of its source object or at the next re-materialization.
