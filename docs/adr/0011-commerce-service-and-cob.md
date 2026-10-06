# ADR 0011: commerce-service composition, the shared service kit, the lifecycle runtime, and DOM-COB

- Status: accepted (2026-10-06)
- Traces: CIC-030-001 §2-3 (S3), CR-030-001-02, DOM-COB (INV-COB-1..6, RUL-COB-1..4, DEC-COB-1/2, CR-COB-01..04),
  CIC-007-001 §2, CIC-011-001, CIC-005-001, AR-0005

## Decisions

1. **One ucos-lite deployable for the commercial core.** `commerce-service` (`services/commerce/go`) composes COB now,
   and REL, CAT, PRC and OFR as their batches land.
   - This follows the precedent of metadata-service (seven kernel contexts) and identity-service.
   - Each context keeps its own package, schema and migrations directory. Contexts never import each other: an
     architecture test enforces it, and only `cmd/` wires the ports. The cell profile can therefore split them
     without code change (CR-030-001-02).
   - Service-level bookkeeping (Idempotency-Key records) lives in its own schema, `ucos_commerce`.
2. **Shared service kit (`platform/svckit/go`).** Business services share one kit; it started as a copy of the
   kernel's `platform` package, which stays independent so the kernel certifies on its own. It provides:
   - the route-table PEP, which refuses to start with an uncovered route;
   - a configurable route-to-context mapping for coarse scopes;
   - principals carrying organization (`ucos_org`) and kind (human/agent/system) for policies;
   - a metadata client: role catalog, policy bundle evaluated by the embedded PDP, types and effective schemas,
     attributes, dimensions as a context-runtime world, lifecycle models, evidence;
   - the outbox relay, and generic Idempotency-Key replay.
3. **Lifecycle-instance runtime (`platform/lifecycle/go`).** This is the S1 item deferred to "the first
   lifecycle-bearing aggregates". It implements CIC-007-001 §2.1 Fire:
   - the check order: unknown transition, then invalid state, then policy, then guard over
     `{aggregate, cmd, ctx, now}`, then requirements, then SoD against the aggregate's history;
   - composite-state descent, state invariants, and returned effects and timers;
   - run-to-completion of automatic transitions (chain ≤ 10).

   It is pure: the owning service supplies the PDP decision, evidence checks and persistence.
4. **DOM-COB has no type-specific code (CR-COB-04, UCOS-L001).**
   - The root type, policy names and the submit transition are composition-root configuration. Everything else comes
     from the effective schema, the type's identityStrategy (nearest in the linearization) and the lifecycle model.
   - An architecture test fails on ucos.std type-name literals in context code.
   - Values outside the effective schema are rejected (`E-COB-UNKNOWN-ATTRIBUTE`).
5. **Contextual values (INV-COB-2, RUL-COB-1).** Writes require `If-Match`; the aggregate row lock plus the revision
   check serialize them per object. Overlap of identical scopes is refused unless `supersede`, which closes the
   earlier entry. The concurrency test prepares tokens and proofs before racing 12 writers; a mutant without the
   revision guard is killed.
6. **Views (DEC-COB-1, CR-COB-02).** `ResolveCommercialObjectView` assembles the context from `UCOS-Context` and
   resolves each attribute with the shared context runtime under `cob.contextual-precedence`, with an optional
   trace. A 1,000-case property test checks it against an independent oracle.
7. **Variants (RUL-COB-2)** store only their axis values and key; resolution falls back to the master's candidates.
   **Composition (INV-COB-6, RUL-COB-3):**
   - shape and cardinality are validated, and cycles are detected over stored compositions;
   - a composite cannot be activated while a component is winding down or closed.
8. **Transition permissions** depend on the transition: `approve` and `reject` need `cob.approve`, others need
   `cob.transition`; then policy `cob.transition` decides. The `approve` requirement for evidence is met by an
   `approval` evidence item that the approver captured and that references the object.

9. **DOM-REL (S3b).**
   - Endpoints are resolved through a port: commercial objects in-process, parties through identity-service. Doing
     so needed identity's PEP to implement ADR 0008's platform-service read on behalf of `UCOS-Tenant`, which it
     lacked.
   - Constraint checks run under advisory locks: the whole type for acyclic types (cycles span any endpoints),
     otherwise the two endpoint keys.
   - The closure table of a hierarchical type is rebuilt from its edges inside the same transaction, so it always
     equals the recomputed closure.
   - Ending an edge sets `validTo`. Edges are never deleted, and ended edges are immutable.
   - GenerateVariants records `VARIANT_OF` edges through a port wired in the composition root.

## Corpus gaps (AR-0005)
- The ucos.std `commercial-object` activate guard reads `aggregate.launchAt`, but no attribute `launchAt` exists, so
  the guard never fails.
- Policy `cob.transition` grants `reject` to no role.
- GenerateVariants and RetypeCommercialObject have no API paths; the RI serves them as `:generate-variants` and
  `:retype`.
