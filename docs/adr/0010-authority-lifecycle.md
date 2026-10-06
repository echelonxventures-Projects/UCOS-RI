# ADR 0010: Authority lifecycle — tenant roles, approval, access reviews, mandate usage, idempotency, exact cut-offs

- Status: accepted (2026-10-06)
- Traces: DOM-AUTH 1.2.0 (INV-AUTH-1, RUL-AUTH-3, CR-AUTH-04, CR-AUTH-05), CIC-002-003 §8-12, CIC-005-001,
  CIC-015-001 1.1.0 §1, AMD-0004, ADR 0009

## Decisions

1. **Corpus first.** AR-0002, AR-0003 and AR-0004 are adopted as corpus 1.4.0 (AMD-0004). The RI's semantics
   documents became normative annexes (CIC-011-007, CIC-006-002, CIC-002-003). DOM-AUTH 1.2.0 adds the missing
   commands, so `contracts/party/DOM-AUTH.*` are regenerated rather than hand-extended.
2. **Tenant roles are governed definitions owned by DOM-AUTH** (kind `role`, table `ucos_party.role_definitions`), like
   SoD sets and limits.
   - metadata-service merges a tenant's published roles into its role catalog, with `includes` flattened, so every
     PEP grants them without change. The tenant roles come from the remote owner, cached for 2 s and invalidated when a
     ChangeSet finishes. When identity-service is unreachable the catalog degrades to pack roles, which only narrows
     access.
   - identity-service bypasses its own catalog cache for 5 s after publishing a role.
   - A role can include only roles that already exist, and published roles are immutable, so the include graph is
     acyclic by construction.
3. **Approval** is a state of the assignment (`pending-approval → active | rejected`); only `active` assignments are
   facts. The approver needs `authority.role.assign` and AAL2, must differ from the requester and the assignee, and
   must hold one of `assignable.approverRoles`. SoD is re-checked at approval under the per-party lock.
4. **Suspension is derived, not scheduled.** An assignment is suspended from `certification base + review interval`
   (by role sensitivity). Every evaluation excludes it, and token horizons include that instant. No timer job is
   needed, and certification ("keep") ends the suspension at once. ucos-lite has an adjustable, forward-only authority
   clock (`POST /internal/clock` on the admin port, `UCOS_CLOCK=adjustable`) so the suite can cross 90 days.
5. **Mandate usage** locks the mandate row, so concurrent usage can never overdraw it. Usage is idempotent per
   reference; the same reference with a different amount is a conflict. Reaching the total exactly makes the mandate
   `exhausted`.
6. **Idempotency-Key replay** (identity-service commands):
   - The caller is authenticated once and the principal reused, because a DPoP proof is single-use.
   - A key is bound to the principal and to a request hash: a different request or principal gets `422
     E-API-IDEMPOTENCY-MISMATCH`, and a concurrent duplicate gets `409 E-API-IDEMPOTENCY-IN-PROGRESS`.
   - Responses are sealed under the KEK, because they can carry one-time secrets (agent client secrets). 5xx responses
     are not kept. The key is optional for now; requiring it is a client-facing change left for a later slice.
7. **Exact revocation cut-offs.**
   - Every token carries `ucos_auth_at`: the database clock in milliseconds, read before any authority fact.
   - The cut-off is stamped after the narrowing change commits, so a token whose authority was read afterwards is
     never rejected. The feed field is `notBeforeMs`.
   - Exchanged agent tokens take the earlier of the subject's and the delegation's read instant.
   - Agent actor tokens confer no API authority and are exempt from party cut-offs.

## Consequences
- The S2c suite runs without its former sleeps and retries, which demonstrates the exact cut-offs. The S2d suite adds
  7 tests.
- Mutants that remove the mandate row lock, or that disable suspension, are killed.
- Still open: per-period delegation limits (they need a consuming context, S4). Requiring Idempotency-Key on identity
  commands is a client-visible change, deferred.
