---
id: CIC-002-003
title: Authority Executable Semantics
version: 1.0.0
status: normative
authority: Chief Architect
corpus: CORPUS-002
dependencies: [CIC-002-001, CIC-011-001, CIC-015-001]
traces: [DOM-AUTH, DOM-IDN, DOM-EVD]
certification: []
validation: []
---

# CIC-002-003 — Authority Executable Semantics

Normative annex to DOM-AUTH, adopted by AMD-0004 from the reference implementation (AR-0004). It restates the parent
specification as executable semantics: where the parent leaves a detail open that changes results, this annex
decides it, and every implementation in any language must agree with it. Clarifications introduced here are marked
in brackets (for example **[C1]**). Golden vectors and black-box suites live with the reference implementation
(CIC-030-001 §5.1). Paths in this annex such as `conformance/…` and `contracts/…` refer to the reference
implementation repository.

Normative for every implementation of the authority context. It makes DOM-AUTH decidable where the spec leaves
room. Raised as AR-0004 and adopted by the corpus as CIC-002-003 (AMD-0004, DOM-AUTH 1.2.0). Black-box suites:
`conformance/s2c/test_authority.py`, `conformance/s2d/test_reviews.py`. Design: ADR 0009, ADR 0010.

## 1. Facts

| Fact | Validity | Notes |
|------|----------|-------|
| RoleAssignment | half-open `[validFrom, validTo)`; `validTo` absent = open; only `active` assignments count (§9), and not while suspended (§10) | Revocation sets `validTo` to the revocation instant (history kept). `validFrom` in the past is clamped to now. |
| Delegation | `[validFrom, validTo)`, `validTo` required | Revoked delegations confer nothing. `parentDelegation` makes it a re-delegation. |
| AuthorityLimit | published only | `holder` is a party URN or a role code. Measures: `amount` (Money), `discountPercent`, `marginPercent` (integer 0..100). |
| SodConflictSet | published only | Members: `{role}` (role code) or `{action}` (a permission string). Mode `assignment` or `execution`. |
| Mandate | `active` until `validTo`, then `expired` | Terms are the content of signed evidence (§7). |

A role may be given as RoleUrn `urn:ucos:<ns>:role:<code>` or as its code; it is stored and compared as the code.
Role permissions come from the tenant's role catalog: the roles contributed by installed packs (DOM-META registry)
plus the tenant's own published role definitions (§12), with `includes` flattened.

## 2. Scope matching

A scope is an ApplicabilityScope (CIC-011-001 §1.3). A fact applies in context vector `C` iff
`ctxrt.Matches(scope, C)` (contracts/context-runtime/semantics.md): every constraint holds, and a constraint on a
dimension absent from `C` fails (except `not-in`). The empty scope is universal.

**Coarse evaluation** ignores scopes. Access tokens carry coarse authority only (DOM-IDN AccessTokenClaims "roles
(coarse)"); scoped decisions use GetEffectiveAuthority / CheckSigningAuthority with a context.

## 3. Effective authority (DEC-AUTH-1, RUL-AUTH-1)

For party `P` at instant `T` in context `C`:

```
roles(P)       = assignments of P valid at T whose scope matches C
rolePerms(P)   = ∪ registry[role].permissions for role in roles(P)
confers(d)     = ∅                                   if d revoked, not valid at T, or scope does not match C
               = d.permissions ∩ confers(parent)     if d has parentDelegation `parent` and parent.delegate = d.delegator
               = ∅                                   if d has a parent whose delegate is not d.delegator
               = d.permissions ∩ rolePerms(d.delegator)   otherwise (a root delegation)
effective(P)   = rolePerms(P) ∪ ∪{ confers(d) : d.delegate = P }
```

A root delegation passes on only the delegator's **own role** authority; authority received by delegation is passed
on only through an explicit re-delegation (`parentDelegation`). This keeps chain depth exact and makes cycles
impossible to exploit. Everything is computed from current facts, so delegated authority vanishes the moment the
delegator loses it (re-validation at use), without touching the delegation.

The **horizon** of an evaluation is the earliest `validTo` among the assignments and delegations that contributed
authority. Tokens never outlive it.

## 4. Granting delegations (INV-AUTH-4, INV-AUTH-5)

`GrantDelegation` by authenticated party `D` (the delegator is always the caller; agents cannot delegate):

1. `delegate ≠ D`; the delegate party exists.
2. With `parentDelegation p`: `p.delegate = D`, `p` is active now; depth = `p.depth + 1`; the delegate must not
   appear as a delegator anywhere in the chain from `p` to its root (no cycles). Without: depth = 1.
3. depth ≤ `authority.max-delegation-depth.maxDepth` (default 3).
4. Every requested permission ∈ base, where base = `confers(p)` for a re-delegation, else `rolePerms(D)` — coarse,
   at grant time. Otherwise `403 E-AUTH-DELEGATION-EXCEEDS-AUTHORITY`.

`RevokeDelegation` revokes the delegation and every delegation below it (`cascaded[]`). Allowed for any delegator
in the chain above it, or a holder of `authority.review.manage`.

## 5. Segregation of duties (INV-AUTH-2, DEC-AUTH-2, RUL-AUTH-2)

Holding a role `r` holds member `m` of a set iff `m.role = r` or `m.action ∈ registry[r].permissions`.

A new assignment `n` conflicts with assignment-mode set `S` iff `n` alone holds two members of `S`, or some existing
assignment `a` of the same party with overlapping validity and **overlapping scope** holds a member of `S` such that
`n` and `a` together hold two distinct members.

Scope overlap is conservative: two scopes are disjoint only when, for some dimension, both restrict it to finite value
sets (`eq`/`in`) without a common value, or one allows only values the other excludes (`not-in`). Every other
combination overlaps. Conflict checks for one party run under a per-(tenant, party) lock, so concurrent conflicting
assignments cannot both succeed (CR-AUTH-01).

Publishing an assignment-mode set reports `existingViolations` (pairs of current assignments that violate it) in
`ucos.party.sod.conflict-set-defined.v1`; it does not revoke them. Execution-mode sets are runtime facts: GetEffective
Authority lists the execution-mode sets in which the party holds at least one member (`sodConflicts`).

## 6. CheckSigningAuthority

Input `{party, representedParty, action, amount: Money, context, counterparty?, asOf?}`. The action needs permission
`perm(action)`: approve-quote → `quote.approve`, approve-price → `pricing.list.approve`, sign-contract →
`contract.approve`, approve-refund → `payment.refund.manual`, approve-credit-note → `billing.creditnote.issue`,
approve-write-off → `billing.writeoff`, purchase → `order.place`. The context gains
`organization = representedParty` when it has no organization.

`party` is authorized when at least one basis holds (`basis` lists them, sorted):

- **limit** (basis = the assignment through whose role the limit applies, or the limit URN when held directly):
  `perm(action) ∈ effective(party)` in context, and a published `amount` limit for the action, held by the party or
  a role it holds in context, whose scope matches, in the same currency, with `amount ≤ limit`.
- **delegation** (basis = delegation URN): a delegation to `party` whose `confers` (in context) contains
  `perm(action)`, whose `perTransaction` limit (if any, same currency) covers the amount, and whose delegator is
  itself authorized for the same request.
- **mandate** (basis = mandate URN): an active mandate held by `party` that includes `perm(action)`, whose
  applicability matches, whose counterparty CEL (if any) holds for `counterparty`, with `amount ≤ perTransaction`
  and `used + amount ≤ total` (same currency); and its grantor is `representedParty` or is itself authorized for
  the same request.

Recursion stops at loops and at depth 16. Money never compares across currencies. Percent measures are returned as
facts (GetEffectiveAuthority `limits`) for policies; CheckSigningAuthority decides amounts only.

## 7. Mandates (INV-AUTH-6)

A mandate is recorded from an Evidence item of kind `attestation` whose content is the mandate terms:

```json
{"type": "ucos.authority.mandate", "grantor": "<party>", "holder": "<party>", "purpose": "…",
 "scope": {"permissions": ["…"], "applicability": [<constraints>], "counterparty": "<CEL over counterparty>"},
 "limits": {"perTransaction": <Money>, "total": <Money>}, "validTo": "<RFC 3339>"}
```

The evidence must carry a signature by the grantor: a compact ES256 JWS (`typ: ucos-evidence+jwt`, embedded `jwk`)
whose payload equals the content, made with the key the grantor's access token was bound to when it captured the
evidence (DOM-EVD checks the thumbprint against `cnf.jkt`). RecordMandate verifies that signature, that the grantor
held every mandated permission at the evidence's `capturedAt` (coarse), that the holder exists and differs from the
grantor, and that any terms repeated in the request equal the signed ones.

## 8. Tokens and propagation (CR-AUTH-03)

- Tokens issued for a party carry `ucos_roles` (coarse roles) and `ucos_delegated` (coarse `∪ confers`), and
  `exp ≤ horizon`. The horizon also includes the instant each contributing assignment would become suspended (§10).
- Every token carries `ucos_auth_at`: the instant, in milliseconds, at which the authority it carries was read
  (taken from the authority store's clock *before* the facts are read). Tokens that carry no tenant authority
  (test or service tokens) use their issue instant.
- An agent acting for its accountable owner keeps the subject token's authority. An agent acting for any other party
  `P` needs an active delegation from `P` to the agent party. Its token then carries
  `ucos_permission_limit = ∪ confers(d)` over those delegations, intersected with any limit the subject token already
  had, and `ucos_auth_at` = the earlier of the subject's and the delegation read's.
- Every PEP computes `(∪ catalog[ucos_roles] ∪ ucos_delegated) ∩ ucos_permission_limit` (`authn.Principal.Permissions`).
- Narrowing changes mark the affected parties stale: revoking or suspending-by-review a role assignment; revoking a
  delegation, including cascades; rejecting nothing (a pending assignment never counted). The affected parties are the
  party itself plus every delegate reachable from it through active re-delegation chains. The cut-off is taken **after
  the change commits**, in milliseconds. The revocation feed (`GET /oauth2/revocations`) publishes
  `notBeforeMs[party] = cutoff`.
- A token is stale when its `ucos_party` or any act-chain `ucos_party` has `ucos_auth_at < cutoff` (`iat·1000` when
  the claim is absent). A token whose authority was read after the change committed is never rejected.
- Agent **actor** tokens (audience `urn:ucos:token-exchange`) confer no API authority and are not subject to party
  cut-offs: the exchange recomputes the agent's authority from current facts.

## 9. Assignment approval (`assignable.requiresApproval`)

Role definitions may declare `assignable: {byRoles[], requiresApproval, approverRoles[], maxDuration}`.

- AssignRole of a role with `requiresApproval` creates the assignment in state `pending-approval`. It confers nothing.
  INV-AUTH-2 (SoD) and INV-AUTH-3 are checked at request time.
- ApproveRoleAssignment moves it to `active`. The approver needs permission `authority.role.assign` and acr ≥ AAL2,
  must differ from the assigner and from the assignee, and must hold one of `approverRoles` when that list is
  non-empty. SoD is checked again at approval, under the same per-party lock as AssignRole.
- RejectRoleAssignment moves it to `rejected` (terminal).
- A pending assignment whose `validTo` passes stays pending but never becomes effective.

`RoleAssignmentLifecycle`: `pending-approval → active | rejected`; `active → revoked`. Suspension (§10) and
end-of-validity are derived, not stored.

## 10. Access reviews and suspension (AUTH-C6, RUL-AUTH-3)

- The **certification base** of an assignment is the latest of `lastCertifiedAt`, its approval instant, and
  `validFrom`.
- Policy `authority.review-interval` gives an interval per role sensitivity (`standard`, `privileged`; a role
  without a sensitivity is `standard`).
- An active assignment is **suspended** at `T` when `T ≥ base + interval`. A suspended assignment is excluded from
  every evaluation (§3), so it also stops conferring through delegations, until it is certified.
- StartAccessReview `{scope: {roles?[], parties?[], sensitivity?}, reviewers[], dueAt}` snapshots the matching
  active assignments (suspended ones included) as items. It needs `authority.review.manage`, at least one reviewer,
  and a `dueAt` in the future. Status `open`, or `overdue` once `dueAt` passes; `completed` when every item is
  decided.
- CertifyAssignment `{reviewId, assignmentRef, decision: keep|revoke}` is made by a listed reviewer, who holds
  `authority.review.manage` and is not the assignee. Each item is decided once.
  - `keep` sets `lastCertifiedAt = now`, which ends a suspension.
  - `revoke` revokes the assignment (§8 propagation).

## 11. Mandate usage (MandateLifecycle)

RecordMandateUsage `{amount: Money, reference}` against an active mandate, with permission
`authority.mandate.manage`:

- It is idempotent per `(mandate, reference)`. Repeating the same reference and amount returns the original result;
  the same reference with a different amount is `409`.
- The currency must equal the mandate's limits, and the amount must be within `perTransaction` and the remaining
  `total`. Otherwise `409 E-AUTH-MANDATE-LIMIT`, and nothing is recorded.
- When `used` reaches `total` exactly, the mandate becomes `exhausted` (terminal).
- An expired mandate (`validTo` passed) reads as `expired`.

## 12. Tenant role definitions (DefineRole, INV-AUTH-1)

- A tenant defines roles in its own namespace: `urn:ucos:<tenant>:role:<code>`. The definition is
  `{code, label?, permissions[], includes[], sensitivity, assignable?}`, drafted into the author's draft ChangeSet and
  published by governance (as for §5 and §6).
- `code` must not collide with a role already in the catalog.
- Every permission must be granted by some role of the catalog (= declared by a DOM spec, VR-AUTH-03).
- `includes` must name catalog roles, and the include graph must stay acyclic.
- Published tenant roles join the tenant's catalog with `includes` flattened.
