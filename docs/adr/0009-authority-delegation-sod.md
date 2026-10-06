# ADR 0009: DOM-AUTH delegations, segregation of duties, limits and mandates; delegation-aware tokens

- Status: accepted (2026-10-06)
- Traces: DOM-AUTH (INV-AUTH-2..6, RUL-AUTH-1/2, DEC-AUTH-1/2, CR-AUTH-01..03), DOM-IDN (RUL-IDN-2/3, CR-IDN-05),
  DOM-EVD, DOM-GOV / CIC-015-001 §1, CIC-009-001 §5, AR-0004, ADR 0007, ADR 0008

## Decisions

1. **Executable semantics.** `contracts/authority/semantics.md` makes DOM-AUTH decidable (AR-0004). The evaluation
   model (`services/identity/go/authority/model.go`, `signing.go`) is pure and unit-tested, including a randomized
   property test of CR-AUTH-02. The service only loads facts within one tenant transaction and persists decisions.
2. **Tokens carry delegation.** Two claims are added:
   - `ucos_delegated`: coarse permissions received through delegations.
   - `ucos_permission_limit`: a ceiling, set on agent tokens obtained under a delegation.

   Every PEP derives permissions through one function, `authn.Principal.Permissions` (Go) and `permissions()`
   (TypeScript): `(roles' permissions ∪ delegated) ∩ limit`. A service that bypassed it would over-grant, so the
   suite checks the rule on metadata-service, identity-service and event-platform-service.
3. **Propagation through the revocation feed.** Revoking a role assignment or a delegation writes per-party cut-offs.
   The affected parties are the party itself plus its downstream delegates through active re-delegation chains.
   `GET /oauth2/revocations` now also returns `notBefore`. Validators reject a token whose party or act-chain party
   has `iat ≤ cutoff`. The cutoff is one second after the change, which covers tokens computed from pre-commit state.
   Tokens are also capped at the earliest expiry of the authority they carry, so expiry needs no propagation.
   Measured revocation-to-rejection is well under the 10 s of CR-AUTH-03 across all four services.
4. **Segregation of duties under a lock.** AssignRole checks assignment-mode sets under
   `pg_advisory_xact_lock(tenant, party)`. In the concurrency test, 25 pairs of simultaneous conflicting assignments
   end with exactly one winner each. Removing the lock makes the test fail.
5. **Governed authority definitions with a remote owner protocol.** SoD sets and authority limits change "via
   ChangeSet". identity-service owns them in `ucos_party` and serves the owner protocol. metadata-service's governance
   wraps it as an ordinary Owner (`governed.RemoteOwner`) and checks its publication Gate before every publish.
   - Protocol calls need a DPoP-bound platform service token with scope `ucos:platform:admin`, which only clients
     listed in `UCOS_GOVERNANCE_CLIENTS` can obtain.
   - Drafts are created through the DOM-AUTH API and must reference the author's own draft ChangeSet.
   - Their risk facts mark them security-relevant, so the risk class is high (two approval stages).
6. **Agent delegation through AUTH.** An agent still acts for its accountable owner with the subject token's
   authority. It may now also act for any other party within an active delegation from that party to the agent
   party. The exchanged token carries the act chain and `ucos_permission_limit`, and expires no later than the
   delegation. Revoking the delegation makes both the exchanged tokens and the agent's own tokens stale.
7. **Signed evidence for mandates.** DOM-EVD gains CaptureEvidence (`POST /v1/evidence/items`, permission
   `evidence.capture`). `signedContent` is a compact ES256 JWS signed with the key the caller's token is bound to.
   VerifyEvidence now reports `signaturesOk`. RecordMandate accepts only evidence signed by the grantor, for
   authority the grantor held at capture.

## Consequences
- 14 S2c black-box tests; the full suite runs on real tokens for both event-platform-service implementations.
- Not covered yet (all but per-period limits were implemented in S2d; see ADR 0010):
  - Access reviews and RUL-AUTH-3 are slice S2d.
  - DefineRole and the access-review routes answer `501` behind the PEP.
  - Mandate consumption needs a consuming context (S4).
  - identity-service commands do not yet replay `Idempotency-Key`; this gap dates from S2a and is scheduled for S2d.
