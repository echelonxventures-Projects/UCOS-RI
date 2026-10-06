# ADR 0008: Token validation and PEPs in every service; service tokens; lite test tokens

- Status: accepted (2026-10-06)
- Traces: CIC-014-001 §3, CIC-009-001 §5 (CR-009-001-02), DOM-IDN RUL-IDN-1, AMD-0003, ADR 0007

## Decisions

1. **No dev headers remain.** echo (Go), metadata-service (Go) and event-platform-service (Go and TypeScript) all
   validate UCOS access tokens: ES256 `at+jwt` from the issuer JWKS, audience `ucos`, revocation feed polled every 5 s.
   Writes require a DPoP proof bound to the token. Tenant, party, identity, roles and acr come only from claims.
   Shared validators:
   - `platform/authn/go`;
   - `platform/authn/typescript`, which mirrors the Go one using `node:crypto` with IEEE-P1363 signatures.
2. **PEP order in metadata-service:**
   1. token;
   2. coarse scope `ucos:<context>:read|write` (context = bounded context of the route; registry and pack routes
      belong to `ontology`);
   3. permission from a central route table (`kernel/cmd/metadata-service`), checked against the tenant's role catalog.

   Registering a route without a table entry panics at startup, and `{rest}` action suffixes without an entry are
   404, so no endpoint can be unguarded (CR-009-001-02). The suite `conformance/s2/test_pep_coverage.py` is
   mutation-tested.
3. **Role catalog.** A tenant's catalog is its installed role registry. Before a tenant installs a pack, and for the
   `platform` tenant, the catalog is that of the newest published `ucos.std`. One kernel seed lets the first pack be
   published: `platform-governance` → `packs.publish`. AMD-0003 ensures every permission is granted by some role.
4. **Platform services.**
   - Service clients are confidential OAuth clients of the `platform` tenant. They are registered by identity-service
     from configuration in lite; production uses workload identity.
   - Their tokens carry the role `platform-service` and the scope `ucos:platform:read`.
   - Such a token may **read** on behalf of the tenant named by `UCOS-Tenant`. It never writes on a tenant's behalf.
     A normal tenant token's `UCOS-Tenant` header is ignored.
   - identity-service mints its own service token, since it is the issuer.
   - event-platform-service uses client credentials to read the platform role catalog.
5. **Lite test tokens.** The S0/S1 suites need arbitrary principals: approvers with chosen roles, acr and identities.
   identity-service therefore exposes `POST /internal/test-tokens` on its admin address, which is never published,
   **only** when `UCOS_TEST_TOKENS=enabled`. It mints real signed, DPoP-bound tokens, so every service still performs
   full validation. The S2 suite keeps using genuine federated login.

## Consequences
- The conformance suites send real tokens everywhere, through the shared helper `conformance/tokens.py`.
- Removing a PEP step is caught: a planted "skip permission check" mutant fails the deny-all test.
