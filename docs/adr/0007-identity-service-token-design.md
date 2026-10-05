# ADR 0007: identity-service: federated login, DPoP-bound ES256 tokens, agents only via exchange

- Status: accepted (2026-10-05)
- Traces: DOM-IDN (RUL-IDN-1..3, INV-IDN-1..5, CR-IDN-03/05), DOM-PTY (INV-PTY-1/5), DOM-AUTH, CIC-009-001 §5,
  CIC-014-001 §3–4, CIC-017-001 §2, AMD-0002

## Decisions

1. **One deployable for IDN + PTY + AUTH** (`services/identity/go`), with schemas `ucos_identity` and `ucos_party`
   as the DOM specs assign them. Parties validate their values against the effective schema served by
   metadata-service, which proves the cross-service ontology port.
2. **Login is always federated.** OIDC authorization code with PKCE (S256) runs on both legs:
   - client → UCOS: PKCE is mandatory and only exact registered redirect URIs are accepted;
   - UCOS → the provider: PKCE plus nonce, and the provider's id_token is verified with its JWKS (RS256 or ES256).

   Claim mapping is CEL, compiled at configuration time (INV-IDN-5). First login provisions just in time:
   - a Person party;
   - a human identity, unique per (federation, subject digest) (INV-IDN-1);
   - redemption of email invitations into role assignments.

   `ucos-lite` runs **dex** (digest-pinned) as the corporate provider, so the conformance suite performs a real
   browser-style login.
3. **Access tokens** are RFC 9068 `at+jwt`, ES256 only, live at most 10 min, and are capped by
   `identity.token-lifetimes`. Their claims are the only principal source for PEPs:
   `ucos_tenant`, `ucos_party`, `ucos_roles`, `scope`, `acr`, `act`.
4. **Sender constraint (RUL-IDN-1).** A DPoP proof at the token endpoint binds the token (`cnf.jkt`). Resource
   servers then require a valid proof:
   - signed by the bound key;
   - matching `htm`, `htu` and `ath`;
   - inside the iat window;
   - not replayed.

   Bearer tokens may only read.
5. **Agents never hold standalone API tokens.**
   - `client_credentials` for an agent client yields an *actor token* whose only audience is
     `urn:ucos:token-exchange`.
   - API access comes only from RFC 8693 exchange. The resulting token has `sub` = the accountable owner,
     `act` = the agent (nested for chains), scope = subject ∩ agent profile ∩ `identity.agent-delegation`, and
     audience `ucos` only. It is bound to the agent's DPoP key, depth-limited, and never outlives the subject token.
   - Every agent call therefore carries its act chain (CR-IDN-05).
   - In S2a an agent may act only for its owner party. Delegation to agents through DOM-AUTH arrives in S2b.
6. **PEP order**, in `pep/`:
   1. authenticate (DPoP for writes);
   2. coarse scope;
   3. role permissions from the tenant's role registry (`ucos.std` 1.1.0, AMD-0002);
   4. an authorization policy evaluated by the embedded PDP over the tenant bundle
      (`GET /v1/policy/bundles/{tenant}`), where one governs the operation.

   `identity.federation-admin` shows step 4: holding the permission is not enough below AAL2.
7. **Key custody.** The signing key and federation secrets are sealed with AES-256-GCM under a KEK. Each party's
   personal attributes are sealed under a per-party subject key, which is itself sealed by the KEK, so erasure is
   crypto-shred (INV-PTY-5).
   - `ucos-lite` reads the KEK from the environment; production uses a KMS/HSM (CIC-014-001 §4).
   - Key rotation and JWKS overlap arrive with the platform signing-key service (S6).
8. **Tenant bootstrap.** Federation, OAuth clients and admin invitations are set up through the lite-only admin
   address (`:8081`, never published). Production uses tenant provisioning (DOM-TNT/RTM, later slice).

## Still open (S2b)
- echo, metadata and eventing still trust dev headers. They move to `platform/authn` (Go) plus a TypeScript
  validator, with service tokens for service-to-service calls (metadata-service is called with dev headers today).
- DOM-AUTH delegations, SoD conflict sets, authority limits, mandates.
- Refresh tokens, sessions, step-up (`acr` > AAL1 needs a provider that asserts MFA), revocation within 60 s across
  gateways (the validators poll `/oauth2/revocations` every 5 s today).
