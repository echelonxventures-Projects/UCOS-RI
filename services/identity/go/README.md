# identity-service

DOM-IDN token service plus DOM-PTY and DOM-AUTH (slice S2). Design: `docs/adr/0007-identity-service-token-design.md`,
`docs/adr/0009-authority-delegation-sod.md`; authority semantics: `contracts/authority/semantics.md`.

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration`, `/.well-known/jwks.json` | Discovery and ES256 keys |
| `GET /oauth2/authorize`, `GET /oauth2/callback` | Federated login: authorization code with PKCE |
| `POST /oauth2/token` | `authorization_code`, `client_credentials`, and RFC 8693 token exchange; DPoP-bound when a proof is sent |
| `POST /oauth2/introspect`, `POST /oauth2/revoke`, `GET /oauth2/revocations` | RFC 7662 / 7009; revocation feed for validators |
| `GET /v1/identity/me` | The authenticated principal (subject, party, roles, scopes, actor chain) |
| `POST /v1/party/parties`, `GET /v1/party/parties/{id}` | RegisterParty / GetParty (PEP: `party.create` / `party.read`) |
| `POST /v1/authority/role-assignments`, `GET …`, `POST …/{id}:revoke` | AssignRole (scope, validity, SoD under a per-party lock) / FindRoleAssignments / RevokeRoleAssignment |
| `POST /v1/authority/delegations`, `POST …/{id}:revoke` | GrantDelegation (narrowing only, depth, no cycles) / RevokeDelegation (cascades) |
| `POST /v1/authority/limits`, `POST /v1/authority/sod-conflict-sets` | Draft governed definitions into the caller's ChangeSet |
| `POST /v1/authority/mandates`, `GET …/{id}`, `POST …/{id}:revoke` | Evidence-backed mandates (INV-AUTH-6) |
| `GET /v1/authority/effective`, `POST /v1/authority:check-signing` | GetEffectiveAuthority / CheckSigningAuthority in context |
| `GET/POST/DELETE /v1/governed-definitions…` | Remote owner protocol, governance only (`ucos:platform:admin`) |
| `POST /v1/identity/agents` | RegisterAgentIdentity (PEP: `identity.agent.create`); returns the agent client secret once |
| `GET /v1/identity/identities/{id}`, `POST …{id}:suspend` | GetIdentity / SuspendIdentity |
| `POST /v1/identity/federations` | ConfigureFederation (PEP plus policy `identity.federation-admin`) |

Lite-only admin port `:8081`: `POST /internal/tenants` sets up a tenant's federation, clients and invitations.
