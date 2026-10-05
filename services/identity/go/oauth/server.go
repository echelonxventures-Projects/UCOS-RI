package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/authn/authn"
	"ucos.dev/ri/identity/kit"
	"ucos.dev/ri/pdp/pdp"
)

// Schema is DOM-IDN's schema.
const Schema = "ucos_identity"

// TokenExchangeAudience is the only audience of agent actor tokens: they are usable solely as actor_token in
// RFC 8693 exchange, so every agent API call carries an act chain with its accountable party (CR-IDN-05).
const TokenExchangeAudience = "urn:ucos:token-exchange"

// APIAudience is the audience of UCOS API access tokens.
const APIAudience = "ucos"

// Parties is the DOM-PTY port used for JIT provisioning and agent parties.
type Parties interface {
	RegisterByTypeName(ctx context.Context, tenant, actor, typeName string, values map[string]any, corr string) (string, error)
}

// Roles is the DOM-AUTH port.
type Roles interface {
	Effective(ctx context.Context, tenant, party string) ([]string, error)
	Redeem(ctx context.Context, tenant, email, party, corr string) error
}

// Policies is the embedded-PDP port (tenant bundle).
type Policies interface {
	Decide(ctx context.Context, tenant, name string, input map[string]any) (any, error)
}

// Server is the token service.
type Server struct {
	DB        *kit.DB
	KEK       *kit.Sealer
	Keys      *KeyRing
	Issuer    string // public base URL; also the token `iss`
	Parties   Parties
	Roles     Roles
	Policies  Policies
	Self      *authn.Validator // verifies API tokens this service issued (audience ucos) and DPoP proofs
	SelfActor *authn.Validator // verifies agent actor tokens (audience urn:ucos:token-exchange)
	Log       *slog.Logger
	Source    string
	Engine    pdp.Engine
	fed       federationClient
}

// ---------------------------------------------------------------- OAuth error helpers

type oauthError struct {
	status int
	code   string
	desc   string
}

func (e *oauthError) Error() string { return e.code + ": " + e.desc }

func oerr(status int, code, desc string) *oauthError { return &oauthError{status, code, desc} }

func writeOAuthError(w http.ResponseWriter, err error, log *slog.Logger) {
	var oe *oauthError
	if !errors.As(err, &oe) {
		log.Error("token endpoint failure", "error", err.Error())
		oe = oerr(500, "server_error", "internal error")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(oe.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": oe.code, "error_description": oe.desc})
}

// ---------------------------------------------------------------- clients, identities

type client struct {
	ID, Tenant, Kind, SecretHash, IdentityRef string
	RedirectURIs, AllowedScopes               []string
}

func (s *Server) loadClient(ctx context.Context, id string) (client, error) {
	var c client
	var secret, ident *string
	err := s.DB.Pool.QueryRow(ctx, `SELECT client_id, tenant, kind, secret_hash, redirect_uris, allowed_scopes, identity_ref
		FROM ucos_identity.oauth_clients WHERE client_id = $1`, id).Scan(&c.ID, &c.Tenant, &c.Kind, &secret, &c.RedirectURIs,
		&c.AllowedScopes, &ident)
	if secret != nil {
		c.SecretHash = *secret
	}
	if ident != nil {
		c.IdentityRef = *ident
	}
	return c, err
}

// authenticateClient implements client_secret_basic / client_secret_post (confidential and agent clients) and
// client_id-only for public clients.
func (s *Server) authenticateClient(ctx context.Context, r *http.Request, requireSecret bool) (client, error) {
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	c, err := s.loadClient(ctx, id)
	if err != nil {
		return c, oerr(401, "invalid_client", "unknown client")
	}
	if c.Kind == "public" {
		if requireSecret {
			return c, oerr(401, "invalid_client", "public clients cannot use this grant")
		}
		return c, nil
	}
	if secret == "" || kit.Hash(secret) != c.SecretHash {
		return c, oerr(401, "invalid_client", "client authentication failed")
	}
	return c, nil
}

// Identity is the DOM-IDN Identity aggregate as served (personal externalSubject never returned).
type Identity struct {
	ID           string         `json:"id"`
	Kind         string         `json:"kind"`
	PartyRef     string         `json:"partyRef"`
	Binding      map[string]any `json:"binding"`
	Status       string         `json:"status"`
	AgentProfile map[string]any `json:"agentProfile,omitempty"`
	Revision     int64          `json:"revision"`
}

// GetIdentity loads an identity of tenant.
func (s *Server) GetIdentity(ctx context.Context, tenant, id string) (Identity, error) {
	var i Identity
	var binding, profile []byte
	var party *string
	err := s.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, kind, party_ref, binding, status, agent_profile, revision FROM ucos_identity.identities
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id).
			Scan(&i.ID, &i.Kind, &party, &binding, &i.Status, &profile, &i.Revision)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return i, kit.NotFound
	}
	if party != nil {
		i.PartyRef = *party
	}
	_ = json.Unmarshal(binding, &i.Binding)
	_ = json.Unmarshal(profile, &i.AgentProfile)
	return i, err
}

func (s *Server) createIdentity(ctx context.Context, tx pgx.Tx, tenant, kind, federation, subject, party, acr string,
	profile map[string]any, actor, corr string) (string, error) {
	id := "urn:ucos:" + tenant + ":identity:" + kit.ULID()
	binding, _ := json.Marshal(map[string]any{"partyRef": party, "validFrom": time.Now().UTC().Format(time.RFC3339),
		"assurance": acr, "verifiedBy": firstNonEmpty(federation, actor)})
	var prof []byte
	if profile != nil {
		prof, _ = json.Marshal(profile)
	}
	var fed, digest, enc any
	if federation != "" {
		fed, digest, enc = federation, kit.Hash(federation+"\x00"+subject), s.KEK.Seal([]byte(subject), id)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO ucos_identity.identities (tenant_id, id, kind, federation_ref, subject_digest,
		subject_enc, party_ref, binding, status, agent_profile, revision, created_at)
		VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, 'active', $8, 1, now())`,
		id, kind, fed, digest, enc, party, binding, prof); err != nil {
		return "", err
	}
	for _, ev := range []kit.Event{
		{Type: "ucos.identity.identity.registered.v1", Payload: map[string]any{"id": id, "kind": kind}},
		{Type: "ucos.identity.identity.bound-to-party.v1", Payload: map[string]any{"id": id, "partyRef": party, "assurance": acr}},
	} {
		ev.Schema, ev.AggregateID, ev.Subject, ev.Principal, ev.Tenant, ev.CorrelationID = Schema, id, id, actor, tenant, corr
		if err := kit.Append(ctx, tx, s.Source, ev); err != nil {
			return "", err
		}
	}
	return id, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------- discovery

// Discovery serves OIDC / RFC 8414 metadata.
func (s *Server) Discovery(w http.ResponseWriter, _ *http.Request) {
	_ = kit.JSON(w, 200, map[string]any{
		"issuer": s.Issuer, "authorization_endpoint": s.Issuer + "/oauth2/authorize", "token_endpoint": s.Issuer + "/oauth2/token",
		"jwks_uri": s.Issuer + "/.well-known/jwks.json", "introspection_endpoint": s.Issuer + "/oauth2/introspect",
		"revocation_endpoint": s.Issuer + "/oauth2/revoke", "response_types_supported": []string{"code"},
		"grant_types_supported":            []string{"authorization_code", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"code_challenge_methods_supported": []string{"S256"}, "dpop_signing_alg_values_supported": []string{"ES256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"subject_types_supported":               []string{"public"}, "id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

// JWKS serves the public signing keys.
func (s *Server) JWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "max-age=300")
	_ = kit.JSON(w, 200, s.Keys.JWKS())
}

// ---------------------------------------------------------------- authorization code + PKCE (federated login)

var scopePattern = regexp.MustCompile(`^ucos:[a-z][a-z0-9-]*:(read|write|admin)$`)

func intersect(requested string, allowed []string) []string {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var out []string
	for _, x := range strings.Fields(requested) {
		if ok[x] && scopePattern.MatchString(x) {
			out = append(out, x)
		}
	}
	return out
}

// Authorize starts login: validates the client and PKCE, then redirects to the tenant's federated provider.
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := s.loadClient(r.Context(), q.Get("client_id"))
	redirect := q.Get("redirect_uri")
	if err != nil || !contains(c.RedirectURIs, redirect) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest) // never redirect to an unregistered URI
		return
	}
	back := func(code, desc string) {
		u, _ := url.Parse(redirect)
		v := u.Query()
		v.Set("error", code)
		v.Set("error_description", desc)
		v.Set("state", q.Get("state"))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		back("unsupported_response_type", "only response_type=code is supported")
		return
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 {
		back("invalid_request", "PKCE with S256 is required")
		return
	}
	var fedID, issuer, idpClient string
	err = s.DB.InTenantTx(r.Context(), c.Tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT id, issuer, client_id FROM ucos_identity.federations
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND status = 'active' ORDER BY created_at LIMIT 1`).
			Scan(&fedID, &issuer, &idpClient)
	})
	if err != nil {
		back("access_denied", "no active federation for this tenant")
		return
	}
	p, err := s.fed.discover(r.Context(), issuer)
	if err != nil {
		s.Log.Error("federation discovery", "error", err.Error())
		back("temporarily_unavailable", "identity provider unavailable")
		return
	}
	state, nonce, verifier := kit.RandomToken(24), kit.RandomToken(24), kit.RandomToken(48)
	scope := strings.Join(intersect(q.Get("scope"), c.AllowedScopes), " ")
	if _, err := s.DB.Pool.Exec(r.Context(), `INSERT INTO ucos_identity.login_requests (state, tenant, client_id, redirect_uri,
		client_state, code_challenge, scope, federation_id, nonce, idp_verifier, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now())`, state, c.Tenant, c.ID, redirect, q.Get("state"), q.Get("code_challenge"),
		scope, fedID, nonce, verifier); err != nil {
		back("server_error", "could not start login")
		return
	}
	u, _ := url.Parse(p.AuthEndpoint)
	v := url.Values{"response_type": {"code"}, "client_id": {idpClient}, "redirect_uri": {s.Issuer + "/oauth2/callback"},
		"scope": {"openid email profile"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// Callback completes federated login: verifies the provider's id_token, maps claims (CEL), finds or JIT-provisions
// identity + party, redeems invitations, and returns a one-time UCOS authorization code to the client.
func (s *Server) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	var lr struct{ tenant, clientID, redirect, clientState, challenge, scope, fedID, nonce, verifier string }
	err := s.DB.Pool.QueryRow(ctx, `DELETE FROM ucos_identity.login_requests WHERE state = $1 AND created_at > now() - interval '10 minutes'
		RETURNING tenant, client_id, redirect_uri, client_state, code_challenge, scope, federation_id, nonce, idp_verifier`,
		q.Get("state")).Scan(&lr.tenant, &lr.clientID, &lr.redirect, &lr.clientState, &lr.challenge, &lr.scope, &lr.fedID,
		&lr.nonce, &lr.verifier)
	if err != nil {
		http.Error(w, "unknown or expired login state", http.StatusBadRequest)
		return
	}
	back := func(params url.Values) {
		u, _ := url.Parse(lr.redirect)
		v := u.Query()
		for k, x := range params {
			v[k] = x
		}
		v.Set("state", lr.clientState)
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	fail := func(code, desc string, err error) {
		if err != nil {
			s.Log.Warn("login failed", "reason", desc, "error", err.Error())
		}
		back(url.Values{"error": {code}, "error_description": {desc}})
	}
	if e := q.Get("error"); e != "" {
		fail("access_denied", "identity provider returned "+e, nil)
		return
	}
	var issuer, idpClient, sealedSecret, mapping string
	var jit []byte
	err = s.DB.InTenantTx(ctx, lr.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT issuer, client_id, client_secret_enc, claim_mapping, jit FROM ucos_identity.federations
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND status = 'active'`, lr.fedID).
			Scan(&issuer, &idpClient, &sealedSecret, &mapping, &jit)
	})
	if err != nil {
		fail("access_denied", "federation unavailable", err)
		return
	}
	secret, err := s.KEK.Open(sealedSecret, lr.fedID)
	if err != nil {
		fail("server_error", "federation secret unavailable", err)
		return
	}
	p, err := s.fed.discover(ctx, issuer)
	if err != nil {
		fail("temporarily_unavailable", "identity provider unavailable", err)
		return
	}
	idToken, err := s.fed.exchange(ctx, p, idpClient, string(secret), q.Get("code"), s.Issuer+"/oauth2/callback", lr.verifier)
	if err != nil {
		fail("access_denied", "identity provider code exchange failed", err)
		return
	}
	claims, err := s.fed.verifyIDToken(p, idToken, idpClient, lr.nonce)
	if err != nil {
		fail("access_denied", "id_token rejected", err)
		return
	}
	mapped, err := s.Engine.EvalCEL(mapping, map[string]any{"claims": claims})
	m, _ := mapped.(map[string]any)
	extSub, _ := m["externalSubject"].(string)
	if err != nil || extSub == "" {
		fail("access_denied", "claim mapping did not yield an externalSubject", err)
		return
	}
	email, _ := m["email"].(string)
	display, _ := m["displayName"].(string)
	corr := kit.ULID()
	identity, party, status, err := s.findOrProvision(ctx, lr.tenant, lr.fedID, extSub, email, display, jit, corr)
	if err != nil {
		fail("access_denied", "identity could not be provisioned", err)
		return
	}
	if status != "active" {
		fail("access_denied", "identity is suspended", nil) // INV-IDN-4
		return
	}
	code := kit.RandomToken(32)
	if _, err := s.DB.Pool.Exec(ctx, `INSERT INTO ucos_identity.auth_codes (code_hash, tenant, client_id, redirect_uri, code_challenge,
		identity, scope, acr, amr, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'AAL1',ARRAY['pwd','fed'],now() + interval '60 seconds')`,
		kit.Hash(code), lr.tenant, lr.clientID, lr.redirect, lr.challenge, identity, lr.scope); err != nil {
		fail("server_error", "could not issue code", err)
		return
	}
	_ = party
	back(url.Values{"code": {code}})
}

func (s *Server) findOrProvision(ctx context.Context, tenant, fedID, extSub, email, display string, jitRaw []byte, corr string) (string, string, string, error) {
	var id, status string
	var party *string
	err := s.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, party_ref, status FROM ucos_identity.identities
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND federation_ref = $1 AND subject_digest = $2`,
			fedID, kit.Hash(fedID+"\x00"+extSub)).Scan(&id, &party, &status)
	})
	if err == nil {
		return id, deref(party), status, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", err
	}
	var jit map[string]any
	_ = json.Unmarshal(jitRaw, &jit)
	if jit["enabled"] != true {
		return "", "", "", errors.New("unknown subject and JIT provisioning is disabled")
	}
	typeName, _ := jit["defaultPartyType"].(string)
	if typeName == "" {
		typeName = "Person"
	}
	if display == "" {
		display = extSub
	}
	actor := "urn:ucos:" + tenant + ":identity:jit"
	partyURN, err := s.Parties.RegisterByTypeName(ctx, tenant, actor, typeName, map[string]any{"displayName": display}, corr)
	if err != nil {
		return "", "", "", err
	}
	err = s.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		id, err = s.createIdentity(ctx, tx, tenant, "human", fedID, extSub, partyURN, "AAL1", nil, actor, corr)
		return err
	})
	if err != nil {
		return "", "", "", err
	}
	if email != "" {
		if err := s.Roles.Redeem(ctx, tenant, strings.ToLower(email), partyURN, corr); err != nil {
			return "", "", "", err
		}
	}
	return id, partyURN, "active", nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- token endpoint

// Token implements POST /oauth2/token.
func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oerr(400, "invalid_request", "malformed form"), s.Log)
		return
	}
	var out map[string]any
	var err error
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		out, err = s.grantCode(r)
	case "client_credentials":
		out, err = s.grantClientCredentials(r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		out, err = s.grantExchange(r)
	default:
		err = oerr(400, "unsupported_grant_type", "grant type not supported")
	}
	if err != nil {
		writeOAuthError(w, err, s.Log)
		return
	}
	_ = kit.JSON(w, 200, out)
}

// dpopKey validates an optional DPoP proof at the token endpoint and returns its thumbprint.
func (s *Server) dpopKey(r *http.Request) (string, error) {
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return "", nil
	}
	jkt, err := s.Self.VerifyDPoP(proof, "POST", s.Issuer+"/oauth2/token", "")
	if err != nil {
		return "", oerr(400, "invalid_dpop_proof", err.Error())
	}
	return jkt, nil
}

func (s *Server) lifetime(ctx context.Context, tenant string) time.Duration {
	out, err := s.Policies.Decide(ctx, tenant, "identity.token-lifetimes", map[string]any{})
	if err == nil {
		if m, ok := out.(map[string]any); ok {
			if d, ok := isoMinutes(m["accessToken"]); ok {
				return d
			}
		}
	}
	return 10 * time.Minute // RUL-IDN-1 ceiling
}

var ptPattern = regexp.MustCompile(`^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$`)

func isoMinutes(v any) (time.Duration, bool) {
	s, _ := v.(string)
	m := ptPattern.FindStringSubmatch(s)
	if m == nil || s == "PT" {
		return 0, false
	}
	h, _ := strconv.Atoi("0" + m[1])
	mi, _ := strconv.Atoi("0" + m[2])
	se, _ := strconv.Atoi("0" + m[3])
	d := time.Duration(h)*time.Hour + time.Duration(mi)*time.Minute + time.Duration(se)*time.Second
	if d > 10*time.Minute {
		d = 10 * time.Minute
	}
	return d, d > 0
}

type tokenSpec struct {
	tenant, identity, party, clientID, acr, jkt string
	amr, roles, scope                           []string
	aud                                         any
	act                                         map[string]any
	extra                                       map[string]any
	lifetime                                    time.Duration
	notAfter                                    int64
}

func (s *Server) issue(t tokenSpec) (map[string]any, error) {
	now := time.Now()
	exp := now.Add(t.lifetime).Unix()
	if t.notAfter > 0 && exp > t.notAfter {
		exp = t.notAfter // exchanged tokens never outlive the subject token
	}
	claims := map[string]any{"iss": s.Issuer, "sub": t.identity, "aud": t.aud, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": exp, "jti": kit.ULID(), "client_id": t.clientID, "scope": strings.Join(t.scope, " "),
		"ucos_tenant": t.tenant, "ucos_party": t.party, "ucos_roles": nonNil(t.roles), "acr": t.acr, "amr": nonNil(t.amr)}
	for k, v := range t.extra {
		claims[k] = v
	}
	if t.act != nil {
		claims["act"] = t.act
	}
	tokenType := "Bearer"
	if t.jkt != "" {
		claims["cnf"] = map[string]any{"jkt": t.jkt}
		tokenType = "DPoP"
	}
	tok, err := s.Keys.Sign("at+jwt", claims)
	if err != nil {
		return nil, err
	}
	return map[string]any{"access_token": tok, "token_type": tokenType, "expires_in": exp - now.Unix(),
		"scope": strings.Join(t.scope, " ")}, nil
}

func nonNil(x []string) []string {
	if x == nil {
		return []string{}
	}
	return x
}

func (s *Server) grantCode(r *http.Request) (map[string]any, error) {
	ctx := r.Context()
	c, err := s.authenticateClient(ctx, r, false)
	if err != nil {
		return nil, err
	}
	var tenant, clientID, redirect, challenge, identity, scope, acr string
	var amr []string
	err = s.DB.Pool.QueryRow(ctx, `UPDATE ucos_identity.auth_codes SET used_at = now()
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING tenant, client_id, redirect_uri, code_challenge, identity, scope, acr, amr`, kit.Hash(r.PostForm.Get("code"))).
		Scan(&tenant, &clientID, &redirect, &challenge, &identity, &scope, &acr, &amr)
	if err != nil {
		return nil, oerr(400, "invalid_grant", "authorization code invalid, expired or already used")
	}
	if clientID != c.ID || redirect != r.PostForm.Get("redirect_uri") {
		return nil, oerr(400, "invalid_grant", "code was issued to another client or redirect_uri")
	}
	if pkceChallenge(r.PostForm.Get("code_verifier")) != challenge {
		return nil, oerr(400, "invalid_grant", "PKCE verification failed")
	}
	jkt, err := s.dpopKey(r)
	if err != nil {
		return nil, err
	}
	ident, err := s.GetIdentity(ctx, tenant, identity)
	if err != nil || ident.Status != "active" {
		return nil, oerr(400, "invalid_grant", "identity is not active")
	}
	roles, err := s.Roles.Effective(ctx, tenant, ident.PartyRef)
	if err != nil {
		return nil, err
	}
	return s.issue(tokenSpec{tenant: tenant, identity: identity, party: ident.PartyRef, clientID: c.ID, acr: acr, amr: amr,
		roles: roles, scope: strings.Fields(scope), aud: APIAudience, jkt: jkt, lifetime: s.lifetime(ctx, tenant)})
}

func (s *Server) grantClientCredentials(r *http.Request) (map[string]any, error) {
	ctx := r.Context()
	c, err := s.authenticateClient(ctx, r, true)
	if err != nil {
		return nil, err
	}
	ident, err := s.GetIdentity(ctx, c.Tenant, c.IdentityRef)
	if err != nil || ident.Status != "active" {
		return nil, oerr(400, "invalid_grant", "client identity is not active")
	}
	jkt, err := s.dpopKey(r)
	if err != nil {
		return nil, err
	}
	if c.Kind == "agent" {
		// Actor token: only usable as actor_token in exchange; agents never call APIs without an act chain.
		return s.issue(tokenSpec{tenant: c.Tenant, identity: ident.ID, party: ident.PartyRef, clientID: c.ID, acr: "AAL2",
			amr: []string{"client-secret"}, aud: TokenExchangeAudience, jkt: jkt, lifetime: 5 * time.Minute,
			extra: map[string]any{"ucos_owner_party": ident.AgentProfile["ownerParty"]}})
	}
	roles, err := s.Roles.Effective(ctx, c.Tenant, ident.PartyRef)
	if err != nil {
		return nil, err
	}
	return s.issue(tokenSpec{tenant: c.Tenant, identity: ident.ID, party: ident.PartyRef, clientID: c.ID, acr: "AAL2",
		amr: []string{"client-secret"}, roles: roles, scope: intersect(r.PostForm.Get("scope"), c.AllowedScopes),
		aud: APIAudience, jkt: jkt, lifetime: s.lifetime(ctx, c.Tenant)})
}

func depth(act map[string]any) int {
	n := 0
	for a := act; a != nil && n < 16; n++ {
		a, _ = a["act"].(map[string]any)
	}
	return n
}

func toStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func intNum(v any, def int) int {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return int(i)
		}
	case float64:
		return int(n)
	case int64:
		return int(n)
	}
	return def
}

// grantExchange implements RFC 8693 for agents (RUL-IDN-2, RUL-IDN-3): the agent client presents the accountable
// subject's token and its own actor token; the result only narrows scope and audience, is bound to the agent's DPoP
// key, never outlives the subject token, and carries act = {sub: agent, ucos_party: agent party, act: prior chain}.
func (s *Server) grantExchange(r *http.Request) (map[string]any, error) {
	ctx := r.Context()
	c, err := s.authenticateClient(ctx, r, true)
	if err != nil {
		return nil, err
	}
	if c.Kind != "agent" {
		return nil, oerr(400, "unauthorized_client", "only agent clients may exchange tokens")
	}
	f := r.PostForm
	if f.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" ||
		f.Get("actor_token_type") != "urn:ietf:params:oauth:token-type:access_token" {
		return nil, oerr(400, "invalid_request", "subject_token_type and actor_token_type must be access_token")
	}
	subj, err := s.verifyOwn(ctx, f.Get("subject_token"), APIAudience)
	if err != nil {
		return nil, oerr(400, "invalid_grant", "subject token: "+err.Error())
	}
	actor, err := s.verifyOwn(ctx, f.Get("actor_token"), TokenExchangeAudience)
	if err != nil {
		return nil, oerr(400, "invalid_grant", "actor token: "+err.Error())
	}
	if actor.ClientID != c.ID || actor.Subject != c.IdentityRef || actor.TenantSlug != subj.TenantSlug {
		return nil, oerr(400, "invalid_grant", "actor token does not belong to the authenticated agent client")
	}
	agent, err := s.GetIdentity(ctx, c.Tenant, c.IdentityRef)
	if err != nil || agent.Status != "active" || agent.Kind != "agent" {
		return nil, oerr(400, "invalid_grant", "agent identity is not active")
	}
	if owner, _ := agent.AgentProfile["ownerParty"].(string); owner != subj.Party {
		return nil, oerr(403, "access_denied", "the agent may act only for its accountable owner party (DOM-AUTH delegations arrive in S2b)")
	}
	policy, _ := s.Policies.Decide(ctx, c.Tenant, "identity.agent-delegation", map[string]any{})
	pm, _ := policy.(map[string]any)
	maxDepth := intNum(pm["maxDepth"], 3)
	if d := intNum(agent.AgentProfile["maxDelegationDepth"], maxDepth); d < maxDepth {
		maxDepth = d
	}
	if depth(subj.Act)+1 > maxDepth {
		return nil, oerr(400, "invalid_grant", "delegation chain would exceed maxDelegationDepth (RUL-IDN-2)")
	}
	requested := f.Get("scope")
	if requested == "" {
		requested = strings.Join(subj.Scopes, " ")
	}
	scope := intersect(requested, subj.Scopes)
	scope = intersect(strings.Join(scope, " "), toStrings(agent.AgentProfile["allowedScopes"]))
	if pol := toStrings(pm["allowedScopes"]); pm != nil {
		scope = intersect(strings.Join(scope, " "), pol)
	}
	if len(scope) == 0 {
		return nil, oerr(400, "invalid_scope", "no requested scope is permitted for this agent")
	}
	if aud := f.Get("audience"); aud != "" && aud != APIAudience {
		return nil, oerr(400, "invalid_target", "audience may only narrow to ucos")
	}
	jkt, err := s.dpopKey(r)
	if err != nil {
		return nil, err
	}
	if jkt == "" {
		return nil, oerr(400, "invalid_dpop_proof", "exchanged agent tokens must be sender-constrained (RUL-IDN-1)")
	}
	act := map[string]any{"sub": agent.ID, "ucos_party": agent.PartyRef}
	if subj.Act != nil {
		act["act"] = subj.Act
	}
	exp := intNum(subj.Claims["exp"], 0)
	out, err := s.issue(tokenSpec{tenant: subj.TenantSlug, identity: subj.Subject, party: subj.Party, clientID: c.ID,
		acr: subj.Acr, amr: []string{"delegated"}, roles: subj.Roles, scope: scope, aud: APIAudience, jkt: jkt, act: act,
		lifetime: s.lifetime(ctx, subj.TenantSlug), notAfter: int64(exp)})
	if err != nil {
		return nil, err
	}
	out["issued_token_type"] = "urn:ietf:params:oauth:token-type:access_token"
	return out, nil
}

// verifyOwn verifies a token this service issued for audience aud, also checking the subject's identity status.
func (s *Server) verifyOwn(ctx context.Context, token, aud string) (authn.Principal, error) {
	v := s.Self
	if aud == TokenExchangeAudience {
		v = s.SelfActor
	}
	p, err := v.VerifyToken(ctx, token)
	if err != nil {
		return p, err
	}
	if s.revoked(ctx, p.Claims["jti"], p.Subject) {
		return p, errors.New("token revoked")
	}
	return p, nil
}

func (s *Server) revoked(ctx context.Context, jti any, sub string) bool {
	j, _ := jti.(string)
	var n int
	_ = s.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM ucos_identity.revocations WHERE key = $1 OR key = $2`, j, sub).Scan(&n)
	return n > 0
}

// ---------------------------------------------------------------- introspection, revocation

// Introspect implements RFC 7662 for authenticated confidential or agent clients.
func (s *Server) Introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oerr(400, "invalid_request", "malformed form"), s.Log)
		return
	}
	if _, err := s.authenticateClient(r.Context(), r, true); err != nil {
		writeOAuthError(w, err, s.Log)
		return
	}
	token := r.PostForm.Get("token")
	h, claims, sig, input, err := authn.Parse(token)
	inactive := map[string]any{"active": false}
	if err != nil || h.Typ != "at+jwt" {
		_ = kit.JSON(w, 200, inactive)
		return
	}
	ok := false
	for _, k := range s.Keys.JWKS()["keys"].([]authn.JWK) {
		if k.Kid == h.Kid {
			pub, _ := k.ECPublicKey()
			ok = pub != nil && authn.VerifyES256(pub, input, sig)
		}
	}
	sub, _ := claims["sub"].(string)
	tenant, _ := claims["ucos_tenant"].(string)
	if !ok || int64(intNum(claims["exp"], 0)) < time.Now().Unix() || s.revoked(r.Context(), claims["jti"], sub) {
		_ = kit.JSON(w, 200, inactive)
		return
	}
	if ident, err := s.GetIdentity(r.Context(), tenant, sub); err != nil || ident.Status != "active" {
		_ = kit.JSON(w, 200, inactive)
		return
	}
	out := map[string]any{"active": true, "token_type": "access_token"}
	for k, v := range claims {
		out[k] = v
	}
	_ = kit.JSON(w, 200, out)
}

// Revoke implements RFC 7009 (revokes the jti of a presented token; unknown tokens succeed silently).
func (s *Server) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oerr(400, "invalid_request", "malformed form"), s.Log)
		return
	}
	if _, err := s.authenticateClient(r.Context(), r, false); err != nil {
		writeOAuthError(w, err, s.Log)
		return
	}
	if _, claims, _, _, err := authn.Parse(r.PostForm.Get("token")); err == nil {
		if jti, ok := claims["jti"].(string); ok {
			_, _ = s.DB.Pool.Exec(r.Context(), `INSERT INTO ucos_identity.revocations (key, kind, revoked_at) VALUES ($1, 'jti', now())
				ON CONFLICT DO NOTHING`, jti)
		}
	}
	w.WriteHeader(200)
}

// Revocations lists revoked jti/subject keys of the last 24 h for resource-server validators (CR-IDN-02).
func (s *Server) Revocations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT key FROM ucos_identity.revocations WHERE revoked_at > now() - interval '24 hours'`)
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	keys, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	if keys == nil {
		keys = []string{}
	}
	_ = kit.JSON(w, 200, map[string]any{"revoked": keys})
}

// ---------------------------------------------------------------- identity commands (PEP applied by caller)

// RegisterAgent implements RegisterAgentIdentity (INV-IDN-3): an Agent party accountable to owner, an agent identity
// with its profile, and an agent OAuth client whose secret is returned exactly once.
func (s *Server) RegisterAgent(ctx context.Context, tenant, owner, ownerIdentity, display string, profile map[string]any, corr string) (map[string]any, error) {
	policy, _ := s.Policies.Decide(ctx, tenant, "identity.agent-delegation", map[string]any{})
	pm, _ := policy.(map[string]any)
	maxDepth := intNum(pm["maxDepth"], 3)
	allowed := intersect(strings.Join(toStrings(profile["allowedScopes"]), " "), toStrings(pm["allowedScopes"]))
	if len(allowed) == 0 {
		return nil, kit.Errf(422, "E-IDN-AGENT-SCOPES", "none of the requested agent scopes is permitted by identity.agent-delegation")
	}
	d := intNum(profile["maxDelegationDepth"], maxDepth)
	if d < 1 || d > maxDepth {
		return nil, kit.Errf(422, "E-IDN-AGENT-DEPTH", "maxDelegationDepth must be 1..%d", maxDepth)
	}
	partyURN, err := s.Parties.RegisterByTypeName(ctx, tenant, owner, "Agent", map[string]any{"displayName": display,
		"accountableParty": owner}, corr)
	if err != nil {
		return nil, err
	}
	prof := map[string]any{"ownerParty": owner, "allowedScopes": allowed, "maxDelegationDepth": d}
	if m, ok := profile["modelRef"].(string); ok {
		prof["modelRef"] = m
	}
	var identity string
	err = s.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		identity, err = s.createIdentity(ctx, tx, tenant, "agent", "", "", partyURN, "AAL2", prof, ownerIdentity, corr)
		return err
	})
	if err != nil {
		return nil, err
	}
	clientID, secret := "agent-"+strings.ToLower(kit.ULID()), kit.RandomToken(32)
	if _, err := s.DB.Pool.Exec(ctx, `INSERT INTO ucos_identity.oauth_clients (client_id, tenant, kind, secret_hash, redirect_uris,
		allowed_scopes, identity_ref, created_at) VALUES ($1,$2,'agent',$3,'{}',$4,$5,now())`, clientID, tenant, kit.Hash(secret),
		allowed, identity); err != nil {
		return nil, err
	}
	return map[string]any{"identity": identity, "party": partyURN, "agentProfile": prof, "clientId": clientID,
		"clientSecret": secret}, nil
}

// Suspend implements SuspendIdentity (INV-IDN-4): no new tokens, existing ones revoked by subject.
func (s *Server) Suspend(ctx context.Context, tenant, id, actor, reason, corr string) error {
	return s.DB.InTenantTx(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE ucos_identity.identities SET status = 'suspended', revision = revision + 1
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1 AND status = 'active'`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return kit.Errf(409, "E-IDN-STATE-CONFLICT", "identity is not active")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_identity.revocations (key, kind, revoked_at) VALUES ($1, 'sub', now())
			ON CONFLICT DO NOTHING`, id); err != nil {
			return err
		}
		for _, ev := range []kit.Event{
			{Type: "ucos.identity.identity.suspended.v1", Payload: map[string]any{"id": id, "reason": reason}},
			{Type: "ucos.identity.token.revoked.v1", Payload: map[string]any{"subject": id}},
		} {
			ev.Schema, ev.AggregateID, ev.Subject, ev.Principal, ev.Tenant, ev.CorrelationID = Schema, id, id, actor, tenant, corr
			if err := kit.Append(ctx, tx, s.Source, ev); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------- tenant bootstrap (lite admin port)

// Bootstrap configures a tenant's federation, OAuth clients and admin invitations. In production this is tenant
// provisioning (DOM-TNT/DOM-RTM, later slice); ucos-lite exposes it only on the internal admin address.
func (s *Server) Bootstrap(ctx context.Context, in BootstrapRequest, invite func(ctx context.Context, tenant, email string, roles []string) error) (map[string]any, error) {
	if in.Federation.ClaimMapping == "" {
		in.Federation.ClaimMapping = `{'externalSubject': claims.sub, 'email': has(claims.email) ? claims.email : '', 'displayName': has(claims.name) ? claims.name : claims.sub}`
	}
	if _, err := s.Engine.EvalCEL(in.Federation.ClaimMapping, map[string]any{"claims": map[string]any{"sub": "probe"}}); err != nil {
		return nil, kit.Errf(422, "E-IDN-CLAIM-MAPPING", "claim mapping does not compile: %v (INV-IDN-5)", err)
	}
	fedID := "urn:ucos:" + in.Tenant + ":federation:" + kit.ULID()
	jit, _ := json.Marshal(map[string]any{"enabled": true, "defaultPartyType": "Person"})
	err := s.DB.InTenantTx(ctx, in.Tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE ucos_identity.federations SET status = 'disabled'
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_identity.federations (tenant_id, id, protocol, issuer, client_id, client_secret_enc,
			claim_mapping, jit, status, created_at) VALUES (current_setting('ucos.tenant_id')::uuid, $1, 'oidc', $2, $3, $4, $5, $6, 'active', now())`,
			fedID, in.Federation.Issuer, in.Federation.ClientID, s.KEK.Seal([]byte(in.Federation.ClientSecret), fedID),
			in.Federation.ClaimMapping, jit); err != nil {
			return err
		}
		return kit.Append(ctx, tx, s.Source, kit.Event{Schema: Schema, Type: "ucos.identity.federation.configured.v1",
			AggregateID: fedID, Subject: fedID, Principal: "urn:ucos:platform:party:bootstrap", Tenant: in.Tenant,
			Payload: map[string]any{"id": fedID, "issuer": in.Federation.Issuer, "protocol": "oidc"}})
	})
	if err != nil {
		return nil, err
	}
	for _, c := range in.Clients {
		var secretHash any
		if c.Secret != "" {
			secretHash = kit.Hash(c.Secret)
		}
		if _, err := s.DB.Pool.Exec(ctx, `INSERT INTO ucos_identity.oauth_clients (client_id, tenant, kind, secret_hash, redirect_uris,
			allowed_scopes, created_at) VALUES ($1,$2,$3,$4,$5,$6,now()) ON CONFLICT (client_id) DO UPDATE SET redirect_uris = EXCLUDED.redirect_uris,
			allowed_scopes = EXCLUDED.allowed_scopes`, c.ClientID, in.Tenant, c.Kind, secretHash, c.RedirectURIs, c.AllowedScopes); err != nil {
			return nil, err
		}
	}
	for _, inv := range in.Invitations {
		if err := invite(ctx, in.Tenant, strings.ToLower(inv.Email), inv.Roles); err != nil {
			return nil, err
		}
	}
	return map[string]any{"tenant": in.Tenant, "federation": fedID, "clients": len(in.Clients), "invitations": len(in.Invitations)}, nil
}

// BootstrapRequest is the lite tenant bootstrap input.
type BootstrapRequest struct {
	Tenant     string `json:"tenant"`
	Federation struct {
		Issuer       string `json:"issuer"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		ClaimMapping string `json:"claimMapping"`
	} `json:"federation"`
	Clients []struct {
		ClientID      string   `json:"clientId"`
		Kind          string   `json:"kind"`
		Secret        string   `json:"secret"`
		RedirectURIs  []string `json:"redirectUris"`
		AllowedScopes []string `json:"allowedScopes"`
	} `json:"clients"`
	Invitations []struct {
		Email string   `json:"email"`
		Roles []string `json:"roles"`
	} `json:"invitations"`
}

// Init prepares the federation HTTP client.
func (s *Server) Init() { s.fed.http = &http.Client{Timeout: 10 * time.Second} }
