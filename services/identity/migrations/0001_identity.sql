-- identity-service schemas: ucos_identity (DOM-IDN), ucos_party (DOM-PTY + DOM-AUTH, per their specs).
CREATE SCHEMA ucos_identity AUTHORIZATION ucos_owner;
CREATE SCHEMA ucos_party AUTHORIZATION ucos_owner;

-- Tenant data ------------------------------------------------------------------------------------------
CREATE TABLE ucos_identity.identities (
  tenant_id uuid NOT NULL, id text NOT NULL, kind text NOT NULL CHECK (kind IN ('human','service','device','agent')),
  federation_ref text, subject_digest text, subject_enc text, party_ref text, binding jsonb,
  status text NOT NULL CHECK (status IN ('active','suspended')), agent_profile jsonb,
  revision bigint NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, federation_ref, subject_digest)                      -- INV-IDN-1
);
CREATE TABLE ucos_identity.federations (
  tenant_id uuid NOT NULL, id text NOT NULL, protocol text NOT NULL CHECK (protocol = 'oidc'), issuer text NOT NULL,
  client_id text NOT NULL, client_secret_enc text NOT NULL, claim_mapping text NOT NULL, jit jsonb NOT NULL,
  status text NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE ucos_party.parties (
  tenant_id uuid NOT NULL, id text NOT NULL, type_ref text NOT NULL, values_enc jsonb NOT NULL,
  subject_key_enc text NOT NULL, status text NOT NULL, revision bigint NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE ucos_party.role_assignments (
  tenant_id uuid NOT NULL, id text NOT NULL, party text NOT NULL, role text NOT NULL, scope jsonb NOT NULL,
  valid_from timestamptz NOT NULL, valid_to timestamptz, assigned_by text NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ON ucos_party.role_assignments (tenant_id, party);
CREATE TABLE ucos_party.invitations (
  tenant_id uuid NOT NULL, email_digest text NOT NULL, roles text[] NOT NULL, invited_by text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, email_digest)
);
-- ucos:tenant-rls ucos_identity.identities ucos_identity.federations ucos_party.parties ucos_party.role_assignments ucos_party.invitations

-- Platform-wide token-service bookkeeping (no tenant data; AMD-0002) --------------------------------------
CREATE TABLE ucos_identity.oauth_clients (
  client_id text PRIMARY KEY, tenant text NOT NULL, kind text NOT NULL CHECK (kind IN ('public','confidential','agent')),
  secret_hash text, redirect_uris text[] NOT NULL, allowed_scopes text[] NOT NULL, identity_ref text,
  created_at timestamptz NOT NULL
);
CREATE TABLE ucos_identity.signing_keys (
  kid text PRIMARY KEY, private_enc text NOT NULL, public_jwk jsonb NOT NULL, created_at timestamptz NOT NULL,
  retired_at timestamptz
);
CREATE TABLE ucos_identity.login_requests (
  state text PRIMARY KEY, tenant text NOT NULL, client_id text NOT NULL, redirect_uri text NOT NULL,
  client_state text NOT NULL, code_challenge text NOT NULL, scope text NOT NULL, federation_id text NOT NULL,
  nonce text NOT NULL, idp_verifier text NOT NULL, created_at timestamptz NOT NULL
);
CREATE TABLE ucos_identity.auth_codes (
  code_hash text PRIMARY KEY, tenant text NOT NULL, client_id text NOT NULL, redirect_uri text NOT NULL,
  code_challenge text NOT NULL, identity text NOT NULL, scope text NOT NULL, acr text NOT NULL, amr text[] NOT NULL,
  expires_at timestamptz NOT NULL, used_at timestamptz
);
CREATE TABLE ucos_identity.revocations (
  key text PRIMARY KEY, kind text NOT NULL CHECK (kind IN ('jti','sub')), revoked_at timestamptz NOT NULL
);

-- ucos:standard-tables ucos_identity ucos_identity_app ucos_identity_relay
-- ucos:standard-tables ucos_party ucos_identity_app ucos_identity_relay
GRANT SELECT, INSERT, UPDATE ON ucos_identity.identities, ucos_identity.federations, ucos_party.parties TO ucos_identity_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_party.role_assignments, ucos_party.invitations TO ucos_identity_app;
GRANT SELECT, INSERT, UPDATE ON ucos_identity.oauth_clients, ucos_identity.signing_keys, ucos_identity.auth_codes,
  ucos_identity.revocations TO ucos_identity_app;
GRANT SELECT, INSERT, DELETE ON ucos_identity.login_requests TO ucos_identity_app;
