-- S2c (ADR 0009): DOM-AUTH role-assignment lifecycle, delegations, governed SoD conflict sets and authority limits,
-- mandates; party cut-offs in the token revocation feed. Expand-only: no existing column changes meaning.

-- Role assignments: revocation keeps history (validity and evidence, DOM-AUTH retention 7 years).
ALTER TABLE ucos_party.role_assignments
  ADD COLUMN last_certified_at timestamptz,
  ADD COLUMN revoked_at timestamptz,
  ADD COLUMN revoked_by text,
  ADD COLUMN revoke_reason text;
CREATE INDEX ON ucos_party.role_assignments (tenant_id, role);

-- Delegations (INV-AUTH-4/5): narrowing only; depth is the chain length through parent_id.
CREATE TABLE ucos_party.delegations (
  tenant_id uuid NOT NULL, id text NOT NULL, delegator text NOT NULL, delegate text NOT NULL, body jsonb NOT NULL,
  valid_from timestamptz NOT NULL, valid_to timestamptz NOT NULL, parent_id text, depth int NOT NULL CHECK (depth >= 1),
  granted_by text NOT NULL, created_at timestamptz NOT NULL, revoked_at timestamptz, revoke_reason text,
  PRIMARY KEY (tenant_id, id),
  CHECK (valid_to > valid_from),
  CHECK (delegator <> delegate)
);
CREATE INDEX ON ucos_party.delegations (tenant_id, delegate, valid_to);
CREATE INDEX ON ucos_party.delegations (tenant_id, delegator);
CREATE INDEX ON ucos_party.delegations (tenant_id, parent_id);

-- Governed definitions owned by DOM-AUTH: drafted through the authority API, published only by a GOV ChangeSet
-- (remote owner protocol, contracts/governance/remote-owner.openapi.yaml).
CREATE TABLE ucos_party.sod_sets (
  tenant_id uuid NOT NULL, urn text NOT NULL, body jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('draft','published')), digest text NOT NULL, change_set_ref text,
  revision bigint NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL, published_at timestamptz,
  existing_violations jsonb,
  PRIMARY KEY (tenant_id, urn)
);
CREATE TABLE ucos_party.authority_limits (
  tenant_id uuid NOT NULL, id text NOT NULL, holder text NOT NULL, action text NOT NULL, measure text NOT NULL,
  limit_value jsonb NOT NULL, scope jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('draft','published')), digest text NOT NULL, change_set_ref text,
  revision bigint NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL, published_at timestamptz,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ON ucos_party.authority_limits (tenant_id, holder);

-- Mandates (INV-AUTH-6): evidence-backed; `used` accumulates consumption per currency.
CREATE TABLE ucos_party.mandates (
  tenant_id uuid NOT NULL, id text NOT NULL, grantor text NOT NULL, holder text NOT NULL, body jsonb NOT NULL,
  used jsonb NOT NULL, status text NOT NULL CHECK (status IN ('active','revoked','expired','exhausted')),
  valid_to timestamptz NOT NULL, recorded_by text NOT NULL, created_at timestamptz NOT NULL, revoked_at timestamptz,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ON ucos_party.mandates (tenant_id, holder);
-- ucos:tenant-rls ucos_party.delegations ucos_party.sod_sets ucos_party.authority_limits ucos_party.mandates

GRANT SELECT, INSERT, UPDATE ON ucos_party.delegations, ucos_party.sod_sets, ucos_party.authority_limits,
  ucos_party.mandates TO ucos_identity_app;
GRANT DELETE ON ucos_party.sod_sets, ucos_party.authority_limits TO ucos_identity_app;

-- Revocation feed: kind 'party' = tokens of that party (as subject or actor) issued at or before revoked_at are stale.
ALTER TABLE ucos_identity.revocations DROP CONSTRAINT revocations_kind_check;
ALTER TABLE ucos_identity.revocations ADD CONSTRAINT revocations_kind_check CHECK (kind IN ('jti','sub','party'));
