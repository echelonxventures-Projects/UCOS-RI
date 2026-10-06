-- S2d (ADR 0010, DOM-AUTH 1.2.0, CIC-002-003 §9-12): assignment approval, access reviews, tenant role definitions,
-- mandate usage, and Idempotency-Key replay for identity-service commands. Expand-only.

ALTER TABLE ucos_party.role_assignments
  ADD COLUMN status text NOT NULL DEFAULT 'active' CHECK (status IN ('pending-approval','active','rejected')),
  ADD COLUMN approved_by text,
  ADD COLUMN approved_at timestamptz,
  ADD COLUMN rejected_at timestamptz,
  ADD COLUMN reject_reason text;

-- Tenant role definitions (DefineRole): governed definitions published by DOM-GOV through the remote owner protocol.
CREATE TABLE ucos_party.role_definitions (
  tenant_id uuid NOT NULL, urn text NOT NULL, code text NOT NULL, body jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('draft','published')), digest text NOT NULL, change_set_ref text,
  revision bigint NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL, published_at timestamptz,
  PRIMARY KEY (tenant_id, urn),
  UNIQUE (tenant_id, code)
);

-- Access reviews (AUTH-C6): items and decisions live in body; status open | completed (overdue is derived).
CREATE TABLE ucos_party.access_reviews (
  tenant_id uuid NOT NULL, review_id text NOT NULL, body jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('open','completed')), due_at timestamptz NOT NULL, created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, review_id)
);

-- Mandate usage (RecordMandateUsage): idempotent per (mandate, reference).
CREATE TABLE ucos_party.mandate_usages (
  tenant_id uuid NOT NULL, mandate_id text NOT NULL, reference text NOT NULL, amount jsonb NOT NULL,
  recorded_by text NOT NULL, recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, mandate_id, reference)
);

-- Idempotency-Key replay (CIC-005-001): responses are sealed under the KEK (they may hold personal data or secrets).
CREATE TABLE ucos_identity.idempotency_keys (
  tenant_id uuid NOT NULL, key text NOT NULL, principal text NOT NULL, request_hash text NOT NULL,
  status int NOT NULL, content_type text, body_enc text, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key)
);
-- ucos:tenant-rls ucos_party.role_definitions ucos_party.access_reviews ucos_party.mandate_usages ucos_identity.idempotency_keys

GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_party.role_definitions, ucos_party.access_reviews, ucos_identity.idempotency_keys
  TO ucos_identity_app;
GRANT SELECT, INSERT ON ucos_party.mandate_usages TO ucos_identity_app;
