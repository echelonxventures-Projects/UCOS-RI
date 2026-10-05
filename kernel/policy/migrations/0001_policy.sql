-- ucos_policy: governed definitions owned by this context (governed.Store).
CREATE SCHEMA ucos_policy AUTHORIZATION ucos_owner;
CREATE TABLE ucos_policy.definitions (
  tenant_id uuid NOT NULL, urn text NOT NULL, kind text NOT NULL, namespace text NOT NULL, name text NOT NULL,
  version text NOT NULL, state text NOT NULL CHECK (state IN ('draft','in-review','published','deprecated','retired')),
  body jsonb NOT NULL, digest text NOT NULL, change_set_ref text, revision bigint NOT NULL,
  created_at timestamptz NOT NULL, published_at timestamptz,
  PRIMARY KEY (tenant_id, urn)
);
CREATE INDEX ON ucos_policy.definitions (tenant_id, kind, state);
-- ucos:tenant-rls ucos_policy.definitions
-- ucos:standard-tables ucos_policy ucos_kernel_app ucos_kernel_relay
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_policy.definitions TO ucos_kernel_app;
