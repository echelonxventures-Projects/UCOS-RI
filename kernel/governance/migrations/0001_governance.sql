-- ucos_governance: ChangeSets (CIC-015-001 §2), state-stored + outbox.
CREATE SCHEMA ucos_governance AUTHORIZATION ucos_owner;
CREATE TABLE ucos_governance.changesets (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, state text NOT NULL, author text NOT NULL, body jsonb NOT NULL,
  revision bigint NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ON ucos_governance.changesets (tenant_id, state);
-- ucos:tenant-rls ucos_governance.changesets
-- ucos:standard-tables ucos_governance ucos_kernel_app ucos_kernel_relay
GRANT SELECT, INSERT, UPDATE ON ucos_governance.changesets TO ucos_kernel_app;
