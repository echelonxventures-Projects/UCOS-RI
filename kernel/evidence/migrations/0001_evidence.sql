-- ucos_evidence: WORM evidence with per-tenant RFC 6962 ledger (INV-EVD-1/2). No UPDATE/DELETE grant: append-only.
CREATE SCHEMA ucos_evidence AUTHORIZATION ucos_owner;
CREATE TABLE ucos_evidence.evidence (
  tenant_id uuid NOT NULL, id text NOT NULL, kind text NOT NULL, digest text NOT NULL, content jsonb NOT NULL,
  links jsonb NOT NULL, captured_by text NOT NULL, captured_at timestamptz NOT NULL,
  ledger_index bigint NOT NULL, leaf_hash text NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, ledger_index)
);
-- ucos:tenant-rls ucos_evidence.evidence
-- ucos:standard-tables ucos_evidence ucos_kernel_app ucos_kernel_relay
GRANT SELECT, INSERT ON ucos_evidence.evidence TO ucos_kernel_app;
