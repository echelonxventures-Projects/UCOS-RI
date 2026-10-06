-- DOM-PRC (S3c): price lists, MVCC price entries (snapshot ranges for replay), snapshot versions and pricing snapshots.
CREATE SCHEMA ucos_pricing AUTHORIZATION ucos_owner;

CREATE TABLE ucos_pricing.price_lists (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, urn text NOT NULL, code text NOT NULL, label jsonb NOT NULL,
  currency text NOT NULL, multi_currency boolean NOT NULL, scope jsonb NOT NULL, priority int NOT NULL,
  valid_from timestamptz NOT NULL, valid_to timestamptz, based_on text, derivation text,
  state text NOT NULL CHECK (state IN ('draft','in-review','approved','scheduled','published','superseded','retired')),
  version int NOT NULL, effective_at timestamptz, author text NOT NULL, approvals jsonb NOT NULL, plan jsonb,
  revision bigint NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ON ucos_pricing.price_lists (tenant_id, code, version);

-- An entry may have several row versions: [snapshot_from, snapshot_to) says in which snapshot versions a row is the
-- published truth (NULL snapshot_from = draft row; NULL snapshot_to = current).
CREATE TABLE ucos_pricing.price_entries (
  tenant_id uuid NOT NULL, list_id char(26) NOT NULL, entry_id char(26) NOT NULL, row_seq int NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('object','type')), subject text NOT NULL, charge_type text NOT NULL,
  model jsonb NOT NULL, scope jsonb NOT NULL, scope_digest text NOT NULL, priority int NOT NULL, currency text NOT NULL,
  recurrence jsonb, meter_ref text, valid_from timestamptz NOT NULL, valid_to timestamptz,
  snapshot_from bigint, snapshot_to bigint,
  PRIMARY KEY (tenant_id, list_id, entry_id, row_seq)
);
CREATE INDEX ON ucos_pricing.price_entries (tenant_id, subject, charge_type) INCLUDE (scope_digest, valid_from, valid_to, snapshot_from, snapshot_to);

CREATE TABLE ucos_pricing.snapshot_versions (
  tenant_id uuid NOT NULL PRIMARY KEY, version bigint NOT NULL
);
CREATE TABLE ucos_pricing.pricing_snapshots (
  tenant_id uuid NOT NULL, snapshot_id text NOT NULL, snapshot_version bigint NOT NULL, as_of timestamptz NOT NULL,
  request jsonb NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, snapshot_id)
);
-- ucos:tenant-rls ucos_pricing.price_lists ucos_pricing.price_entries ucos_pricing.snapshot_versions ucos_pricing.pricing_snapshots
-- ucos:standard-tables ucos_pricing ucos_commerce_app ucos_commerce_relay
GRANT SELECT, INSERT, UPDATE ON ucos_pricing.price_lists, ucos_pricing.price_entries, ucos_pricing.snapshot_versions TO ucos_commerce_app;
GRANT SELECT, INSERT ON ucos_pricing.pricing_snapshots TO ucos_commerce_app;
