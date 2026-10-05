-- Standard tables for context schema {schema} (contracts/persistence/standard-tables.yaml, CIC-003-001 §4),
-- expanded by tools/migrate.py from the directive `-- ucos:standard-tables {schema} {app} {relay}`.
CREATE TABLE {schema}.event_store (
  tenant_id uuid NOT NULL, aggregate_type text NOT NULL, aggregate_id char(26) NOT NULL, sequence bigint NOT NULL,
  event_id char(26) NOT NULL, event_type text NOT NULL, schema_version text NOT NULL, occurred_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(), correlation_id char(26) NOT NULL, causation_id char(26),
  principal text NOT NULL, payload jsonb NOT NULL, payload_enc_key text,
  PRIMARY KEY (tenant_id, aggregate_id, sequence, recorded_at)
) PARTITION BY RANGE (recorded_at);
CREATE TABLE {schema}.event_store_default PARTITION OF {schema}.event_store DEFAULT;
CREATE UNIQUE INDEX ON {schema}.event_store (event_id, recorded_at);
CREATE UNIQUE INDEX ON {schema}.event_store_default (tenant_id, aggregate_id, sequence);
CREATE TABLE {schema}.outbox (
  id bigserial PRIMARY KEY, event_id char(26) NOT NULL UNIQUE, topic text NOT NULL, partition_key text NOT NULL,
  envelope jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz
);
CREATE INDEX ON {schema}.outbox (created_at) WHERE published_at IS NULL;
CREATE TABLE {schema}.snapshots (
  tenant_id uuid NOT NULL, aggregate_id char(26) NOT NULL, sequence bigint NOT NULL, state jsonb, taken_at timestamptz,
  PRIMARY KEY (tenant_id, aggregate_id, sequence)
);
CREATE TABLE {schema}.processed_messages (
  consumer text NOT NULL, event_id char(26) NOT NULL, processed_at timestamptz, PRIMARY KEY (consumer, event_id)
);
-- ucos:tenant-rls {schema}.event_store {schema}.event_store_default {schema}.snapshots
GRANT USAGE ON SCHEMA {schema} TO {app}, {relay};
GRANT SELECT, INSERT ON {schema}.event_store, {schema}.snapshots, {schema}.processed_messages TO {app};
GRANT INSERT ON {schema}.outbox TO {app};
GRANT USAGE ON SEQUENCE {schema}.outbox_id_seq TO {app};
GRANT SELECT, UPDATE ON {schema}.outbox TO {relay};
