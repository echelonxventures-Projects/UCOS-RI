-- echo context schema: state-stored + outbox persistence style (CIC-003-001 §4), tenancy (§5).
-- Applied by the migrator as ucos_owner; service roles never run DDL (CIC-014-001 §3).
CREATE SCHEMA ucos_echo AUTHORIZATION ucos_owner;

CREATE TABLE ucos_echo.messages (
  tenant_id   uuid        NOT NULL,
  id          char(26)    NOT NULL,
  text        text        NOT NULL CHECK (char_length(text) BETWEEN 1 AND 280),
  status      text        NOT NULL CHECK (status IN ('accepted', 'echoed')),
  revision    bigint      NOT NULL CHECK (revision >= 1),
  accepted_at timestamptz NOT NULL,
  echoed_at   timestamptz,
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE ucos_echo.idempotency_keys (       -- CIC-005-001 §3, retained 24 h (reclaimed after expiry)
  tenant_id    uuid        NOT NULL,
  key          text        NOT NULL,
  request_hash text        NOT NULL,
  status       integer,
  headers      jsonb,
  body         bytea,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key)
);

-- Standard tables (contracts/persistence/standard-tables.yaml).
CREATE TABLE ucos_echo.event_store (
  tenant_id       uuid        NOT NULL,
  aggregate_type  text        NOT NULL,
  aggregate_id    char(26)    NOT NULL,
  sequence        bigint      NOT NULL,
  event_id        char(26)    NOT NULL,
  event_type      text        NOT NULL,
  schema_version  text        NOT NULL,
  occurred_at     timestamptz NOT NULL,
  recorded_at     timestamptz NOT NULL DEFAULT now(),
  correlation_id  char(26)    NOT NULL,
  causation_id    char(26),
  principal       text        NOT NULL,
  payload         jsonb       NOT NULL,
  payload_enc_key text,
  PRIMARY KEY (tenant_id, aggregate_id, sequence, recorded_at)
) PARTITION BY RANGE (recorded_at);
CREATE TABLE ucos_echo.event_store_default PARTITION OF ucos_echo.event_store DEFAULT;
CREATE UNIQUE INDEX ON ucos_echo.event_store (event_id, recorded_at);
-- Gapless per-aggregate sequence regardless of recorded_at (the PK includes recorded_at for partitioning).
CREATE UNIQUE INDEX event_store_default_sequence ON ucos_echo.event_store_default (tenant_id, aggregate_id, sequence);

CREATE TABLE ucos_echo.outbox (
  id            bigserial PRIMARY KEY,
  event_id      char(26) NOT NULL UNIQUE,
  topic         text     NOT NULL,
  partition_key text     NOT NULL,
  envelope      jsonb    NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  published_at  timestamptz
);
CREATE INDEX ON ucos_echo.outbox (created_at) WHERE published_at IS NULL;

CREATE TABLE ucos_echo.snapshots (
  tenant_id uuid NOT NULL, aggregate_id char(26) NOT NULL, sequence bigint NOT NULL, state jsonb, taken_at timestamptz,
  PRIMARY KEY (tenant_id, aggregate_id, sequence)
);

CREATE TABLE ucos_echo.processed_messages (
  consumer text NOT NULL, event_id char(26) NOT NULL, processed_at timestamptz,
  PRIMARY KEY (consumer, event_id)
);

-- Row-level security on every tenant table, forced (applies to the owner too), partitions included.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['messages', 'idempotency_keys', 'event_store', 'event_store_default', 'snapshots'] LOOP
    EXECUTE format('ALTER TABLE ucos_echo.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE ucos_echo.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON ucos_echo.%I
                     USING (tenant_id = current_setting('ucos.tenant_id')::uuid)
                     WITH CHECK (tenant_id = current_setting('ucos.tenant_id')::uuid)$p$, t);
  END LOOP;
END $$;

-- Least-privilege grants.
GRANT USAGE ON SCHEMA ucos_echo TO ucos_echo_app, ucos_echo_relay;
GRANT SELECT, INSERT, UPDATE ON ucos_echo.messages, ucos_echo.idempotency_keys TO ucos_echo_app;
GRANT SELECT, INSERT ON ucos_echo.event_store, ucos_echo.snapshots, ucos_echo.processed_messages TO ucos_echo_app;
GRANT INSERT ON ucos_echo.outbox TO ucos_echo_app;
GRANT USAGE ON SEQUENCE ucos_echo.outbox_id_seq TO ucos_echo_app;
GRANT SELECT, UPDATE ON ucos_echo.outbox TO ucos_echo_relay;
