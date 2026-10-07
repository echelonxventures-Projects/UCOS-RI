-- supply-service bookkeeping (ucos-lite composition of INV, AVL): Idempotency-Key replay records.
-- Context data lives in each context's own schema.
CREATE SCHEMA ucos_supply_service AUTHORIZATION ucos_owner;
CREATE TABLE ucos_supply_service.idempotency_keys (
  tenant_id uuid NOT NULL, key text NOT NULL, principal text NOT NULL, request_hash text NOT NULL,
  status int NOT NULL, response jsonb, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key)
);
-- ucos:tenant-rls ucos_supply_service.idempotency_keys
-- Every ucos_* schema carries the standard tables (CIC-003-001 §4); this one's event store stays empty.
-- ucos:standard-tables ucos_supply_service ucos_supply_app ucos_supply_relay
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_supply_service.idempotency_keys TO ucos_supply_app;
