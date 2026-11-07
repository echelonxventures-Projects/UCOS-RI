-- DOM-INV (S4a): inventory positions, the append-only movement ledger, reservations, capacity pools and
-- expected receipts. Schema ucos_supply is shared with DOM-AVL (S4b); each context keeps its own tables.
-- Serial/lot tracking and finite resource pools arrive with the slice that consumes them (ADR 0013).
CREATE SCHEMA ucos_supply AUTHORIZATION ucos_owner;

-- Positions: (object, node, stock status, lot) with onHand maintained from the ledger in the same
-- transaction (INV-INV-3); reserved is maintained from the reservations table (RUL-INV-1 serialization).
CREATE TABLE ucos_supply.positions (
  tenant_id uuid NOT NULL, object_ref text NOT NULL, node_ref text NOT NULL, stock_status text NOT NULL,
  lot_ref text NOT NULL DEFAULT '', on_hand numeric(38,9) NOT NULL DEFAULT 0, reserved numeric(38,9) NOT NULL DEFAULT 0,
  safety_stock numeric(38,9) NOT NULL DEFAULT 0, version bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, object_ref, node_ref, stock_status, lot_ref)
);
CREATE INDEX ON ucos_supply.positions (tenant_id, object_ref, node_ref);
-- Fast "below safety stock" scan for FindPositions.
CREATE INDEX ON ucos_supply.positions (tenant_id, (on_hand - reserved - safety_stock)) WHERE on_hand - reserved - safety_stock < 0;

-- Append-only ledger (INV-INV-3). Idempotent on the derived key (sourceDocument, lineRef, type): RUL-INV-2.
CREATE TABLE ucos_supply.movements (
  tenant_id uuid NOT NULL, movement_id char(26) NOT NULL, type text NOT NULL, object_ref text NOT NULL,
  node_ref text NOT NULL, quantity numeric(38,9) NOT NULL, from_status text, to_status text, lot_ref text NOT NULL DEFAULT '',
  serials text[] NOT NULL DEFAULT '{}', source_document text NOT NULL, idempotency_key text NOT NULL,
  reason_code text, occurred_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, movement_id, occurred_at)
);
CREATE UNIQUE INDEX ON ucos_supply.movements (tenant_id, idempotency_key);   -- RUL-INV-2 (one ledger entry per key)
CREATE INDEX ON ucos_supply.movements (tenant_id, object_ref, node_ref, occurred_at);

-- Reservations: soft (TTL) or hard; lines reference positions (INV-INV-4).
CREATE TABLE ucos_supply.reservations (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, source_ref text NOT NULL, kind text NOT NULL,
  lines jsonb NOT NULL, status text NOT NULL, expires_at timestamptz, revision bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX ON ucos_supply.reservations (tenant_id, source_ref);
CREATE INDEX ON ucos_supply.reservations (tenant_id, status, expires_at) WHERE status = 'active';

-- Capacity pools: time-slotted capacity for services and experiences (INV-INV-5).
CREATE TABLE ucos_supply.capacity_pools (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, resource_ref text NOT NULL, label jsonb NOT NULL DEFAULT '{}',
  slot_duration text NOT NULL, capacity_per_slot numeric(38,9) NOT NULL, timezone text NOT NULL,
  exceptions jsonb NOT NULL DEFAULT '[]', revision bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE ucos_supply.capacity_bookings (
  tenant_id uuid NOT NULL, pool_id char(26) NOT NULL, slot_start timestamptz NOT NULL, booking_id char(26) NOT NULL,
  quantity numeric(38,9) NOT NULL, source_ref text NOT NULL, status text NOT NULL,
  PRIMARY KEY (tenant_id, pool_id, slot_start, booking_id)
);

-- Expected receipts feed ATP (DOM-AVL, S4b).
CREATE TABLE ucos_supply.expected_receipts (
  tenant_id uuid NOT NULL, object_ref text NOT NULL, node_ref text NOT NULL, expected_at timestamptz NOT NULL,
  quantity numeric(38,9) NOT NULL, source_document text NOT NULL,
  PRIMARY KEY (tenant_id, source_document, object_ref)
);
CREATE INDEX ON ucos_supply.expected_receipts (tenant_id, object_ref, node_ref, expected_at);

-- ucos:tenant-rls ucos_supply.positions ucos_supply.movements ucos_supply.reservations
-- ucos:tenant-rls ucos_supply.capacity_pools ucos_supply.capacity_bookings ucos_supply.expected_receipts
-- ucos:standard-tables ucos_supply ucos_supply_app ucos_supply_relay
GRANT SELECT, INSERT, UPDATE ON ucos_supply.positions, ucos_supply.reservations TO ucos_supply_app;
GRANT SELECT, INSERT ON ucos_supply.movements, ucos_supply.expected_receipts, ucos_supply.capacity_bookings TO ucos_supply_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_supply.capacity_pools TO ucos_supply_app;
GRANT DELETE ON ucos_supply.capacity_bookings TO ucos_supply_app;
GRANT UPDATE ON ucos_supply.expected_receipts TO ucos_supply_app;
