-- DOM-AVL (S4b): availability — ATP projection, sellability rules, sourcing policies, node calendars,
-- lead times and the derived availability status. Schema ucos_supply is shared with DOM-INV (S4a);
-- each context keeps its own tables (CIC-030-001 §2).
CREATE SCHEMA IF NOT EXISTS ucos_supply AUTHORIZATION ucos_owner;

-- ATP projection maintained from ucos.supply.inventory.* events (AtpProjector, CIC-011-006 §2).
-- Kept per (object, node) with the inventory version so caches can key on it (CIC-011-006 §4).
CREATE TABLE ucos_supply.atp_projection (
  tenant_id uuid NOT NULL, object_ref text NOT NULL, node_ref text NOT NULL,
  on_hand numeric(38,9) NOT NULL DEFAULT 0, reserved numeric(38,9) NOT NULL DEFAULT 0,
  safety_stock numeric(38,9) NOT NULL DEFAULT 0, inbound numeric(38,9) NOT NULL DEFAULT 0,
  inbound_at timestamptz,                       -- earliest expected receipt within the horizon
  version bigint NOT NULL DEFAULT 0, updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, object_ref, node_ref)
);

-- Sellability rules (fact kind sellability-rule, owning context supply, regulated). Conflict 'all'
-- with deny-overrides; every deny carries a reason code (RUL-AVL-1).
CREATE TABLE ucos_supply.sellability_rules (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, code text NOT NULL,
  object_ref text NOT NULL DEFAULT '', type_ref text NOT NULL DEFAULT '',
  effect text NOT NULL, reason_code text NOT NULL DEFAULT '',
  scope jsonb NOT NULL DEFAULT '[]', condition text NOT NULL DEFAULT '',
  regulated boolean NOT NULL DEFAULT false, valid_from timestamptz NOT NULL DEFAULT now(),
  valid_to timestamptz, revision bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, code)
);
CREATE INDEX ON ucos_supply.sellability_rules (tenant_id, object_ref) WHERE object_ref <> '';
CREATE INDEX ON ucos_supply.sellability_rules (tenant_id, type_ref) WHERE type_ref <> '';

-- Sourcing policies: which nodes may fulfil which contexts, and the objective weights (DEC-AVL-2).
CREATE TABLE ucos_supply.sourcing_policies (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, scope jsonb NOT NULL DEFAULT '[]',
  body jsonb NOT NULL DEFAULT '{}', valid_from timestamptz NOT NULL DEFAULT now(),
  valid_to timestamptz, revision bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id)
);

-- Node calendars: working hours, holidays and cut-offs in the node's timezone (RUL-AVL-3, AVL-C5).
CREATE TABLE ucos_supply.node_calendars (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, node_ref text NOT NULL, body jsonb NOT NULL DEFAULT '{}',
  revision bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, node_ref)
);

-- Lead times: processing and transit durations by scope (AVL-C3).
CREATE TABLE ucos_supply.lead_times (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, scope jsonb NOT NULL DEFAULT '[]',
  body jsonb NOT NULL DEFAULT '{}', revision bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id)
);

-- Derived availability status per (object, context class); changed on threshold crossings
-- (AvailabilityStatus machine; ucos.supply.availability.status-changed.v1).
CREATE TABLE ucos_supply.availability_status (
  tenant_id uuid NOT NULL, object_ref text NOT NULL, context_class text NOT NULL,
  status text NOT NULL, changed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, object_ref, context_class)
);

-- ucos:tenant-rls ucos_supply.atp_projection ucos_supply.sellability_rules ucos_supply.sourcing_policies
-- ucos:tenant-rls ucos_supply.node_calendars ucos_supply.lead_times ucos_supply.availability_status
-- ucos:standard-tables ucos_supply ucos_supply_app ucos_supply_relay
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_supply.atp_projection TO ucos_supply_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_supply.sellability_rules TO ucos_supply_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_supply.sourcing_policies TO ucos_supply_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_supply.node_calendars TO ucos_supply_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_supply.lead_times TO ucos_supply_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_supply.availability_status TO ucos_supply_app;
