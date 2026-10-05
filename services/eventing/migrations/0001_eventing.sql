-- ucos_eventing (DOM-EVT): platform-wide event type + schema registry. Language-neutral: every
-- event-platform-service implementation (go/, typescript/) runs against exactly this schema (CR-030-001-05).
CREATE SCHEMA ucos_eventing AUTHORIZATION ucos_owner;
CREATE TABLE ucos_eventing.event_types (
  type text PRIMARY KEY,
  owning_context text NOT NULL,
  category text NOT NULL CHECK (category IN ('domain', 'integration', 'command')),
  classification text NOT NULL,
  retention jsonb NOT NULL,
  external_subscribable boolean NOT NULL,
  state text NOT NULL,
  registered_at timestamptz NOT NULL
);
CREATE INDEX ON ucos_eventing.event_types (owning_context);
CREATE TABLE ucos_eventing.schema_versions (
  type text NOT NULL REFERENCES ucos_eventing.event_types(type),
  semver text NOT NULL,
  major integer NOT NULL, minor integer NOT NULL, patch integer NOT NULL,
  schema_text text NOT NULL,          -- RFC 8785 canonical JSON, returned verbatim
  digest text NOT NULL,
  compatibility text NOT NULL,
  registered_at timestamptz NOT NULL,
  PRIMARY KEY (type, semver)
);
-- ucos:standard-tables ucos_eventing ucos_eventing_app ucos_eventing_relay
GRANT SELECT, INSERT ON ucos_eventing.event_types, ucos_eventing.schema_versions TO ucos_eventing_app;
