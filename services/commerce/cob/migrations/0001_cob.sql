-- DOM-COB (S3a): commercial objects with contextual values, composition, variants and lifecycle history.
-- Schema per the DOM spec persistence model; no type-specific tables or columns (UCOS-L001).
CREATE SCHEMA ucos_cob AUTHORIZATION ucos_owner;

CREATE TABLE ucos_cob.commercial_objects (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, urn text NOT NULL, type_urn text NOT NULL, type_major int NOT NULL,
  type_lineage text[] NOT NULL,                       -- linearization of the pinned type (FindCommercialObjects by supertype)
  lifecycle_model text NOT NULL, lifecycle_state text NOT NULL,
  natural_key jsonb NOT NULL, natural_key_digest text NOT NULL,
  base_values jsonb NOT NULL, facets_config jsonb NOT NULL, composition jsonb,
  variant_of char(26), owning_party text NOT NULL, home_region text NOT NULL,
  revision bigint NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, natural_key_digest)               -- INV-COB-4 (uniquenessScope tenant)
);
CREATE INDEX ON ucos_cob.commercial_objects (tenant_id, type_urn, lifecycle_state);
CREATE INDEX ON ucos_cob.commercial_objects USING gin (type_lineage);
CREATE INDEX ON ucos_cob.commercial_objects (tenant_id, variant_of);

CREATE TABLE ucos_cob.contextual_values (
  tenant_id uuid NOT NULL, object_id char(26) NOT NULL, attribute_code text NOT NULL, scope jsonb NOT NULL,
  scope_digest text NOT NULL, priority int NOT NULL, valid_from timestamptz NOT NULL, valid_to timestamptz,
  value jsonb NOT NULL, entry_id char(26) NOT NULL,
  PRIMARY KEY (tenant_id, object_id, attribute_code, scope_digest, valid_from)
);
CREATE INDEX ON ucos_cob.contextual_values (tenant_id, object_id, attribute_code);

CREATE TABLE ucos_cob.external_references (
  tenant_id uuid NOT NULL, object_id char(26) NOT NULL, scheme text NOT NULL, issuer text NOT NULL, value text NOT NULL,
  PRIMARY KEY (tenant_id, scheme, issuer, value)
);

-- Lifecycle history: who performed which transition (SoD, policy inputs such as submittedBy).
CREATE TABLE ucos_cob.lifecycle_history (
  tenant_id uuid NOT NULL, object_id char(26) NOT NULL, seq bigint NOT NULL, transition text NOT NULL,
  from_state text NOT NULL, to_state text NOT NULL, actor text NOT NULL, reason text, evidence_ref text,
  at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, object_id, seq)
);

-- ucos:tenant-rls ucos_cob.commercial_objects ucos_cob.contextual_values ucos_cob.external_references ucos_cob.lifecycle_history
-- ucos:standard-tables ucos_cob ucos_commerce_app ucos_commerce_relay
GRANT SELECT, INSERT, UPDATE ON ucos_cob.commercial_objects, ucos_cob.lifecycle_history TO ucos_commerce_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_cob.contextual_values, ucos_cob.external_references TO ucos_commerce_app;
