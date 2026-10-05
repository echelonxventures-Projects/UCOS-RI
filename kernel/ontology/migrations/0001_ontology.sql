-- ucos_ontology: DOM-ONT definitions + compiled schemas; DOM-META registry entries, packs, installations.
CREATE SCHEMA ucos_ontology AUTHORIZATION ucos_owner;
CREATE TABLE ucos_ontology.definitions (
  tenant_id uuid NOT NULL, urn text NOT NULL, kind text NOT NULL, namespace text NOT NULL, name text NOT NULL,
  version text NOT NULL, state text NOT NULL CHECK (state IN ('draft','in-review','published','deprecated','retired')),
  body jsonb NOT NULL, digest text NOT NULL, change_set_ref text, revision bigint NOT NULL,
  created_at timestamptz NOT NULL, published_at timestamptz,
  PRIMARY KEY (tenant_id, urn)
);
CREATE INDEX ON ucos_ontology.definitions (tenant_id, kind, state);
CREATE TABLE ucos_ontology.compiled_schemas (
  tenant_id uuid NOT NULL, type_urn text NOT NULL, schema jsonb NOT NULL, digest text NOT NULL, compiled_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, type_urn)
);
-- Platform-wide pack store (DOM-META): published bundles are not tenant data.
CREATE TABLE ucos_ontology.packs (
  id text NOT NULL, version text NOT NULL, digest text NOT NULL, bundle jsonb NOT NULL, published_by text NOT NULL,
  published_at timestamptz NOT NULL, PRIMARY KEY (id, version)
);
CREATE TABLE ucos_ontology.pack_installations (
  tenant_id uuid NOT NULL, pack_id text NOT NULL, version text NOT NULL, state text NOT NULL,
  change_set_ref text NOT NULL, items jsonb NOT NULL, updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, pack_id)
);
-- ucos:tenant-rls ucos_ontology.definitions ucos_ontology.compiled_schemas ucos_ontology.pack_installations
-- ucos:standard-tables ucos_ontology ucos_kernel_app ucos_kernel_relay
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_ontology.definitions, ucos_ontology.compiled_schemas, ucos_ontology.pack_installations TO ucos_kernel_app;
GRANT SELECT, INSERT ON ucos_ontology.packs TO ucos_kernel_app;
