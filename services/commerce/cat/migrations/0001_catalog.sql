-- DOM-CAT (S3d): catalogs, navigation, materialized membership with generations (CIC-011-005 §3).
-- Catalogs store no prices, stock or product data. Membership references objects by id only.
CREATE SCHEMA ucos_catalog AUTHORIZATION ucos_owner;

-- body: the working definition; serving: the frozen published version incl. navigation (INV-CAT-3);
-- pending: the version being materialized.
CREATE TABLE ucos_catalog.catalogs (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, urn text NOT NULL, code text NOT NULL,
  body jsonb NOT NULL, serving jsonb, pending jsonb, scope jsonb NOT NULL,
  state text NOT NULL, version int NOT NULL, generation bigint NOT NULL,
  author text NOT NULL, submitted_by text, approvals jsonb NOT NULL, approval_ref text,
  revision bigint NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, code)
);
CREATE INDEX ON ucos_catalog.catalogs (tenant_id, state);

CREATE TABLE ucos_catalog.navigation_nodes (
  tenant_id uuid NOT NULL, catalog_id char(26) NOT NULL, node_id text NOT NULL, parent_node_id text, ordinal text NOT NULL,
  body jsonb NOT NULL,
  PRIMARY KEY (tenant_id, catalog_id, node_id)
);

CREATE TABLE ucos_catalog.catalog_membership (
  tenant_id uuid NOT NULL, catalog_id char(26) NOT NULL, generation bigint NOT NULL, object_id char(26) NOT NULL,
  valid_from timestamptz NOT NULL, valid_to timestamptz, source text NOT NULL,
  PRIMARY KEY (tenant_id, catalog_id, generation, object_id)
);
CREATE INDEX ON ucos_catalog.catalog_membership (tenant_id, object_id, catalog_id);

-- Swapped generations; a superseded generation stays readable for in-flight cursors for 24 h (CR-CAT-02).
CREATE TABLE ucos_catalog.generations (
  tenant_id uuid NOT NULL, catalog_id char(26) NOT NULL, generation bigint NOT NULL, swapped_at timestamptz NOT NULL,
  superseded_at timestamptz, size int NOT NULL,
  PRIMARY KEY (tenant_id, catalog_id, generation)
);

CREATE TABLE ucos_catalog.selector_dependencies (
  tenant_id uuid NOT NULL, dependency_kind text NOT NULL, dependency_ref text NOT NULL, catalog_id char(26) NOT NULL,
  PRIMARY KEY (tenant_id, dependency_kind, dependency_ref, catalog_id)
);

-- ucos:tenant-rls ucos_catalog.catalogs ucos_catalog.navigation_nodes ucos_catalog.catalog_membership ucos_catalog.generations ucos_catalog.selector_dependencies
-- ucos:standard-tables ucos_catalog ucos_commerce_app ucos_commerce_relay
GRANT SELECT, INSERT, UPDATE ON ucos_catalog.catalogs TO ucos_commerce_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ucos_catalog.navigation_nodes, ucos_catalog.catalog_membership, ucos_catalog.generations,
  ucos_catalog.selector_dependencies TO ucos_commerce_app;
