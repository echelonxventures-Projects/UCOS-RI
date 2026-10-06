-- DOM-REL (S3b): relationships and closure tables for hierarchical relationship types (DOM-HIER).
-- Edges are never physically deleted: ending sets valid_to (INV-REL-4).
CREATE SCHEMA ucos_graph AUTHORIZATION ucos_owner;

CREATE TABLE ucos_graph.relationships (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, urn text NOT NULL, rel_type text NOT NULL, rel_type_urn text NOT NULL,
  source text NOT NULL, target text NOT NULL, scope jsonb NOT NULL, valid_from timestamptz NOT NULL, valid_to timestamptz,
  ended_at timestamptz, ordinal text, attributes jsonb NOT NULL, revision bigint NOT NULL, created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  CHECK (valid_to IS NULL OR valid_to >= valid_from)
);
CREATE INDEX ON ucos_graph.relationships (tenant_id, source, rel_type) INCLUDE (target, valid_from, valid_to);
CREATE INDEX ON ucos_graph.relationships (tenant_id, target, rel_type) INCLUDE (source, valid_from, valid_to);

CREATE TABLE ucos_graph.closure (
  tenant_id uuid NOT NULL, rel_type text NOT NULL, ancestor text NOT NULL, descendant text NOT NULL, depth int NOT NULL,
  valid_from timestamptz NOT NULL, valid_to timestamptz,
  PRIMARY KEY (tenant_id, rel_type, ancestor, descendant, valid_from)
);
CREATE INDEX ON ucos_graph.closure (tenant_id, rel_type, descendant);
-- ucos:tenant-rls ucos_graph.relationships ucos_graph.closure
-- ucos:standard-tables ucos_graph ucos_commerce_app ucos_commerce_relay
GRANT SELECT, INSERT, UPDATE ON ucos_graph.relationships TO ucos_commerce_app;
GRANT SELECT, INSERT, DELETE ON ucos_graph.closure TO ucos_commerce_app;
