-- DOM-OFR (S3d): offer versions (INV-OFR-3: published versions immutable; quotes and orders reference (id, version)),
-- the object index used by FindOffers, and offer transition matrices.
CREATE SCHEMA ucos_offer AUTHORIZATION ucos_owner;

CREATE TABLE ucos_offer.offers (
  tenant_id uuid NOT NULL, id char(26) NOT NULL, version int NOT NULL, urn text NOT NULL, code text NOT NULL,
  body jsonb NOT NULL, scope jsonb NOT NULL, valid_from timestamptz NOT NULL, valid_to timestamptz,
  state text NOT NULL, effective_at timestamptz, withdrawn_at timestamptz,
  author text NOT NULL, submitted_by text, approvals jsonb NOT NULL, plan jsonb NOT NULL, coverage jsonb,
  revision bigint NOT NULL, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id, version)
);
CREATE INDEX ON ucos_offer.offers (tenant_id, state, valid_from);
CREATE INDEX ON ucos_offer.offers USING gin (scope jsonb_path_ops);
CREATE INDEX ON ucos_offer.offers (tenant_id, code);

CREATE TABLE ucos_offer.offer_object_index (
  tenant_id uuid NOT NULL, object_ref text NOT NULL, offer_id char(26) NOT NULL, version int NOT NULL,
  PRIMARY KEY (tenant_id, object_ref, offer_id, version)
);

CREATE TABLE ucos_offer.offer_transitions (
  tenant_id uuid NOT NULL, from_offer text NOT NULL, to_offer text NOT NULL, matrix_id char(26) NOT NULL, body jsonb NOT NULL,
  PRIMARY KEY (tenant_id, from_offer, to_offer)
);

-- ucos:tenant-rls ucos_offer.offers ucos_offer.offer_object_index ucos_offer.offer_transitions
-- ucos:standard-tables ucos_offer ucos_commerce_app ucos_commerce_relay
GRANT SELECT, INSERT, UPDATE ON ucos_offer.offers, ucos_offer.offer_transitions TO ucos_commerce_app;
GRANT SELECT, INSERT, DELETE ON ucos_offer.offer_object_index TO ucos_commerce_app;
