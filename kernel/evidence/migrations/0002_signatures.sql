-- S2c (ADR 0009): CaptureEvidence with signatures. Each signature is a compact ES256 JWS whose payload is the evidence
-- content, signed by the capturing principal's DPoP key (DOM-EVD Evidence.signatures). Expand-only.
ALTER TABLE ucos_evidence.evidence ADD COLUMN signatures jsonb NOT NULL DEFAULT '[]';
