---
id: CIC-014-001
title: Security Constitution
version: 1.0.0
status: normative
authority: Chief Security Architect
corpus: CORPUS-014
dependencies: [CIC-009-001, CIC-003-001, CIC-005-001, CIC-006-001, CIC-001-001]
traces: [PRIN-010, PRIN-015, PRIN-022, DOM-SEC, DOM-PRI, DOM-IDN]
certification: [CR-014-001-01, CR-014-001-02, CR-014-001-03, CR-014-001-04, CR-014-001-05, CR-014-001-06, CR-014-001-07]
validation: [VR-014-001-01, VR-014-001-02]
---

# CIC-014-001 — Security Constitution

## 1. Security model

Zero trust: no network location confers trust. Every call — user, partner, agent, or service — is
authenticated (DOM-IDN), authorized by the PDP (CIC-009-001), encrypted in transit, and audited.
Baseline assurance target: OWASP ASVS 4.0 Level 3 for kernel, identity, policy, billing, settlement;
Level 2 elsewhere. Control mapping maintained for ISO/IEC 27001:2022 Annex A, SOC 2 TSC, PCI DSS 4.0
(settlement cell only), and NIST SP 800-53 moderate.

## 2. Trust zones

| Zone | Contents | Ingress | Egress |
|------|----------|---------|--------|
| Z0 Edge | CDN, WAF, API gateway | Internet | Z1 only |
| Z1 Service mesh | Bounded-context services | Z0, Z1 (mTLS, SPIFFE) | Z2, Z1, egress proxy |
| Z2 Data | Databases, brokers, caches, search | Z1 by service identity | None (backups via Z4) |
| Z3 Cardholder/regulated cell | PSP adapters, vault, tokenization | Z1 settlement only | PSP endpoints via egress proxy |
| Z4 Operations | CI/CD, backup, break-glass | SSO + device posture + JIT | All zones (audited) |

Inter-zone traffic only on explicitly declared flows (Kubernetes NetworkPolicy / service-mesh
AuthorizationPolicy generated from `ucos-module.yaml` ports declarations). Default deny.

## 3. Authorization layering

1. **Gateway**: token validation (signature, expiry, sender constraint, revocation cache), coarse scope check against `x-ucos-permission`.
2. **Service PEP**: PDP `Decide(<context>.<operation>)` with principal, resource attributes, context (CIC-009-001 §5).
3. **Data layer**: PostgreSQL RLS by tenant (CIC-003-001 §5); service DB roles with least privilege (no DDL at runtime, no cross-schema grants).
4. **Field level**: PDP obligations `redact` applied in response serializers; personal fields excluded from events.

Authorization model: ABAC over RBAC — roles (DOM-AUTH) are attributes; policies decide. Relationship-based
checks (ReBAC: "principal is account-manager of the party that owns this contract") are expressed as
policy functions over DOM-REL edges with a bounded depth of 3 and cached edge sets.

## 4. Cryptography

| Use | Standard |
|-----|----------|
| Transit (external) | TLS 1.3 only; HSTS; certificate transparency monitoring |
| Transit (internal) | mTLS with SPIFFE SVIDs, 24 h rotation |
| At rest | AES-256-GCM storage encryption + envelope encryption for confidential+ fields |
| Field encryption | Per-tenant KEK in KMS/HSM, per-subject DEK for personal data (crypto-shred, CIC-003-001 §9) |
| Signing | Ed25519 / ECDSA P-256 (JWS, Sigstore); HSM-backed for tokens, bundles, evidence checkpoints |
| Hashing | SHA-256 (integrity), Argon2id (secret verifiers), HMAC-SHA-256 keyed hashes for searchable personal fields |
| Crypto agility | Algorithms referenced by policy `security.crypto-suite`; PQC hybrid (X25519+ML-KEM-768) supported in TLS where the platform supports it |

Keys: rotation ≤ 90 days for DEK-wrapping KEKs (re-wrap, not re-encrypt), ≤ 30 days for token
signing keys; no key material in code, config files, or environment variables — only KMS references.

## 5. Secrets

Secrets live only in the secrets manager (`SecretsPort`; Vault/cloud KMS adapters). Workloads fetch
via workload identity at start and on rotation events. CI secret scanning (gitleaks ruleset +
UCOS patterns) blocks merges. Secret TTL ≤ 90 days; database credentials dynamic (≤ 24 h).

## 6. Supply chain

SLSA Level 3 builds, signed images (cosign), admission control verifying signature + provenance +
SBOM presence (Kyverno/Gatekeeper policy), vulnerability gates: no Critical; High only with waiver
≤ 30 days (CIC-000-004 waiver process). Base images: distroless or minimal, rebuilt weekly.

## 7. Application security requirements (excerpt, all MUST)

1. Input validation against contract schemas at gateway and service (double validation).
2. Output encoding by renderers; UI uses strict CSP (`default-src 'self'`; no inline script; Trusted Types).
3. CEL/Rego sandboxing with cost limits (CIC-008-001 §4); no user-supplied regular expressions except RE2.
4. SSRF controls: all outbound HTTP through egress proxy with allow-lists per context (webhooks, IdP metadata, plugin endpoints).
5. Deserialization: JSON only across trust boundaries; no polymorphic type deserialization.
6. Rate limiting and abuse detection per tenant, client, route class (CIC-005-001 §9); credential-stuffing defences at IdP federation edge.
7. Mass assignment prevented: commands are explicit DTOs; PATCH allow-lists derived from ontology `editable` and lifecycle `editable` state.
8. Multi-tenant isolation tests in every service test suite (CR-014-001-02).

## 8. Privacy by design (with DOM-PRI)

- Purpose registry: every personal-data read declares `UCOS-Purpose`; PDP enforces purpose binding.
- Data minimization: events, logs, traces, analytics contain no personal data in clear (DLP-enforced).
- Data subject rights: access/export (machine-readable JSON-LD), rectification, erasure (crypto-shred), restriction (processing flag honored by PDP), objection (consent withdrawal) — SLA 30 days, automated workflow.
- Residency: personal data stored only in regions allowed by `privacy.residency` for the subject's jurisdiction; cross-region event replication strips personal fields.

## 9. Security monitoring and response

Security events (authN failures, PDP denies spikes, privilege changes, break-glass, key operations,
evidence verification failures) are forwarded to SIEM via OTLP logs with `security=true` attribute.
Detection rules versioned in repo; Sev-1 security incidents follow CORPUS-025 incident runbook with
regulator notification timers driven by policy `security.breach-notification` per jurisdiction.

## 10. Break-glass

Emergency access via Z4 with: two-person approval, max 4 h, session recording, automatic Evidence
capture, post-incident review within 5 business days. Break-glass cannot bypass crypto-shred or legal holds.

## 11. Certification Rules

- **CR-014-001-01** Every route of every service has an authorization test with a deny-all bundle returning 403 (extends CR-009-001-02).
- **CR-014-001-02** Cross-tenant isolation suite (API, events, search, cache, graph, exports) finds zero leaks.
- **CR-014-001-03** DAST (OWASP ZAP full scan + UCOS auth scripts) and SAST (Semgrep UCOS ruleset) report zero High/Critical unwaived findings.
- **CR-014-001-04** Network policy test: every undeclared flow between zones is blocked (synthetic probes in each environment).
- **CR-014-001-05** Container admission rejects unsigned images or images lacking SBOM/provenance (negative test per release).
- **CR-014-001-06** DLP scan of logs, traces, events, and analytics sinks over 24 h of L2 load finds zero personal values in clear.
- **CR-014-001-07** Annual external penetration test with no open Critical findings; Highs remediated within 30 days.

## 12. Validation Rules

- **VR-014-001-01** Every DOM-*.yaml declares `security.permissions` and `security.dataClassification`.
- **VR-014-001-02** Every flow implied by `boundaries.upstream` of a domain is declared as a port in the owning module manifest.
