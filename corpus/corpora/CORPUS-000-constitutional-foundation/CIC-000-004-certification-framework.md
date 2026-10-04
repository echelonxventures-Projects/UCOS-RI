---
id: CIC-000-004
title: Certification Framework
version: 1.0.1
status: normative
authority: UCOS Constitutional Authority
corpus: CORPUS-000
dependencies: [CIC-000-001, CIC-000-003]
traces: [PRIN-012, PRIN-011]
certification: [CR-000-004-01, CR-000-004-02, CR-000-004-03]
validation: [VR-000-004-01]
---

# CIC-000-004 — Certification Framework

## 1. Certifiable subjects

| Subject | Example | Certified against |
|---------|---------|-------------------|
| Corpus revision | git tag `cic-1.4.0` | CIC-000-003 validation rules |
| Service module | `ucos-pricing-service:3.2.1` | CR rules traced from its `ucos.traces` |
| Metadata package | Type Pack `com.acme.telco@1.2.0` | CIC-029 pack rules + type well-formedness |
| Plugin | `com.vendor.tax-avalara@2.0.0` | CIC-028 plugin rules |
| Deployment | `prod-eu-west/2026-10-04T10:00Z` | CIC-024 release gates |

## 2. Certification levels

| Level | Meaning | Required evidence |
|-------|---------|-------------------|
| L0 Registered | Subject known, metadata valid | VR rules pass |
| L1 Conformant | All MUST-level CR rules pass | Test reports linked per CR |
| L2 Verified | L1 + performance/SLO and security rules pass in a production-like environment | Load test, DAST, SBOM scan |
| L3 Assured | L2 + independent review and 30-day production observation without Sev-1 attributable to subject | Review record, SLO report |

Activation in production requires ≥ L1 (metadata, plugins) or ≥ L2 (services).

## 3. CertificationRecord (aggregate, owned by DOM-CRT)

```yaml
CertificationRecord:
  id: urn:ucos:<tenant>:cert:<ulid>
  subject: {kind: module|pack|plugin|corpus|deployment, ref: <URN or coordinates>, digest: sha256:<hex>}
  level: L0|L1|L2|L3
  ruleResults: [{ruleId: CR-…, outcome: pass|fail|waived, evidenceRefs: [urn:ucos:…:evidence:…], waiverRef?: urn}]
  issuedBy: urn:ucos:…:party:…
  issuedAt: RFC3339
  expiresAt: RFC3339           # default issuedAt + 365d; L3 + 180d
  state: issued|suspended|revoked|expired
```

Waivers: a failed CR MAY be waived only by a Governance ChangeSet with expiry ≤ 90 days; waived rules
cap the level at L1.

## 4. Certification Rules

- **CR-000-004-01** The release pipeline blocks promotion of any subject lacking a non-expired CertificationRecord at the required level, matching the subject digest.
- **CR-000-004-02** Every CertificationRecord rule result of `pass` references ≥ 1 Evidence whose digest verifies.
- **CR-000-004-03** Revocation of a record emits `ucos.governance.certification-record.revoked.v1` (declared by DOM-CRT) and the runtime deactivates the subject within 5 minutes (plugins/packs) or blocks next deploy (services).

## 5. Validation Rules

- **VR-000-004-01** Every CR rule in the corpus is mapped to ≥ 1 certification level in its defining artifact or defaults to L1.
