---
id: CIC-024-001
title: Deployment Constitution — Pipeline, Release Gates, Progressive Delivery
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-024
dependencies: [CIC-000-004, CIC-001-001, CIC-014-001, CIC-021-001, CIC-022-001, CIC-023-001]
traces: [PRIN-012, PRIN-015, PRIN-010]
certification: [CR-024-001-01, CR-024-001-02, CR-024-001-03, CR-024-001-04, CR-024-001-05]
validation: [VR-024-001-01, VR-024-001-02]
---

# CIC-024-001 — Deployment Constitution

## 1. Deployable units

| Unit | Artifact | Deployed by |
|------|----------|-------------|
| Service module | OCI image + Helm chart + `ucos-module.yaml` | GitOps (Argo CD ApplicationSet per cell) |
| Schema migration | Versioned SQL bundle inside the image, run as pre-sync Job | GitOps hook |
| Metadata (packs, policies, models) | Signed pack bundle | Governance apply (CIC-015-001 §6), not the code pipeline |
| Plugin | OCI artifact + manifest | Plugin activation (CORPUS-028) |
| Infrastructure | IaC modules | Infra pipeline with plan review |

## 2. Pipeline stages

```
commit → build (reproducible, SBOM, provenance) → unit/property/component/contract/SAST
       → image sign → deploy ephemeral env → scenario smoke → merge to main
main   → int (full scenario + conformance) → staging (perf L2 profile, DAST, chaos smoke, migration rehearsal on prod-sized snapshot of synthetic data)
       → certification record issued (L1/L2) → prod wave 0 (canary cell) → wave 1 (10 % cells) → wave 2 (50 %) → wave 3 (100 %)
```

Release gates (all automated, CR-000-004-01): valid CertificationRecord for the module digest, no
open Sev-1/Sev-2 for the context, error budget not exhausted (CIC-022-001 §4), change freeze not
active (`governance.freeze-windows`), migration compatibility check passed (§4).

## 3. Progressive delivery

- Within a cell: canary via service mesh traffic split 1 % → 10 % → 50 % → 100 % with automated
  analysis (Argo Rollouts/Flagger) on SLIs (error rate, p99 latency, business KPIs like order rejection
  rate); each step ≥ 10 min; automatic rollback on breach.
- Across cells: waves as above; wave 0 = canary cell hosting internal and opted-in tenants; ≥ 24 h bake between wave 0 and wave 1 for MAJOR or high-risk changes.
- Event consumers: canary consumers run in a shadow consumer group writing to a shadow projection; promotion compares outputs before switching.

## 4. Compatibility rules for zero-downtime

1. N and N−1 versions of a service must run concurrently: API and event changes are additive within a MAJOR; consumers tolerate unknown fields.
2. Database migrations follow expand → migrate → contract across ≥ 2 releases (CIC-003-001 §10); the pipeline rejects a release whose migration drops/renames a column still read by N−1 (static check against N−1 queries catalog).
3. Event MAJOR changes dual-publish for the deprecation window (RUL-EVT-1).
4. Feature flags gate incomplete features; flags default off in production.

## 5. Rollback

- Code: redeploy previous image digest (GitOps revert); allowed while migrations are in expand phase.
- Data: never roll back schema contract steps; use forward fixes. Point-in-time restore only via DR runbook with governance approval.
- Metadata: deprecate the new version and reactivate the previous (governance rollback plan).

## 6. Certification Rules

- **CR-024-001-01** Pipeline refuses to promote any image without signature, SBOM, provenance, and matching CertificationRecord (negative test each release).
- **CR-024-001-02** N/N−1 compatibility test: mixed-version deployment passes scenario smoke suite.
- **CR-024-001-03** Automated canary analysis rolls back an injected regression (error rate +2 %) within 15 minutes.
- **CR-024-001-04** Migration static check rejects contract-phase changes conflicting with N−1 queries.
- **CR-024-001-05** Deployment frequency and change failure rate reported per context (DORA metrics) each release.

## 7. Validation Rules

- **VR-024-001-01** Every deployable module has a Helm chart with readiness/liveness probes, PodDisruptionBudget, and resource requests.
- **VR-024-001-02** Every production wave definition includes the canary cell as wave 0.
