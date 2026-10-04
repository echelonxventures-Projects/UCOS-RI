---
id: CIC-021-001
title: Infrastructure Constitution
version: 1.0.0
status: normative
authority: Chief Systems Engineer
corpus: CORPUS-021
dependencies: [CIC-001-001, CIC-014-001, CIC-020-001]
traces: [PRIN-022, PRIN-015, PRIN-010]
certification: [CR-021-001-01, CR-021-001-02, CR-021-001-03, CR-021-001-04]
validation: [VR-021-001-01, VR-021-001-02]
---

# CIC-021-001 — Infrastructure Constitution

## 1. Portability contract (PRIN-022)

UCOS runs on any infrastructure that provides the **Infrastructure Capability Set (ICS)** below. Each
capability is consumed only through a port with ≥ 2 certified adapters.

| Capability | Port | Certified adapters (reference) |
|------------|------|-------------------------------|
| Container orchestration | Kubernetes API ≥ 1.30 | Any CNCF-conformant distribution |
| Relational DB | `SqlStorePort` (PostgreSQL 16 wire + features) | Self-managed PostgreSQL (CloudNativePG), managed PostgreSQL services |
| Event log | `EventBusPort` (Kafka protocol) | Apache Kafka (Strimzi), Redpanda, managed Kafka |
| Cache | `CachePort` (RESP3) | Redis OSS / Valkey, managed equivalents |
| Search | `SearchIndexPort` | OpenSearch, Elasticsearch-compatible |
| Graph | `GraphStorePort` (openCypher/GQL) | Neo4j, Apache AGE, Memgraph |
| Object storage | `ObjectStorePort` (S3 API incl. object lock) | MinIO, cloud object storage |
| KMS / HSM | `KeyManagementPort` (PKCS#11 / KMIP / cloud KMS) | HashiCorp Vault Transit, cloud KMS, HSM |
| Secrets | `SecretsPort` | Vault, cloud secret managers (via External Secrets Operator) |
| Identity federation | OIDC | Keycloak, cloud IdPs |
| Telemetry | OTLP | OpenTelemetry Collector → any backend |
| Service mesh | SPIFFE/SPIRE + Envoy-compatible | Istio, Linkerd (mTLS) |

## 2. Infrastructure as Code

- All infrastructure declared in code: OpenTofu/Terraform modules for cloud primitives, Crossplane or
  Helm for in-cluster resources, GitOps reconciliation (Argo CD / Flux) — no manual changes in
  production (drift detection alerts within 15 min; auto-revert for non-emergency drift).
- Module layout: `deploy/infra/modules/<capability>/<adapter>`, environment overlays
  `deploy/infra/envs/<env>/<region>/<cell>`.
- Policy as code on IaC: Checkov/OPA rules (encryption on, public access off, object lock on evidence
  buckets, deletion protection on databases, backups enabled).

## 3. Cell blueprint (per cell, minimum production)

| Component | Spec |
|-----------|------|
| Kubernetes | 3 AZs; node pools: `system`, `services` (general), `compute` (pricing/rules, CPU-optimized), `jobs` (spot/preemptible allowed), `data-adjacent` |
| PostgreSQL | One cluster per bounded-context group (kernel, commerce, finance, supply, platform); 1 primary + 2 sync/async replicas across AZs; PITR 35 days; PgBouncer transaction pooling |
| Kafka | 3+ brokers across AZs, RF=3, min.insync.replicas=2, rack awareness |
| Cache | 3-shard cluster with replicas; no persistence requirement (rebuildable) |
| Search | 3 master + ≥ 3 data nodes; index per tenant-group with aliasing |
| Object storage | Buckets: evidence (object lock compliance), archive (lifecycle → cold), documents, backups (separate account/project) |

## 4. Capacity and autoscaling

- Horizontal Pod Autoscaling on custom metrics (request concurrency, consumer lag) not CPU alone.
- Each service declares `resources.requests` = p50 usage, `limits` memory only (no CPU limits for latency-critical services).
- Capacity model per cell maintained as code (CORPUS-025), target utilization ≤ 60 % at forecast peak.
- Database scaling: vertical first, then read replicas for query paths, then tenant re-placement to new cells.

## 5. Backup and restore

- Databases: continuous WAL archiving + daily base backups, encrypted, copied to a separate backup account; restore test weekly (automated) per cluster.
- Event log: mirrored to the archive (Parquet) — the archive plus database backups must be able to rebuild every projection.
- Restores are verified with row counts, checksums, and application smoke tests; evidence captured.

## 6. Environments

`dev` (ephemeral per PR, synthetic data) → `int` → `staging` (production-like, masked/synthetic data only)
→ `prod` (per region/cell). Production personal data never leaves production (CR-014-001-06 extends to non-prod).

## 7. Certification Rules

- **CR-021-001-01** Every adapter listed passes its port conformance suite; each port has ≥ 2 passing adapters per release.
- **CR-021-001-02** IaC policy scan reports zero violations on production environments.
- **CR-021-001-03** Weekly automated restore test succeeds for every production database cluster (evidence linked).
- **CR-021-001-04** Drift detection: injected manual change is detected within 15 minutes.

## 8. Validation Rules

- **VR-021-001-01** Every port named in a `ucos-module.yaml` exists in §1.
- **VR-021-001-02** Every production environment overlay sets backup, encryption, and deletion-protection flags.
