---
id: CIC-030-001
title: Reference Implementation Constitution — Scope, Build Order, Definition of Done
version: 1.1.0
status: normative
authority: Chief Architect
corpus: CORPUS-030
dependencies: [CIC-001-001, CIC-002-001, CIC-020-001, CIC-023-001, CIC-024-001, CIC-029-001]
traces: [PRIN-012, PRIN-009, PRIN-019, PRIN-022]
certification: [CR-030-001-01, CR-030-001-02, CR-030-001-03, CR-030-001-04, CR-030-001-05]
validation: [VR-030-001-01, VR-030-001-02]
---

# CIC-030-001 — Reference Implementation Constitution

## 1. Purpose

The Reference Implementation (RI) is the executable proof that the corpus is implementable and
consistent. Its language-neutral parts — contracts and conformance suites with golden vectors — are the oracle for
conformance tests and the basis for SDK generation; its implementations are the starting codebase for
adopters. The RI is contract-first and polyglot (CIC-001-001 §1.1): no language is privileged, and
every implementation (including the RI's own) is judged only by the conformance suites.
Where the RI and the corpus disagree, the corpus wins and the RI has a defect.

## 2. Profiles

| Profile | Composition | Use |
|---------|-------------|-----|
| `ucos-lite` | All kernel + core contexts in one Compose project on one host, one PostgreSQL instance with a schema per context, lightweight `EventBusPort` adapter (CloudEvents HTTP push) with outbox semantics preserved, no cells | Local development, pack authoring, CI scenario tests |
| `ucos-cell` | One deployment per bounded context, full ports per CIC-021-001 §3 | Staging and production |

Both profiles are built from the same module images; the difference is only the composition
(`apps/lite/compose.yaml`, `apps/<context>-service`) and the bound adapters. Module boundaries and contracts are identical, so moving from
lite to cell requires no code change (CR-030-001-02).

## 3. Build order (vertical slices)

Each slice is complete only when its Definition of Done (§4) holds.

| Slice | Contents | Exit demonstration |
|-------|----------|--------------------|
| S0 Platform | Contract toolchain (generator + linters), conformance harness, `ucos-kernel-api` contracts, eventing (outbox/relay/consumer), persistence (migrations, RLS), security filter, observability, validator in CI — all container-only | Echo context with event round-trip, RLS isolation test green |
| S1 Metadata kernel | ONT, CTX, POL (PDP embedded), LFC, EVT registry, EVD (ledger), GOV ChangeSets (minimal) | `ucos.std` pack installs via ChangeSet; context resolution conformance suite green |
| S2 Identity & party | IDN (OIDC federation, token service), PTY, AUTH (roles/delegation basics) | Login, party creation, PDP-guarded API, agent token with act chain |
| S3 Commercial core | COB, REL, CAT, PRC, OFR | Create Product/Subscription from pack types; resolve catalog with prices in 3 markets/2 channels without code changes |
| S4 Transaction | QTE, ORD, AVL, INV, PAY (simulated provider) | B2C checkout and B2B quote-to-order journeys; oversell test green |
| S5 Post-sale | ENT, CTR, BIL, (TAX simulated engine), REV skeleton events | Subscription lifecycle with mid-cycle upgrade, proration, invoice issuance, payment application |
| S6 Hardening | DR, chaos, performance to L2 SLOs, security tests, ops runbooks | L2 certification of all S1–S5 modules |
| S7 Breadth | Remaining core and extension contexts per registry tier priority | Reference tenant fixtures (CIC-023-001 §3) all green on one build |

## 4. Definition of Done (per module)

1. Contracts (OpenAPI/proto/AsyncAPI) published and linted; SDK regenerated.
2. All commands, queries, events, state machines, rules, and invariants of the DOM spec implemented; deviations recorded as corpus amendment requests, not silent changes.
3. All CR rules traced from the module (`ucos-module.yaml.traces`) have passing verifying tests; mutation score ≥ 80 % on domain.
4. SLOs codified (OpenSLO), dashboards/alerts generated, runbooks written for every alert.
5. Security: PEP on every operation, RLS, DLP-clean telemetry, SAST/DAST clean.
6. Migration scripts follow expand/contract; N/N−1 compatibility test passes.
7. Documentation: module README, ADRs for decisions not dictated by the corpus.
8. CertificationRecord issued at the level required for promotion.

## 5. Repository bootstrap

The monorepo layout is CIC-001-001 §2; the repository is named `UCOS-RI`. The corpus repository
(this one) is vendored into `corpus/` at a pinned tag recorded in `corpus.lock` (tag, commit, content
hash); CI fails if the vendored corpus does not validate, if its content hash differs from the lock, or
if any `ucos-module.yaml` traces an ID absent from it.

### 5.1 Contract-first delivery

1. Per-domain OpenAPI 3.1 and AsyncAPI 3.0 contracts are **generated** from the DOM specs
   (`apis`, `events`, `commands`, `queries`) by a containerized generator; generated files carry the
   source DOM id and version and are never hand-edited. Hand-authored refinements (schemas) live
   beside them and are linted against the generated skeleton.
2. Conformance suites are black-box: they reach an implementation only through `UCOS_BASE_URL`
   (HTTP), a CloudEvents sink, and `UCOS_DB_URL` (for persistence-level rules such as RLS). They run in
   containers and never import implementation code.
3. A module is implemented only after its contracts and conformance suite exist (tests first).

## 6. Certification Rules

- **CR-030-001-01** The RI passes every L1 conformance suite defined in the corpus for implemented domains (report lists any domain not yet implemented as `not-claimed`, never as passed).
- **CR-030-001-02** The same scenario suite passes on `ucos-lite` and `ucos-cell` profiles with identical results.
- **CR-030-001-03** Reference tenant fixtures for at least four industries pass on one build with zero tenant- or industry-specific code (UCOS-L001 clean).
- **CR-030-001-04** Every module meets §4 Definition of Done before its slice is declared complete (evidence: CertificationRecord + checklist Evidence).
- **CR-030-001-05** Replaceability: for at least one S1 module, a second implementation in a different language passes the identical conformance and scenario suites and is swapped into `ucos-lite` with no change to any other module.

## 7. Validation Rules

- **VR-030-001-01** Every domain with tier kernel or core is assigned to exactly one slice S1–S7.
- **VR-030-001-02** The vendored corpus tag in the RI matches a validated corpus release.
