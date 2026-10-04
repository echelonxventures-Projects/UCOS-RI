---
id: CIC-023-001
title: Testing Constitution
version: 1.0.1
status: normative
authority: Chief Systems Engineer
corpus: CORPUS-023
dependencies: [CIC-000-004, CIC-001-001, CIC-005-001, CIC-006-001]
traces: [PRIN-012, PRIN-009, PRIN-008]
certification: [CR-023-001-01, CR-023-001-02, CR-023-001-03, CR-023-001-04, CR-023-001-05]
validation: [VR-023-001-01, VR-023-001-02]
---

# CIC-023-001 — Testing Constitution

## 1. Test taxonomy

Tooling is illustrative; any language-equivalent tool run in a container satisfies the level (CIC-001-001 §1.1).

| Level | Scope | Tooling (examples) | Gate |
|-------|-------|---------------------|------|
| Unit | Domain model, pure functions | JUnit 5 / Kotest, Vitest | PR |
| Property | Resolution algorithms, invariants, money arithmetic | jqwik / Kotest property, fast-check | PR |
| Mutation | `-domain` modules | PIT, Stryker | Nightly; release gate ≥ 80 % |
| Component | One service with real DB/broker (Testcontainers) | Testcontainers | PR |
| Contract | API (provider + consumer), events (AsyncAPI) | Schemathesis, Pact, AsyncAPI validators | PR |
| Conformance | Corpus CR rules (algorithms, ports, adapters) | Black-box `conformance/` suites + golden vectors (CIC-030-001 §5.1) | Release |
| Scenario (E2E) | Business journeys across contexts | Gherkin features over SDK | Nightly + release |
| Performance | SLO verification | k6 / Gatling with production-like data | Release (L2) |
| Resilience | Chaos, failure injection, DR | Chaos Mesh / Litmus, Toxiproxy | Weekly + release |
| Security | SAST, DAST, dependency, IaC | Semgrep, ZAP, Trivy, Checkov | PR + release |
| Concurrency | Linearizability of critical aggregates | Jepsen-style harness, Porcupine checker | Release |

## 2. Traceability to certification

Every test that verifies a CR rule is annotated (`@Verifies("CR-PRC-01")`). The certification pipeline
collects results per rule (CIC-000-004). A CR rule with no verifying test fails certification.

## 3. Test data

- Synthetic data generators per TypeDefinition (ontology-driven: valid instances generated from EffectiveSchema constraints) — no production personal data in any non-production environment.
- Golden files for algorithms (pricing, proration, resolution) are versioned and reviewed like code; changes require ChangeSet-equivalent PR approval by the domain owner.
- Reference tenant fixtures: `retail-b2c`, `b2b-distribution`, `telco-subscriptions`, `insurance-policies`, `saas-usage`, `marketplace`, `public-sector-benefits` — exercising the same kernel with different packs (proves PRIN-019).

## 4. Scenario specification format

```gherkin
Feature: Subscription upgrade mid-cycle (traces: DOM-ORD, DOM-BIL, DOM-ENT; CR-BIL-04)
  Background: tenant "telco-subscriptions" at 2026-03-15T10:00Z in context {market: DE, channel: web, currency: EUR}
  Scenario: Upgrade prorates daily-exact
    Given party "P1" has active subscription "Basic" billed monthly on the 1st
    When "P1" orders action "modify" to offer "Plus" effective immediately
    Then an order is accepted with price lock
    And entitlement "data-volume" allowance becomes 50 GB for the current period
    And billing creates a credit charge of 17/31 × 10.00 EUR and a charge of 17/31 × 20.00 EUR
```

## 5. Flakiness policy

Tests failing nondeterministically are quarantined automatically after 2 flaky failures in 7 days,
with a ticket to the owner; quarantine > 14 days blocks the owning module's release.

## 6. Certification Rules

- **CR-023-001-01** Every CR rule in the corpus has ≥ 1 verifying test in the release's results.
- **CR-023-001-02** Reference tenant fixtures pass all scenario suites on the same kernel build without tenant-specific code.
- **CR-023-001-03** Contract tests cover 100 % of operations and event types per context.
- **CR-023-001-04** No production personal data in non-production (DLP scan of non-prod stores).
- **CR-023-001-05** Quarantined tests older than 14 days: zero for released modules.

## 7. Validation Rules

- **VR-023-001-01** Every scenario feature declares `traces` resolving to corpus IDs.
- **VR-023-001-02** Every golden file directory has an owner in CODEOWNERS.
