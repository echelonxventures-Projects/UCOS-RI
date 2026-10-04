---
id: CIC-016-001
title: Risk Constitution — Fraud, Counterfeit, Financial, Cyber, Operational Risk
version: 1.0.0
status: normative
authority: Chief Governance Architect
corpus: CORPUS-016
dependencies: [CIC-009-001, CIC-010-001, CIC-014-001, CIC-015-001, CIC-022-001]
traces: [PRIN-005, PRIN-010, PRIN-011, DOM-FRD, DOM-CFT, DOM-FRK, DOM-CYR, DOM-ORK]
certification: [CR-016-001-01, CR-016-001-02, CR-016-001-03, CR-016-001-04, CR-016-001-05]
validation: [VR-016-001-01, VR-016-001-02]
---

# CIC-016-001 — Risk Constitution

## 1. Unified risk model

All risk domains share one model so that risk decisions are composable inputs to policies:

```yaml
RiskAssessment:                       # produced by a risk provider, stored as DecisionRecord (type risk-score)
  id: urn:ucos:<tenant>:decision:<ulid>
  riskType: fraud|counterfeit|credit|financial-exposure|cyber|operational|compliance
  subject: urn                          # order, party, payment intent, seller, listing, asset, process
  score: integer 0..1000                # calibrated: score/1000 ≈ probability of adverse outcome within horizon
  band: low|medium|high|critical        # from policy risk.<type>.bands
  horizon: duration
  signals: [{code, weight, valueDigest}]  # feature attributions, no raw personal data
  provider: {kind: rules|model|plugin|human, ref, version}
  recommendedAction: allow|review|step-up|hold|block
  expiresAt: Instant
```

Risk assessments never act on their own: **policies decide** (PRIN-005). E.g. `order.validation-steps`
calls `fraud-risk`; the PEP evaluates `risk.order-action` with the assessment as input and receives
`allow | review | step-up | block` plus obligations.

## 2. Risk domains

| Domain | Subjects | Key controls |
|--------|----------|--------------|
| Fraud (DOM-FRD) | Orders, payments, account creation, promotions, refunds, agents | Real-time scoring (≤ 50 ms p99), velocity rules, device/identity signals, promotion-abuse rules, manual review queue, feedback loop from chargebacks |
| Counterfeit (DOM-CFT) | Marketplace listings, sellers, serialized items | Authorized-seller registries, serial/lot provenance verification (DOM-PRV), listing similarity checks, takedown workflow with evidence |
| Financial risk (DOM-FRK) | Customer credit exposure, partner settlement exposure, FX, revenue at risk | Credit limits per party (policy), exposure aggregation over open orders + AR, settlement holds, FX exposure reports |
| Cyber risk (DOM-CYR) | Tenants, integrations, plugins, identities | Plugin risk ratings, anomalous API usage detection, credential stuffing defence, third-party risk records |
| Operational risk (DOM-ORK) | Processes, controls, incidents | Risk register (likelihood × impact), control mapping (CIC-015-001 §5), key risk indicators from metrics, loss event database |

## 3. Decision flow (real-time)

```
PEP(command) → collect features (bounded: ≤ 20 ms, cached party/device aggregates)
            → providers in parallel (rules engine CIC-008 fact kind risk-rule; model plugins I2)
            → aggregate: max-band across providers unless policy risk.aggregation says weighted
            → PDP Decide('risk.<subject>-action', {assessments, amount, context})
            → DecisionRecord (always for adverse; CIC-010-001 §3)
            → action: allow | review (queue + hold) | step-up (SCA/IDV) | block (reason code)
```

Timeouts: a provider exceeding its budget is skipped; policy `risk.fail-mode` per decision type
decides fail-open (low-value) or fail-closed (high-value, regulated).

## 4. Model risk management (with CORPUS-017)

Risk models are versioned, validated before activation (holdout AUC/precision targets, fairness
checks on protected attributes where lawful), monitored for drift (PSI > 0.2 → alert), and have a
challenger process. Every model decision is replayable (CIC-010-001 §6).

## 5. Feedback and learning

Outcome events (chargeback, confirmed fraud, false-positive release, counterfeit confirmed, default)
are linked to the originating DecisionRecord to compute precision/recall per rule/model weekly; rules
with precision below policy threshold are flagged for review.

## 6. Certification Rules

- **CR-016-001-01** Fraud decision path p99 ≤ 50 ms (excluding external step-up) at checkout L2 load.
- **CR-016-001-02** Every adverse risk action produces a DecisionRecord with ≥ 1 reason code and signal attributions.
- **CR-016-001-03** Fail-mode test: provider timeouts trigger the policy-defined fail-open/closed behavior per decision type.
- **CR-016-001-04** Credit exposure aggregation equals recomputation from open orders + AR for 10⁴ parties.
- **CR-016-001-05** Model drift monitoring alerts on injected distribution shift within one monitoring window.

## 7. Validation Rules

- **VR-016-001-01** Every risk type has a bands policy and a fail-mode policy.
- **VR-016-001-02** Every risk provider plugin declares the signals it consumes and their data classification.
