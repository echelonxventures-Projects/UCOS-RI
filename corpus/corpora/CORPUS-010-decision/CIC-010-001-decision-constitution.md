---
id: CIC-010-001
title: Decision Constitution — Decision Records, Explainability, Replay
version: 1.0.0
status: normative
authority: Chief Governance Architect
corpus: CORPUS-010
dependencies: [CIC-009-001, CIC-008-001, CIC-011-001, CIC-003-001]
traces: [PRIN-005, PRIN-011, PRIN-012, DOM-DEC, DOM-EVD]
certification: [CR-010-001-01, CR-010-001-02, CR-010-001-03, CR-010-001-04]
validation: [VR-010-001-01, VR-010-001-02]
---

# CIC-010-001 — Decision Constitution

## 1. What is a decision

A **decision** is any evaluation whose outcome changes what UCOS does for a party: authorization,
pricing, eligibility, availability promise, fraud/risk scoring, recommendation selection, AI-agent
action selection, approval routing. Decisions are produced by **decision providers**: PDP (CIC-009),
rule engine (CIC-008), resolvers (CIC-011), models (CORPUS-017), and humans (approval tasks).

## 2. DecisionRecord

```yaml
DecisionRecord:
  id: urn:ucos:<tenant>:decision:<ulid>
  decisionType: string               # registered, e.g. authorization, price, eligibility, fraud-score, agent-action, approval
  provider: {kind: pdp|rules|resolver|model|human, ref: urn, version: semver | modelVersion}
  subject: urn?                      # aggregate the decision is about
  principal: urn                     # who/what requested it
  inputs: {digest: sha256, snapshotRef?: urn, redactedInputs: json}   # §4
  context: {digest, vectorRef?}
  output: json                       # outcome, scores, selected items
  confidence: decimal?               # model / probabilistic providers
  reasons: [{code, messageKey, params}]   # human-explainable reasons (adverse-action ready)
  trace: json?                       # provider-specific trace (resolution trace, rule hits, feature attributions)
  obligations: [Obligation]
  supersedes: urn?                   # override / appeal chain
  humanReview: {required: bool, reviewer?: urn, outcome?: confirm|override, at?}
  correlationId: ULID
  decidedAt: Instant
  retentionClass: standard|regulated|financial
```

## 3. Recording policy

| Decision type | Record | Trace |
|---------------|--------|-------|
| Authorization allow | Sampled (policy `decision.sampling`, default 1 %) | Sampled |
| Authorization deny | Always | Always |
| Price bound to quote/order | Always (pricingSnapshotId + result) | Always |
| Eligibility, credit, fraud, risk scoring affecting a party | Always | Always |
| AI-agent action (CORPUS-017) | Always | Always incl. prompt/context digests |
| Recommendations / ranking | Aggregated (impression logs), per-decision record optional | Sampled |
| Human approvals | Always | — |

Regulated decisions (fact kinds flagged `regulated`, or decision types flagged by the
`decision.regulated-types` policy per jurisdiction) MUST be recorded synchronously before the
outcome is returned (write-ahead); others asynchronously via the event bus.

## 4. Inputs and privacy

Raw inputs are not stored when they contain personal data. Instead: (a) `inputs.digest` over the
canonical input, (b) `snapshotRef` pointing to versioned source data (e.g. pricing snapshot, policy
bundle sequence, feature store snapshot), sufficient for replay, and (c) `redactedInputs` with
personal fields replaced by classification tags. Inputs that cannot be reconstructed from snapshots
and are needed for regulated replay are stored encrypted under the subject key (crypto-shreddable).

## 5. Explainability

- Every decision type registers a **reason code catalogue** (`E-`/`R-` codes with localized message keys).
- Adverse decisions affecting a party (deny of credit/eligibility, fraud block, price above list due to
  segment) MUST include ≥ 1 reason code and be retrievable by the party via `GET /v1/decisions/{id}/explanation`
  (PDP-guarded; party sees only own decisions, internal trace removed).
- Model decisions include top-k feature attributions (k ≥ 3) mapped to reason codes.

## 6. Replay

`POST /v1/decisions/{id}:replay` re-executes the provider at its recorded version against the recorded
snapshots and returns `{original, replayed, equal: bool, diff}`. Providers MUST be deterministic for
the same version and snapshots (models: deterministic inference mode, fixed seeds). Replay of a
regulated decision that is not equal raises `ucos.policy.decision.replay-mismatch.v1` (Sev-2; declared by DOM-DEC).

## 7. Overrides and appeals

An override creates a new DecisionRecord with `supersedes`, `provider.kind = human`, reason, and
Evidence. The superseded decision is never modified. Appeal workflows are DOM-WFL definitions bound to
decision types.

## 8. Certification Rules

- **CR-010-001-01** Write-ahead test: for regulated decision types, killing the provider after decision computation but before persistence never returns the outcome to the caller.
- **CR-010-001-02** Replay determinism: 10⁴ sampled regulated decisions replay with `equal = true`.
- **CR-010-001-03** Privacy scan: no DecisionRecord field outside encrypted payloads contains values classified personal (DLP scanner on stored records).
- **CR-010-001-04** Every adverse decision in the conformance suite returns ≥ 1 localized reason via the explanation endpoint.

## 9. Validation Rules

- **VR-010-001-01** Every decision type registered has a reason code catalogue and a retention class.
- **VR-010-001-02** Every `decisions` entry in DOM-*.yaml names an algorithm/artifact or provider that exists in the corpus.
