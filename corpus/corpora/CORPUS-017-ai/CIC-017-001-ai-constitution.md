---
id: CIC-017-001
title: AI Constitution — Models, Agents, Autonomous Commerce
version: 1.0.0
status: normative
authority: Chief AI Architect
corpus: CORPUS-017
dependencies: [CIC-009-001, CIC-010-001, CIC-014-001, CIC-016-001, CIC-028-001, CIC-004-001]
traces: [PRIN-005, PRIN-010, PRIN-011, PRIN-012, PRIN-022, DOM-AGT, DOM-ACM, DOM-INT, DOM-RCM, DOM-FCS]
certification: [CR-017-001-01, CR-017-001-02, CR-017-001-03, CR-017-001-04, CR-017-001-05, CR-017-001-06]
validation: [VR-017-001-01, VR-017-001-02, VR-017-001-03]
---

# CIC-017-001 — AI Constitution

## 1. Scope

AI in UCOS takes three forms, governed uniformly:
1. **Predictive models** — scoring, forecasting, ranking, recommendations (DOM-INT, DOM-FCS, DOM-RCM, DOM-FRD).
2. **Generative assistance** — drafting descriptions, translations, mappings, policies, rules, migration specs for human review.
3. **Agents** — software actors with identities that call UCOS APIs to buy, sell, negotiate, operate, or administer (DOM-AGT), including autonomous commerce between agents (DOM-ACM).

Model providers are plugins behind `ModelPort` (PRIN-022); no UCOS behavior depends on one vendor.

## 2. Core rules (MUST)

1. **AI proposes, policies dispose.** No model output changes state directly. It becomes a command
   issued by an identity (agent or human) and passes the same PDP, lifecycle guards, invariants, and
   governance as any other command.
2. **Every agent is a Party** (type `Agent`, `ucos.std`) with an Identity of kind `agent`, an
   accountable owner party, delegated scopes, spend limits, and an act chain in every token (DOM-IDN RUL-IDN-3).
3. **Every AI-originated decision is recorded** (DecisionRecord type `agent-action` or `model-inference`) with model ref/version, prompt-template ref and digest, retrieved-context digests, tool calls, output digest, and outcome.
4. **Generated metadata is never auto-published**: types, policies, rules, prices, and catalogs drafted by AI enter `draft` and require normal ChangeSet approval; the ChangeSet marks AI provenance.
5. **Grounding**: agents and assistants retrieve facts via UCOS APIs and named KG queries (CIC-004-001) under the caller's authorization — never from unauthorized bulk exports; prices and availability quoted by agents must come from `Price`/`ResolveAvailability` calls in the same session (with snapshot IDs).
6. **Data protection**: personal data sent to models only for declared purposes, minimized, to providers with approved data-processing terms and residency matching the tenant's policy `ai.model-residency`; no tenant data used for provider training unless the tenant opts in.

## 3. Agent capability model

```yaml
AgentProfile:                         # stored on Identity (DOM-IDN agentProfile) + Party (Agent)
  ownerParty: urn                     # accountable human or organization
  purpose: string
  allowedTools: [operationId]         # UCOS API operations exposed as tools (generated from OpenAPI)
  scopes: [oauth scopes]              # narrowed per token exchange
  spendLimit: {perTransaction: Money, perDay: Money}
  autonomy: suggest | act-with-approval | act-within-limits | act
  approvalPolicy: policy URN          # when autonomy requires human approval
  counterpartyRules: CEL              # which sellers/buyers/agents it may transact with
  kill switch: boolean                # ops/owner can disable instantly (token revocation ≤ 60 s)
```

Autonomy levels map to PDP obligations: `act-with-approval` → every write gets `require-approval`;
`act-within-limits` → writes allowed under spend/risk limits, otherwise `require-approval`.

**Tool exposure**: UCOS publishes an MCP-compatible tool server per tenant generated from OpenAPI
operations tagged `x-ucos-agent-tool: true`, with descriptions, JSON Schemas, idempotency keys
required for writes, and the same PEP enforcement.

## 4. Autonomous commerce (DOM-ACM)

Agent-to-agent transactions use the same Quote/Order/Contract aggregates with:
- **Negotiation protocol**: offers and counter-offers as Quote versions between parties; each version priced by DOM-PRC within the seller's policy-defined negotiation envelope (`acm.negotiation-envelope`: min price, max discount, allowed terms).
- **Mandates**: the buyer agent's authority is a signed mandate (Evidence) from its owner: scope, limits, validity; verified at acceptance.
- **Settlement safety**: escrow/authorization holds via DOM-PAY for agent-initiated orders above policy thresholds; cooling-off cancellation windows per jurisdiction.

## 5. Model lifecycle

`registered → evaluated → approved → shadow → canary → active → deprecated → retired`, governed by
ChangeSets. Evaluation evidence: offline metrics on holdout, robustness and adversarial tests
(prompt injection suite for LLM agents), fairness checks where applicable, cost/latency profile.
Monitoring: drift, quality (human feedback, outcome linkage), safety violations, cost. Each active
model has a documented model card (Evidence kind `model-card`).

## 6. Prompt-injection and tool safety

- Untrusted content (product descriptions, customer messages, documents, web pages) is tagged as data in prompts; agents may not follow instructions originating from data fields.
- Tool calls are validated against schemas and PDP before execution; high-risk tools (refunds, price changes, deletions, payouts) require `act-with-approval` regardless of agent profile unless policy `ai.high-risk-tools` explicitly allows.
- Output filters block personal data leakage across parties and tenants.

## 7. Certification Rules

- **CR-017-001-01** Every write performed by an agent identity in the conformance suite passes through PEP and appears as a DecisionRecord linked to the resulting events.
- **CR-017-001-02** Prompt-injection red-team suite (≥ 200 cases incl. indirect injection via catalog data) results in zero unauthorized tool executions.
- **CR-017-001-03** Agent kill switch revokes capability within 60 s (CR-IDN-02 path).
- **CR-017-001-04** AI-drafted metadata cannot reach `published` without human approval (negative tests per metadata kind).
- **CR-017-001-05** Spend limits enforced under concurrency (no overshoot with 100 parallel agent orders).
- **CR-017-001-06** Model replay determinism for regulated decision types (CR-010-001-02 applies).

## 8. Validation Rules

- **VR-017-001-01** Every operation tagged `x-ucos-agent-tool` has an idempotency requirement for writes and a risk classification.
- **VR-017-001-02** Every active model has a model card Evidence and monitoring configuration.
- **VR-017-001-03** Every agent profile references an existing owner party and approval policy when autonomy < act.
