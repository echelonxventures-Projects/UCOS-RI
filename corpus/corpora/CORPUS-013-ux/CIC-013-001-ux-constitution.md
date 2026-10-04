---
id: CIC-013-001
title: UX Constitution — Interaction Standards for Governed Commerce Work
version: 1.0.0
status: normative
authority: Chief Product Architect
corpus: CORPUS-013
dependencies: [CIC-012-001, CIC-010-001, CIC-015-001, CIC-005-001]
traces: [PRIN-011, PRIN-014, PRIN-006]
certification: [CR-013-001-01, CR-013-001-02, CR-013-001-03, CR-013-001-04]
validation: [VR-013-001-01, VR-013-001-02]
---

# CIC-013-001 — UX Constitution

## 1. Users and jobs

| Persona (role family) | Primary jobs | Surface |
|-----------------------|--------------|---------|
| Commercial author (product, pricing, catalog, offer managers) | Define types/objects, contextual values, prices, catalogs, offers; preview by context | Console |
| Approver (domain owners, finance, legal, compliance) | Review ChangeSets, impact, simulation; approve/reject | Console (approval inbox) |
| Seller / service agent | Configure, quote, order on behalf, resolve exceptions | Console / partner portal |
| Operator (order desk, billing ops, inventory, payments) | Fallout queues, disputes, reconciliation breaks | Console (work queues) |
| Customer / buyer / partner | Discover, buy, manage subscriptions, entitlements, invoices | Channel apps via SDK |
| Agent supervisor | Oversee AI agents' actions and approvals | Console (agent oversight) |

## 2. Interaction standards (MUST)

1. **Context is always visible**: every screen that shows contextual facts (prices, availability, text, catalogs) shows the active ContextVector as a chip bar and offers "view as" (simulate another context, `asOf` included) — the preview runs the real resolvers, never a client approximation.
2. **Explain everywhere**: any resolved value (price, availability, eligibility, policy decision) has an "Why?" affordance that renders the server trace (CIC-011-001 §4, CIC-010-001 §5) in plain language with reason codes.
3. **Draft → review → publish** is uniform for all governed metadata: same states, same diff view, same impact panel (CIC-015-001 §3), same approval inbox.
4. **Diffs before commit**: every governed change and every bulk operation shows a structured before/after diff with counts (objects, prices, tenants affected) before submission.
5. **No silent failure**: commands return Problem Details; UI maps `code` to localized message + remediation; partial batch failures list each failed item with a retry path.
6. **Concurrency**: on 409/412 the UI shows the other actor's change (diff) and offers merge or reload — never last-write-wins overwrite.
7. **Destructive or irreversible actions** (crypto-shred, write-off, revoke, retire) require typed confirmation of the object name plus reason, and show the policy obligations that will apply (e.g. approval required).
8. **Time zones**: timestamps show the user's zone with tooltip of UTC and the object's business zone where relevant (node calendars, bill cycles).
9. **Agent transparency**: any action proposed or taken by an AI agent is labeled with the agent identity, accountable party, and a link to its DecisionRecord; humans can approve, edit, or reject proposals inline.

## 3. Work queues

Exception handling is queue-based: fallout (orders), DLQ (ops), disputes (billing/payments),
reconciliation breaks, match reviews (party), approval inbox, data-quality issues. All queues share:
SLA timers with escalation (DOM-WFL), assignment rules (metadata), bulk actions with diffs, and
evidence capture on resolution.

## 4. Content standards

Plain language at CEFR B2 for customer-facing copy; error messages follow "what happened — why — what
to do"; reason codes map to approved copy per locale; no blame wording; sentence case.

## 5. Research and measurement

Each persona's top tasks have UX metrics: task success rate ≥ 90 %, time-on-task targets per task,
SUS ≥ 75 for console releases; instrumented via privacy-safe product analytics (no personal data,
aggregate only, CIC-022-001).

## 6. Certification Rules

- **CR-013-001-01** Every screen rendering contextual facts exposes the context bar and "Why?" affordance (automated UI audit over derived views).
- **CR-013-001-02** Moderated usability tests of top 10 tasks per persona achieve ≥ 90 % task success before GA of a console MAJOR.
- **CR-013-001-03** All governed metadata kinds use the shared draft/review/publish flow components (static check: no bespoke publish flows).
- **CR-013-001-04** Every error code reachable from the console has localized remediation copy in all tier-1 locales.

## 7. Validation Rules

- **VR-013-001-01** Every reason code in registries has approved copy for every tier-1 locale.
- **VR-013-001-02** Every work queue definition declares SLA, assignment rule, and resolution evidence kind.
