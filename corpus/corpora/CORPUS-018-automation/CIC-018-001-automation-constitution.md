---
id: CIC-018-001
title: Automation Constitution — Workflow, Orchestration, Process Managers
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-018
dependencies: [CIC-007-001, CIC-006-001, CIC-008-001, CIC-009-001, CIC-020-001, CIC-017-001]
traces: [PRIN-004, PRIN-005, PRIN-008, PRIN-011, DOM-WFL, DOM-AUT, DOM-ORC]
certification: [CR-018-001-01, CR-018-001-02, CR-018-001-03, CR-018-001-04]
validation: [VR-018-001-01, VR-018-001-02]
---

# CIC-018-001 — Automation Constitution

## 1. Three automation mechanisms (choose the narrowest)

| Mechanism | Use when | Owner | State |
|-----------|----------|-------|-------|
| **Lifecycle** (CIC-007-001) | Behavior of a single aggregate over time | Aggregate's context | In the aggregate |
| **Process manager / saga** | Fixed, code-owned cross-context protocol (PlaceOrder, apply ChangeSet) | Initiating context | Saga table in that context |
| **Workflow** (DOM-WFL) | Configurable, long-running, human-in-the-loop or tenant-defined processes (approvals, dunning, onboarding, fallout handling, appeals, ops runbooks) | Automation context | Workflow instance store |

Rule: tenants change behavior through workflows and policies — never by editing sagas.

## 2. Workflow definition (metadata)

BPMN 2.0 subset serialized as YAML/JSON (import/export BPMN XML):

```yaml
WorkflowDefinition:
  urn: urn:ucos:<ns>:workflow:<name>@<semver>
  trigger: {kind: event|command|schedule|manual, eventType?, filter?: CEL, schedule?: cron}
  input: JSON Schema
  steps:
    - {id, kind: service-task, call: {context, operation (from OpenAPI operationId)}, input: CEL map, retry: {max, backoff}, compensation?: stepId}
    - {id, kind: human-task, queue, assignment: CEL|rule, form: ViewDefinition URN, sla: duration, escalation: [...]}
    - {id, kind: decision, ruleSet: urn | policy: urn}
    - {id, kind: wait, for: {event: type, correlate: CEL} | {timer: duration|CEL}}
    - {id, kind: gateway, type: exclusive|parallel|inclusive, branches: [{when: CEL, next}]}
    - {id, kind: subprocess, workflow: urn}
    - {id, kind: agent-task, agentProfile: urn, goal: string, tools: [operationId], autonomy: suggest|act-with-approval}
  sla: duration
  version policy: running instances finish on their version unless migration defined
```

Service tasks call only published APIs with the workflow's **run-as identity** (a System or the
initiating principal by delegation) — authorization is identical to any other caller.

## 3. Execution semantics

- Durable execution: each step transition is persisted (event-sourced instance history) before side effects; side effects carry idempotency keys `wf:<instance>:<step>:<attempt-lineage>`.
- Exactly-once observable effects via idempotent APIs; at-least-once step execution.
- Timers per CIC-007-001 §4 scheduler; correlation of waits by indexed correlation keys.
- Compensation in reverse completion order for failed sagas within workflows.
- Limits per tenant: concurrent instances, steps/second, history size (archived after completion + 90 days).

Reference engine: any engine certified against the conformance suite (Temporal-, Zeebe-, or
custom-based adapters behind `WorkflowEnginePort`).

## 4. Rules automation

Event-condition-action automations ("when invoice overdue 30 days and segment = consumer, suspend
entitlements") are expressed as workflows with an event trigger and decision step — not as ad-hoc
listeners — so they are versioned, governed, observable, and testable.

## 5. Certification Rules

- **CR-018-001-01** Engine conformance: crash at every step boundary resumes without duplicate external effects (verified through idempotency-key observation).
- **CR-018-001-02** Human-task SLA escalation fires within 60 s of breach.
- **CR-018-001-03** Workflow service tasks executed with a deny-all policy bundle fail with 403 (no privileged bypass).
- **CR-018-001-04** BPMN import/export round trip preserves semantics for the supported subset (golden models).

## 6. Validation Rules

- **VR-018-001-01** Every service-task operation exists in a published contract.
- **VR-018-001-02** Every workflow definition has a run-as identity and SLA.
