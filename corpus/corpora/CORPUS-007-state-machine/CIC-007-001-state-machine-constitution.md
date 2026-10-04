---
id: CIC-007-001
title: State Machine Constitution — LifecycleModel Semantics and Interpreter
version: 1.0.0
status: normative
authority: Chief Architect
corpus: CORPUS-007
dependencies: [CIC-000-002, CIC-000-003, CIC-008-001, CIC-009-001, CIC-006-001]
traces: [PRIN-004, PRIN-005, PRIN-008, PRIN-016, DOM-LFC]
certification: [CR-007-001-01, CR-007-001-02, CR-007-001-03, CR-007-001-04, CR-007-001-05]
validation: [VR-007-001-01, VR-007-001-02, VR-007-001-03]
---

# CIC-007-001 — State Machine Constitution

Every stateful aggregate in UCOS either (a) has a **kernel-fixed** state machine declared in its
DOM-*.yaml `stateMachines` (definition lifecycles, relationship validity), or (b) is governed by a
**LifecycleModel** — metadata interpreted at runtime (PRIN-004). Commercial objects, contracts,
entitlements, orders, and any pack-defined aggregate use (b). Code MUST NOT branch on state names of
interpreted models (lint `UCOS-L004`); it may only branch on **state categories** (§2.2).

## 1. LifecycleModel (aggregate, DOM-LFC)

```yaml
LifecycleModel:
  urn: urn:ucos:<ns>:lifecycle:<name>@<semver>
  label: LocalizedText
  appliesTo: [MetadataUrn]              # types (subtype-aware) allowed to bind this model
  extends: MetadataUrn?                  # refine a parent model (§5)
  initial: StateCode
  states:
    - code: string                       # ^[a-z][a-z0-9-]{1,47}$
      label: LocalizedText
      category: draft|review|ready|active|suspended|winding-down|closed|archived   # §2.2
      terminal: boolean
      editable: boolean                  # aggregate attributes writable in this state
      parent: StateCode?                 # hierarchical (composite) state
      onEntry: [Effect]                  # §3
      onExit:  [Effect]
      timers:  [{id, after: ISO8601 duration | at: CEL(Instant), fire: TransitionCode}]
      invariants: [CEL]                  # must hold while in state; checked on every write
  transitions:
    - code: string                       # command verb, e.g. approve
      from: [StateCode]                  # '*' allowed = any non-terminal
      to: StateCode
      kind: command|timer|event|automatic
      trigger: {eventType?: string, filter?: CEL}      # kind=event
      guard: CEL?                        # inputs: aggregate (resolved view), command, ctx, now
      policy: MetadataUrn?               # authorization policy (defaults to <context>.transition)
      requires: [{kind: approval|evidence|certification|checklist, params}]
      effects: [Effect]
      reasonRequired: boolean
      sod: {distinctFrom: [transitionCode]}?   # segregation of duties (actor must differ)
  regions: [{name, states: [StateCode]}]?       # orthogonal regions (§2.3)
```

## 2. Semantics

### 2.1 Transition execution (single aggregate, atomic)

```
function Fire(aggregate, transitionCode, cmd, ctx):
    m ← Model(aggregate.typeRef)                          # pinned version bound at instantiation
    t ← m.transitions[transitionCode]   else E-LFC-UNKNOWN-TRANSITION
    s ← aggregate.lifecycleState
    require s ∈ expand(t.from)                            else E-LFC-INVALID-STATE (409)
    require PDP.decide(t.policy, {principal, aggregate, transition}) = allow   else 403
    require CEL(t.guard, {aggregate, cmd, ctx, now}) = true                    else E-LFC-GUARD-FAILED (422, guard id)
    for r in t.requires: require Satisfied(r, aggregate)                       else E-LFC-REQUIREMENT-UNMET
    require SoD(t, aggregate.history, principal)                               else E-LFC-SOD-VIOLATION
    exitChain  ← states from s up to LCA(s, t.to), exclusive of LCA
    entryChain ← states from LCA down to t.to
    effects ← [onExit(x) for x in exitChain] ++ t.effects ++ [onEntry(y) for y in entryChain]
    newState ← t.to ; if t.to is composite: descend via its `initial` child
    check invariants(newState) on resulting aggregate                          else rollback
    events ← [LifecycleTransitioned{from: s, to: newState, transition, reason, actor}] ++ effectEvents
    persist atomically (event store + outbox); schedule timers of entered states; cancel timers of exited states
```

Run-to-completion: `automatic` transitions whose guard is true after entry fire immediately in the
same unit of work, max chain length 10 (`E-LFC-AUTOMATIC-LOOP`).

### 2.2 State categories (the only states code may depend on)

| Category | Platform meaning |
|----------|------------------|
| draft | Not visible outside authoring; fully editable |
| review | Frozen for review; edits return it to draft |
| ready | Approved, not yet effective |
| active | Sellable / effective / in force |
| suspended | Temporarily not effective; reversible |
| winding-down | No new sales/acquisitions; existing obligations continue |
| closed | No longer effective; history retained |
| archived | Terminal; read-only cold storage eligible |

Catalog, offer, availability, and entitlement logic key off categories (e.g. CIC-011-005
`catalog.visible-states` defaults to category `active` + `winding-down` for owners).

### 2.3 Orthogonal regions

A model MAY declare regions (e.g. `commercial` and `compliance`). The aggregate's state is then a
map `region → state`. A transition belongs to exactly one region. Category of the aggregate =
the most restrictive category across regions, ordering
`archived > closed > suspended > winding-down > draft > review > ready > active`.

## 3. Effects

Effects are **declarative**, never code: `{kind, params}`, kinds registered in DOM-LFC:

| Kind | Params | Result |
|------|--------|--------|
| `set-attribute` | attributeCode, value (CEL) | Attribute change in same transaction |
| `emit-event` | integrationEventType, payload (CEL) | Integration event via outbox |
| `send-command` | context, command, payload (CEL) | Async command message (process manager owns retries/compensation) |
| `start-workflow` | workflowDefinitionRef, input | DOM-WFL instance started |
| `notify` | templateRef, recipients (CEL) | Notification request |
| `attach-evidence` | evidenceKind | Evidence capture (DOM-EVD) |
| `schedule` | timerId | Explicit timer |

Effects with external side effects (send-command, start-workflow, notify) are dispatched **after
commit** via outbox; they never participate in the aggregate transaction.

## 4. Timers

Timers persist in `lifecycle_timers(tenant, aggregate, timer_id, due_at, transition, model_version)`.
A sharded scheduler polls due timers (`FOR UPDATE SKIP LOCKED`, shard by hash(tenant, aggregate))
and issues the transition as a system command with principal `urn:ucos:system:party:scheduler`.
Firing is at-least-once; the transition is idempotent via `(aggregate, timer_id, due_at)` dedupe.
Max timer skew SLO: p99 ≤ 5 s after `due_at`.

## 5. Model inheritance and versioning

- `extends` lets a child model add states (only as sub-states of parent states or new states in a
  category), add transitions, tighten guards (AND), add requirements and effects. It MUST NOT remove
  states or transitions of the parent (Liskov for lifecycles).
- Instances bind the model version pinned at creation. Upgrading in-flight instances to a new MAJOR
  requires a **state mapping** `{oldState → newState}` covering every non-terminal old state, executed
  as a migration job (CORPUS-026) emitting `lifecycle-migrated` events. MINOR upgrades (additive) apply
  lazily on next transition.

## 6. Static verification at publication

The model compiler rejects models where:
1. Any non-terminal state is unreachable from `initial`.
2. Any non-terminal state has no outgoing transition (deadlock) unless marked `terminal`.
3. Automatic transitions form a cycle whose guards are not provably mutually exclusive (conservative: any cycle is rejected).
4. A transition `to` a state whose `invariants` contradict a `set-attribute` effect of that transition (checked via CEL constant folding where possible).
5. A state's category ordering is violated by a `parent`/child pair (child category must equal parent's).

## 7. Certification Rules

- **CR-007-001-01** Interpreter conformance suite (≥ 300 cases: hierarchy entry/exit order, regions, timers, automatic chains, SoD) passes 100 %.
- **CR-007-001-02** Model compiler rejects every model in the negative corpus for §6 rules 1–5.
- **CR-007-001-03** Timer test: 10⁶ timers due in the same minute fire within p99 5 s, each exactly once observable (deduped).
- **CR-007-001-04** Lint `UCOS-L004` reports zero comparisons against interpreted state codes outside tests.
- **CR-007-001-05** Migration test: MAJOR model upgrade with mapping migrates 10⁶ instances resumably after injected crashes with zero lost or double transitions.

## 8. Validation Rules

- **VR-007-001-01** Every LifecycleModel in ucos.std passes §6 static verification.
- **VR-007-001-02** Every effect kind used is registered; every policy referenced exists.
- **VR-007-001-03** Every TypeDefinition with a lifecycleModelRef binds a model whose `appliesTo` includes the type or a supertype.
