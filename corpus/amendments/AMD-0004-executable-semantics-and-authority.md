---
id: AMD-0004
title: Executable Semantics Annexes, Authority Lifecycle and Remote Governed Owners
version: 1.0.0
status: approved
authority: Chief Architect
dependencies: [CIC-000-001, CIC-011-001, CIC-006-001, CIC-015-001, DOM-AUTH]
traces: [PRIN-005, PRIN-006, PRIN-010, PRIN-011, DOM-AUTH, DOM-CTX, DOM-EVT, DOM-GOV]
---

# AMD-0004: Executable Semantics Annexes, Authority Lifecycle and Remote Governed Owners

Amendment per CIC-000-001 §5. Released in corpus 1.4.0 (tag `cic-1.4.0`). It adopts reference-implementation
amendment requests AR-0002, AR-0003 and AR-0004, which the RI raised during slices S1 and S2c.

## Defects

1. **Undecidable details.** CIC-011-001 (context resolution), CIC-006-001 (FULL_TRANSITIVE event-schema
   compatibility) and DOM-AUTH (delegation, segregation of duties, signing authority, mandates) left open details
   that change results. Two conforming implementations could disagree: byte-for-byte on resolution, on whether a
   schema change is compatible, and on who may act.
2. **Incomplete authority lifecycle.** DOM-AUTH required approval for some role assignments but defined no command to
   approve or reject them. MandateLifecycle had an `exhausted` state that no command could reach.
3. **Governed definitions outside the governance service.** CIC-015-001 required DOM-AUTH definitions to change "via
   ChangeSet" but did not say how governance publishes definitions owned by another service.

## Changes

- **New normative annexes:**
  - **CIC-011-007** Context Resolution Executable Semantics, for CIC-011-001 (now 1.2.0).
  - **CIC-006-002** Event Registry and Schema Compatibility Executable Semantics, for CIC-006-001 (now 1.1.0). It
    defines the schema profile and the `accepts` relation. Events may declare `classification`; the default is
    `internal`.
  - **CIC-002-003** Authority Executable Semantics, for DOM-AUTH (now 1.2.0). It covers effective authority with the
    delegation base rule, grant-time invariants, conservative SoD scope overlap, the action → permission mapping,
    CheckSigningAuthority, evidence-backed mandates, delegation-aware tokens and millisecond revocation cut-offs,
    assignment approval, access reviews with derived suspension, mandate usage, and tenant role definitions.
- **DOM-AUTH 1.2.0:**
  - ApproveRoleAssignment, RejectRoleAssignment and RecordMandateUsage, with their REST paths and events
    (`role.assignment-requested/approved/rejected`, `mandate.usage-recorded`, `mandate.exhausted`).
  - RoleAssignmentLifecycle; `assignable.approverRoles` and role `sensitivity`.
  - CR-AUTH-04 (RUL-AUTH-3 enforcement) and CR-AUTH-05 (mandate usage limits).
- **CIC-015-001 1.1.0:** each governed kind has one owning context. Owners hosted outside governance implement the
  remote owner protocol. Governance remains the only publisher and checks its Gate before every publish.

## Impact

- Additive for consumers: the new commands, events and annexes do not change the meaning of existing ones.
- Implementations that already conform to the RI's executable semantics conform to the annexes unchanged.
- Generated contracts for DOM-AUTH gain three operations and five event channels.
