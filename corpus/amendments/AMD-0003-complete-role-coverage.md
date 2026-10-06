---
id: AMD-0003
title: Complete Role Coverage and Defined Approver Roles
version: 1.0.0
status: approved
authority: Chief Data Architect
dependencies: [CIC-000-001, CIC-029-001, DOM-AUTH]
traces: [PRIN-010, DOM-AUTH, CIC-009-001, CIC-014-001]
---

# AMD-0003: Complete Role Coverage and Defined Approver Roles

Amendment per CIC-000-001 §5. Released in corpus 1.3.0 (tag `cic-1.3.0`). Raised by the reference implementation
(S2b) when it began enforcing permissions on every API.

## Defects

1. **Ungranted permissions.** 388 permissions declared in DOM `security.permissions` across 72 domains (kernel,
   core and extension) were granted by no `ucos.std` role. Examples are `governance.changeset.approve`,
   `policy.read` and `evidence.read`. A permission-based PEP could not authorize those operations for any tenant
   using only the standard pack.
2. **Undefined approver roles.** Approval plans in `ucos.std` policies named 22 roles that the role registry did
   not define (`domain-owner`, `chief-architect`, `commercial-director`, `cfo-office`, …). VR-AUTH-01 checked only
   role names used in CEL.

## Changes (`ucos.std` 1.2.0; DOM-AUTH 1.1.0)

- **Per-context roles.** For every bounded context, two roles are generated from the DOM specs:
  - `<context>-reader` holds the context's read permissions;
  - `<context>-operator` (privileged) holds every permission of the context.

  Hand-written roles are unchanged. Tenants compose narrower roles from these.
- **Approver roles.** Every role named by an `approverRoles` list is now defined. Governance approvers hold
  `governance.read` and `governance.changeset.approve`. Other approvers hold `governance.read`, because their
  authority comes from the approval plans that name them.
- **New validation rules, enforced by the corpus validator:**
  - **VR-AUTH-03:** every declared permission is granted by at least one `ucos.std` role;
  - **VR-AUTH-04:** every approver role named in a policy body is defined.

## Impact

- Pack definition URNs move to `@1.2.0`. The definitions themselves are unchanged; only registry entries are added.
- Installed tenants pick up the roles on re-install until pack upgrades (CIC-026-001) exist.
- No conformant implementation becomes non-conformant.
