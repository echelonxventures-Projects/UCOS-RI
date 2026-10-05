---
id: AMD-0002
title: Role Coverage for Party and Agent Commands; Tenancy of Bookkeeping Tables
version: 1.0.0
status: approved
authority: Chief Data Architect
dependencies: [CIC-000-001, CIC-003-001, CIC-029-001]
traces: [PRIN-010, DOM-PTY, DOM-IDN, DOM-AUTH, CR-003-001-01]
---

# AMD-0002 — Role Coverage for Party and Agent Commands; Tenancy of Bookkeeping Tables

Amendment per CIC-000-001 §5. Released in corpus 1.2.0 (tag `cic-1.2.0`). Raised by the reference implementation.

## 1. Role coverage (`ucos.std` 1.1.0)

**Defect.** DOM-PTY and DOM-IDN declare the permissions `party.create`, `party.update`, `party.consent.record`
and `identity.agent.create`. No `ucos.std` role granted any of them, so no tenant could register a party or an
agent without first authoring its own roles. VR-AUTH-02 checks that role permissions are declared, but it does
not check that declared command permissions are granted by some role.

**Change.** The `ucos.std` pack goes to 1.1.0 (MINOR: registry entries added). It adds:

| Role | Permissions |
|------|-------------|
| `party-steward` | `party.read`, `party.create`, `party.update`, `party.consent.record` |
| `agent-owner` (privileged) | `identity.read`, `identity.agent.create`, `party.read` |

`tenant-admin` additionally receives `authority.read` and `identity.read`.

## 2. Bookkeeping tables (CIC-003-001 1.1.0 §5, from RI AR-0001)

**Defect.** §5 required `tenant_id` and RLS on every table, but the standard DDL of §4 defines `outbox` and
`processed_messages` without `tenant_id`.

**Change.** The rule now applies to tables holding tenant data. Bookkeeping and platform-wide registry tables are
governed by role grants (service role: INSERT-only on its outbox; relay role: read and mark).

## Impact

- Pack definition URNs move from `@1.0.0` to `@1.1.0`. The definitions themselves are unchanged.
- Installations of 1.0.0 upgrade by re-installing until pack upgrades (CIC-026-001) exist.
- No conformant implementation becomes non-conformant.
