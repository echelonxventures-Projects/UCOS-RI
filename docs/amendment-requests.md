# Corpus amendment requests raised by the RI

Per CIC-030-001 §4.2, a deviation is recorded here and is never made silently. Each request is submitted
to the corpus repository as an amendment.

## AR-0001 — Tenant column on platform bookkeeping tables (CIC-003-001 §4 vs §5)

- Raised: 2026-10-05, slice S0
- Conflict:
  - CIC-003-001 §5 says "Every table has `tenant_id` as the first PK column", and CR-003-001-01 applies RLS
    "on every table".
  - The standard DDL in §4 defines `outbox` and `processed_messages` without `tenant_id`.
- RI behaviour (S0):
  - Both tables are treated as non-tenant platform bookkeeping. The service role may only `INSERT` into
    `outbox` and cannot read it.
  - Only the dedicated relay role may `SELECT` and `UPDATE` it. §5 allows dedicated roles for platform-wide jobs.
  - `processed_messages` holds only consumer names and event ids.
  - The conformance suite verifies these grants (`test_bookkeeping_tables_not_readable_by_service_role`).
- Proposed amendment: in CIC-003-001 §5, state that the rule applies to tables holding tenant data. Name
  `outbox` and `processed_messages` as platform bookkeeping governed by role grants. Alternatively, add
  `tenant_id` to both tables.
