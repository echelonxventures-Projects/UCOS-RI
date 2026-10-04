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

## AR-0002: Executable precision for context resolution (CIC-011-001 §1.2, §3, §6)

- Raised: 2026-10-05, slice S1 (context runtime)
- Problem: CR-011-001-01 requires byte-identical Resolutions across implementations in any language.
  CIC-011-001 leaves several details open that change the bytes. `contracts/context-runtime/semantics.md`
  pins each one, and every clarification below is labelled there:
  - **C1–C3:** canonical JSON (JCS), integer-only numbers, and fixed-width instants compared as strings.
  - **C4–C5:** hierarchy cycle handling and value normalization rules.
  - **C6:** fallback relaxations are **not cumulative**. The corpus wording "yield ctx[d := a]" / "yield ctx \ {d}"
    allows either reading.
  - **C7:** the precedence order used for the reverse-precedence drop is `dimensionPrecedence`, followed by the other
    dimensions by `defaultPrecedence` and then code.
  - **C8:** specificity is computed with binary64 terms summed in scope order, truncated once, and no FMA.
    (The corpus says "multiplying by 10⁶ and truncating" without fixing an evaluation order.)
  - **C9:** for `descendant-of` with several matching values, the deepest match determines DepthFactor.
  - **C10:** the tie-break is by ascending id (−Ordinal).
  - **C11:** `policy:` strategies need the PDP and return `E-CTX-POLICY-DELEGATION-UNAVAILABLE` standalone.
  - **C12:** contextDigest is formatted as `hex:bucket`, with 60 s default granularity.
  - **C13:** table-driven derivations stand in until the rule engine lands.
- Proposed amendment: adopt the semantics document as a normative annex of CIC-011-001 (version 1.2.0), and
  publish the golden vectors (`conformance/context-resolution/`) as the CR-011-001-01 reference.
