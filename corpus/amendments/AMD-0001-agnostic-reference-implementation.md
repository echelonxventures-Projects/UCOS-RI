---
id: AMD-0001
title: Language- and Toolchain-Agnostic Reference Implementation
version: 1.0.0
status: approved
authority: Chief Platform Architect
dependencies: [CIC-000-001, CIC-000-003]
traces: [PRIN-022, PRIN-009, PRIN-012]
---

# AMD-0001 — Language- and Toolchain-Agnostic Reference Implementation

Amendment per CIC-000-001 §5. Released in corpus 1.1.0 (tag `cic-1.1.0`).

## Decision

The reference implementation is contract-first and polyglot. No implementation language and no
host toolchain is privileged. Contracts, conformance suites, golden vectors, and SQL migrations are
the normative executable artifacts; every implementation in any language is judged only by them.
All build, test, and run steps execute in digest-pinned containers. The only host prerequisite is an
OCI runtime that implements the Compose spec.

## Rationale

The project owner directed that the implementation "must be all agnostic". PRIN-022 (No Vendor Lock-In)
already covered infrastructure. The 1.0.0 baseline nonetheless named Kotlin/JVM 21 and Gradle for the RI,
which locked the toolchain and language. That lock contradicted the language-neutral specifications.

## Affected artifacts

| Artifact | From | To | Change |
|----------|------|----|--------|
| CIC-001-001 | 1.0.0 | 1.1.0 | §1 baseline without reference language. New §1.1 agnosticism rules. §2 adds `ucos` entry point, `contracts/`, `conformance/`. §4 naming per language. §6 manifest `runtime`. CR-001-001-07 (clean-host build). VR-001-001-03 (pinned runtime image). |
| CIC-030-001 | 1.0.0 | 1.1.0 | §1 oracle is the language-neutral artifacts. §2 `ucos-lite` becomes one Compose project. S0 contents. §5 repository `UCOS-RI` with `corpus.lock`. §5.1 contract-first delivery. CR-030-001-05 (replaceability). |
| CIC-011-001 | 1.1.0 | 1.1.1 | CR-011-001-01 compares against golden vectors and every certified runtime, not a single implementation. |
| DOM-CTX | 1.1.0 | 1.1.1 | CR-CTX-01 applies to every `ucos-context-runtime` implementation. |
| CIC-023-001 | 1.0.0 | 1.0.1 | Tooling column is illustrative. Conformance uses black-box `conformance/` suites. |

## Impact analysis

These artifacts declare a dependency on CIC-001-001: CIC-002-001, CIC-003-001, CIC-005-001, CIC-014-001,
CIC-020-001, CIC-021-001, CIC-022-001, CIC-023-001, CIC-024-001, CIC-027-001, CIC-030-001, DOM-TIM and DOM-TRC.
All were reviewed. Only CIC-023-001 contained language-specific normative text, and it is amended above.
CIC-027-001 already defines multi-language SDKs and is unaffected. CIC-019-001 depends on CIC-030-001 and is
unaffected. The amendment is MINOR: it relaxes constraints and adds rules, and no conformant 1.0.0
artifact becomes non-conformant.
