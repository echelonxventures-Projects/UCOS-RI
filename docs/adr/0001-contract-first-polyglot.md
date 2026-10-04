# ADR 0001 — Contract-first, polyglot, container-only reference implementation

- Status: accepted (2026-10-05)
- Traces: AMD-0001, CIC-001-001 §1.1, CIC-030-001 §5.1, PRIN-022

## Context
The project owner required the implementation to be "all agnostic". Corpus 1.0.0 named Kotlin/JVM and Gradle
for the RI. AMD-0001 (corpus 1.1.0) removed that requirement.

## Decision
1. Normative executable artifacts are language-neutral: `contracts/` and `conformance/`, plus SQL migrations
   and the vendored `corpus/`.
2. Per-domain OpenAPI 3.1 and AsyncAPI 3.0 skeletons are generated from the DOM specs
   (`tools/gen_contracts.py`). CI fails on drift.
3. Conformance suites are black-box: they reach an implementation only through HTTP, CloudEvents and SQL.
4. The only host prerequisite is an OCI runtime with Compose. `./ucos` is POSIX `sh` and only drives that runtime.
   Every image is pinned by digest.
5. Each module chooses its language and declares it in `ucos-module.yaml` `runtime`.

## Consequences
- Any module can be reimplemented in another language and swapped in (CR-030-001-05).
- Platform libraries (context runtime, PEP client, and so on) exist once per language. They are admitted only when
  they pass shared vectors.
- In-process composition across languages is impossible. `ucos-lite` is one Compose project (CIC-030-001 §2).
