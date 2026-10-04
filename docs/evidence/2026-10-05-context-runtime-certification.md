# Evidence: ucos-context-runtime L1 conformance run (2026-10-05)

- Command: `./ucos ctx-conformance 1000000` (generator seed `s1`)
- Corpus: cic-1.1.0 (corpus.lock); semantics: contracts/context-runtime/semantics.md (S1-CTXRT 1.0.0)
- Runtime images (local build ids):
  - Go: `sha256:c15d8f84e5d4f5f5899ec5073f60025f107fef84a9377658ddf2dbf96f3f88a1`
  - TypeScript: `sha256:dafc8b9f3eb43406c12c99886092fe01e447cb6840e3a37dd4b414f22de5b00d`

| Rule | Result |
|------|--------|
| CR-011-001-01 determinism | 10⁶ generated cases produced 1,225,234 results (resolve, assemble, and metamorphic twins). Go and TypeScript are **byte-identical**. Golden vectors: 328/328 passed on both. The context digest also agrees with an independent Python computation. |
| CR-011-001-02 metamorphic | 127,882 universal-candidate twins checked; 0 changed the result |
| CR-011-001-03 fallback order | Every ucos.std hierarchical dimension and leaf chain was checked. Ancestor k is reached at step k, and step k−1 exhausts. Drop order follows reverse precedence for each adjacent dimension pair. All passed. |
| CR-011-001-04 performance | 1,000 candidates, in process. Go: p50 92 µs, p99 381 µs. TypeScript: p50 214 µs, p99 433 µs. The limit is p99 ≤ 2,000 µs. |

**Suite sensitivity:** the suite was run against three mutants with injected single-line bugs: validFrom tie order,
DepthFactor, and drop direction. Each was detected by both the golden vectors and the differential.

CI runs the same suite with N = 20,000 on every push.
