---
id: CIC-011-007
title: Context Resolution Executable Semantics
version: 1.0.0
status: normative
authority: Chief Architect
corpus: CORPUS-011
dependencies: [CIC-011-001, CIC-011-003]
traces: [DOM-CTX, CIC-011-001]
certification: []
validation: []
---

# CIC-011-007 — Context Resolution Executable Semantics

Normative annex to CIC-011-001, adopted by AMD-0004 from the reference implementation (AR-0002). It restates the parent
specification as executable semantics: where the parent leaves a detail open that changes results, this annex
decides it, and every implementation in any language must agree with it. Clarifications introduced here are marked
in brackets (for example **[C1]**). Golden vectors and black-box suites live with the reference implementation
(CIC-030-001 §5.1). Paths in this annex such as `conformance/…` and `contracts/…` refer to the reference
implementation repository.

- Traces: CIC-011-001 1.1.1 (§1–4), CIC-011-003 §2, DOM-CTX 1.1.1, CR-011-001-01..04, CR-CTX-01
- Status: normative for every `ucos-context-runtime` implementation in any language (CIC-001-001 §1.1 rule 4)

This contract restates CIC-011-001 as an executable specification. Byte-identical output across languages
needs some details that the corpus leaves open. Those clarifications are marked **[C#]**.

## 1. Runner protocol (how conformance reaches an implementation)

An implementation ships a **runner**: a container command that reads JSON Lines from stdin and writes
JSON Lines to stdout. It writes exactly one output line per `case` input line, in input order.

| Input `kind` | Fields | Output |
|--------------|--------|--------|
| `world` | `id`, `dimensions[]` (§2) | none; the runner caches the world under `id` |
| `case` | `id`, `world`, `op` = `resolve` or `assemble`, plus the op fields (§3, §4) | `{"id":…, "result":…}` |
| `bench` | `id`, `world`, `case` (a resolve case), `iterations` | `{"id":…, "p99Micros":int, "p50Micros":int}` (excluded from differential comparison) |

Every output line is RFC 8785 (JCS) canonical JSON **[C1]**:
- object keys sorted by UTF-16 code units;
- no insignificant whitespace;
- strings escaped exactly as ECMAScript `JSON.stringify` escapes them: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other
  characters below U+0020 as `\u00xx` in lowercase hex, and everything else emitted raw as UTF-8.

All numbers in the protocol are integers in the signed 64-bit range. Non-integers are not allowed in inputs or
outputs **[C2]**. Instants are RFC 3339 UTC strings of the fixed form `YYYY-MM-DDTHH:MM:SS.sssZ`. That form sorts
lexicographically in time order, so implementations compare instants as strings **[C3]**.

## 2. World (dimensions)

```json
{"code":"locale","valueType":"hierarchical-enum","weight":100,"precedence":18,"required":false,
 "default":"und","normalize":"bcp47","values":null,"hierarchy":{"fr-CA":"fr","fr":"und"},"fromAsOf":false}
```

- **`hierarchy`** maps child to parent. `depth(v)` is the number of parent steps from `v` to a root, so a root has
  depth 0. A value absent from the map has depth 0 and no ancestors. Implementations follow at most 64 parent
  steps, and a cycle is treated as a root **[C4]**.
- **`ancestors(v)`** lists the parents of `v`, nearest first, excluding `v` itself.
- **`values`** is the allowed set, or `null`. When it is `null` and a hierarchy exists, the allowed set is every
  key and parent in the hierarchy. When there is no hierarchy, any value is allowed.
- **`normalize`** is `bcp47`, `upper`, or `none` **[C5]**. Under `bcp47`, `_` becomes `-`. The first subtag is
  lowercased; any later subtag that is 4 letters is title-cased; any later subtag that is 2 letters or 3 digits
  is uppercased; every other subtag is lowercased.
- **`fromAsOf: true`** marks the `time` dimension, whose value is the evaluation instant. It is excluded from
  the context digest.

## 3. `resolve`: CIC-011-001 §3

Input fields:
- `factKind`;
- `candidates[]`: each is `{id, scope:[{dimension, op, values[]}], validFrom, validTo|null, priority, value}`.
  The `id` values are ULIDs, distinct within a case;
- `context`: `{values:{dimension:scalar}, asOf}`. Context values are strings, integers, or booleans;
- `config`: `{dimensionPrecedence[], conflictStrategy, cardinality, relaxationAllowed, fallbackChains[],
  maxFallbackSteps (default 32), configRef|null}`.

The `context.values` are taken as given. They have already been assembled and normalized (§4).

1. **Temporal filter.** Keep candidates with `validFrom ≤ asOf` and either `validTo = null` or `asOf < validTo`.
   Instants are compared as strings (§1).
2. **Match.** `Matches(scope, ctx)` follows §3.1 of the corpus. Scalars are equal when both type and value are
   equal (`"1"` ≠ `1`). `range` compares the value `v` against `[values[0], values[1])` numerically when all
   three are integers, by code points when all three are strings, and is false otherwise. `eq` and `in` never
   consult the hierarchy.
3. **Fallback** runs only when no candidate matches and `relaxationAllowed` is true. A counter `steps` starts at 0,
   and every relaxed context starts from the *original* context; relaxations do not accumulate **[C6]**.
   - a. For each `d` in `fallbackChains` that is present in the context, and for each `a` in
     `ancestors(ctx[d])`: increment `steps`. If `steps > maxFallbackSteps`, return not-found with
     `E-CTX-FALLBACK-EXHAUSTED`. Otherwise try `ctx[d := a]`, with path `"<d>:<v>→<a>"`.
   - b. Then compute the precedence order **[C7]**: the dimensions named in `config.dimensionPrecedence`, in that
     order, followed by all other world dimensions sorted by `precedence` ascending, then by `code`. Walk that
     order in **reverse**. For each `d` that is present in the context and has `required = false`, apply the same
     step counting and try `ctx \ {d}`, with path `"<d>:<v>→*"`.
   - c. The first step that produces any match ends the fallback. That step's context becomes the *effective
     context* for ranking, and `fallbackPath` is `[path]`. If the steps run out with no match, return not-found
     with `E-CTX-NOT-FOUND`.
4. **Specificity** is computed per matched candidate, against the effective context **[C8]**. Use IEEE 754 binary64
   arithmetic, evaluating exactly as written with **no fused multiply-add**:
   ```
   S := 0.0
   for k in scope (in input order):
       t := weight(k.dimension) × opFactor(k) × depthFactor(k)      // left to right
       S := S + t
   specificity := truncate_toward_zero(S × 1000000.0)               // integer
   ```
   - `opFactor` values: `eq` = 1.0; `in` = 1.0 / sqrt(n), where n is the number of values; `range` = 0.75;
     `descendant-of` = 0.5; `not-in` = 0.1; `exists` = 0.05.
   - `depthFactor` is 1.0 for every op except `descendant-of`. For `descendant-of`, take the matched value `x`
     with the greatest `depth(x)` (the deepest match) and compute (depth(x) + 1.0) / (depth(v) + 1.0) **[C9]**.
   - A constraint on a dimension that is not in the world gets weight 0.
5. **Rank.**
   - The key is `(P, specificity, priority, validFrom, id)`, where `P` is one flag per entry of
     `dimensionPrecedence`. Each flag is 1 when the scope constrains that dimension and 0 when it does not.
   - Sort descending on `P` (lexicographic), then `specificity`, then `priority`, then `validFrom`. Sort
     **ascending** on `id`, which is how −Ordinal(id) works out **[C10]**.
   - `trace.ranking` lists every matched candidate in that order as `{id, specificity, priority}`.
6. **Cardinality `many`.** The result is `status: many`, `selected` holds every matched id in rank order, and
   `value` is null.
7. **Ties.** `top` is the set of candidates whose `(P, specificity, priority)` equals that of the first-ranked
   candidate. When `top` has exactly one member, the result is `one`, with that candidate's `value`.
   Otherwise apply the conflict strategy:

| Strategy | Result |
|----------|--------|
| `error` | `status: error`, `code: E-CTX-AMBIGUOUS`, `selected: []` |
| `most-recent` | `one`: greatest `validFrom`, then greatest `id` |
| `lowest-value` / `highest-value` | `one`: extreme `value`. Values compare as integers, or as Money `{amountMinor:string, currency, scale}` by exact rational value. Mixed types or currencies give `error` with `E-CTX-INCOMPARABLE`. Ties are broken by rank order. |
| `merge` | `one`. `selected` is every member of `top` in rank order. `value` is a deep merge in rank order: the first value wins for scalars and arrays; objects merge recursively. |
| `all` | `many`, with `selected` = `top` in rank order |
| `policy:<urn>` | `error` with `E-CTX-POLICY-DELEGATION-UNAVAILABLE` in a standalone runtime **[C11]**. Service integration with the PDP arrives with DOM-POL. |

For every conflict, `trace.conflict` is `{strategy, tied:[ids in rank order]}`; otherwise it is `null`.

### Result

```json
{"status":"one|many|not-found|error","selected":[…],"value":…|null,"code":null|"E-CTX-…",
 "trace":{"factKind":…,"contextDigest":…,"candidates":n,"afterTemporal":n,"matched":n,
          "fallbackPath":[…],"ranking":[…],"conflict":…,"selected":id|null,"configRef":…}}
```

- **`trace.matched`** counts the matches in the effective context.
- **`trace.selected`** is the chosen id for `one` results; for a `merge`, it is the first id. In every other
  case it is `null`.
- **`contextDigest`** is `hex(sha256(JCS(values)))` + `":"` + `floor(epochMillis(asOf) / (granularitySeconds × 1000))`.
  The `values` exclude any `fromAsOf` dimensions. `granularitySeconds` is `context.cacheGranularitySeconds`,
  with a default of 60 **[C12]**.

## 4. `assemble`: CIC-011-001 §2

Input fields:
- `explicit`: dimension to scalar;
- `principal`: dimension to scalar;
- `derivations[]`: `{id, inputs[], output, authoritative, table:{inputValue: outputValue}}`, already in
  topological order;
- `asOf`;
- `cacheGranularitySeconds`.

Every value is normalized (§2 `normalize`) at the moment it is set; derivation tables are keyed by normalized values.

Steps:
1. Start with the explicit values, source `explicit`. Then add principal values that are absent, also source
   `explicit`, because the principal is caller identity.
2. Apply the derivations in order. A derivation applies when all of its inputs are present and the table has an
   entry for the value of `inputs[0]`; `table` is a lookup table and stands in for the rule engine until DOM-RUL
   lands **[C13]**. When the output is already present, a non-authoritative derivation is skipped and an
   authoritative one overrides the value. The source becomes `derived`.
3. Set every `fromAsOf` dimension to `asOf`, with source `derived`.
4. Give each absent dimension that has a `default` and is not required its default, with source `default`.
5. If a required dimension is absent, fail with `E-CTX-REQUIRED-MISSING`. When several are missing, report the
   first by precedence order (§3 step 3b).
6. Check each value against the allowed set (§2). The first invalid one, by precedence order, fails with
   `E-CTX-INVALID-VALUE`.

Output: `{"status":"ok|error","code":…,"dimension":…|null,"vector":{d:{"value":…,"source":…}},"contextDigest":…|null}`.
On error, `vector` is `{}`.
