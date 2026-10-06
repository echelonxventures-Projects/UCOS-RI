---
id: CIC-006-002
title: Event Registry and Schema Compatibility Executable Semantics
version: 1.0.0
status: normative
authority: Chief Architect
corpus: CORPUS-006
dependencies: [CIC-006-001]
traces: [DOM-EVT, CIC-006-001]
certification: []
validation: []
---

# CIC-006-002 — Event Registry and Schema Compatibility Executable Semantics

Normative annex to CIC-006-001, adopted by AMD-0004 from the reference implementation (AR-0003). It restates the parent
specification as executable semantics: where the parent leaves a detail open that changes results, this annex
decides it, and every implementation in any language must agree with it. Clarifications introduced here are marked
in brackets (for example **[C1]**). Golden vectors and black-box suites live with the reference implementation
(CIC-030-001 §5.1). Paths in this annex such as `conformance/…` and `contracts/…` refer to the reference
implementation repository.

- Traces: DOM-EVT (INV-EVT-1..3, VR-EVT-01/02), CIC-006-001 §3 rule 3 (FULL_TRANSITIVE), CR-006-001-04, RUL-EVT-1
- Status: normative for every `event-platform-service` implementation, in any language
- Precision added here is marked **[E#]**.

## 1. Scope and tenancy

Event types are platform metadata, shared by all tenants, keyed by the type string. The registry tables have no
`tenant_id`. Every call needs a valid UCOS access token (DOM-IDN). Reads are open to any authenticated principal of
any tenant. Writes need a DPoP-bound token of the `platform` tenant with scope `ucos:eventing:write`, whose roles
grant `eventing.registry.write` in the platform role catalog (for example `eventing-operator`, `ucos.std` 1.2.0).
Emitted events belong to the `platform` tenant **[E1]**.

## 2. API

All bodies are JSON. Errors are RFC 9457 problems.

| Operation | Request | Success |
|-----------|---------|---------|
| `POST /v1/eventing/event-types` | `{type, owningContext, category, classification, retention?, externalSubscribable?}` | `201` EventType; `200` if identical to the existing one (idempotent) |
| `GET /v1/eventing/event-types?owningContext=&category=` | — | `200 {items:[EventType], nextCursor:null}`, sorted by `type` in code-point order |
| `GET /v1/eventing/event-types/{type}` | — | `200` EventType |
| `POST /v1/eventing/event-types/{type}/schemas` | `{semver, schema}` | `201 {type, semver, digest, compatibility}`; `200` if the same semver and digest already exist |
| `GET /v1/eventing/event-types/{type}/schemas/{semver}` | — | `200` the schema, exactly as registered |

`EventType` = `{type, owningContext, category, classification, retention:{logDays, compacted}, externalSubscribable,
state:"published", versions:[{semver, digest, registeredAt, compatibility}]}`. Versions are sorted by semver
ascending. The default `retention` is `{logDays:30, compacted:false}`.

Errors:

| Status | Code | Meaning |
|--------|------|---------|
| 400 | `E-EVT-INVALID-TYPE` | the type does not match `^ucos\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.v[0-9]+$` |
| 422 | `E-EVT-CONTEXT-MISMATCH` | the context segment of the type ≠ `owningContext` (INV-EVT-1) |
| 409 | `E-EVT-OWNER-CONFLICT` | the type is already registered with a different owner or attributes (INV-EVT-3) |
| 404 | `E-EVT-TYPE-NOT-FOUND` | unknown type |
| 404 | `E-EVT-SCHEMA-NOT-FOUND` | unknown version |
| 422 | `E-EVT-MAJOR-MISMATCH` | the semver MAJOR ≠ N in `.vN`; a breaking change needs a new type (RUL-EVT-1) |
| 422 | `E-EVT-SCHEMA-PROFILE` | the schema uses something outside the profile (§3) |
| 409 | `E-EVT-INCOMPATIBLE` | the schema fails FULL_TRANSITIVE compatibility (§4); `detail` names the prior version and the reason |
| 409 | `E-EVT-VERSION-ORDER` | the semver is not greater than the latest registered version **[E2]** |
| 409 | `E-EVT-VERSION-EXISTS` | the semver already exists with a different digest |
| 401 | `E-IDN-…` | no valid token, or a write without a DPoP-bound token (RUL-IDN-1) |
| 403 | `E-API-INSUFFICIENT-SCOPE` / `E-API-FORBIDDEN` | missing scope, or no `eventing.registry.write` in the platform tenant |

`RegisterEventSchemaVersion` checks run in this order, and the first failure is returned **[E6]**:
1. type exists (404);
2. the body is a JSON object;
3. profile (§3);
4. integer-only JSON;
5. semver syntax (400 `E-API-VALIDATION`);
6. MAJOR matches;
7. same semver (200 if the digest is equal, else `E-EVT-VERSION-EXISTS`);
8. version order;
9. FULL compatibility against each prior version in ascending order.

`RegisterEventType` checks run in this order:
1. grammar;
2. context segment;
3. category;
4. classification;
5. owner and attribute conflict.

Categories are `domain`, `integration` and `command`. Classifications are `public`, `internal`, `confidential`,
`restricted`, `personal`, `sensitive-personal`, or `regulated(<regime>)`.
`digest` = `"sha256:" + hex(sha256(JCS(schema)))` **[E3]**. Schemas are integer-only JSON, as in
contracts/context-runtime/semantics.md §1.

## 3. Event schema profile [E4]

A registered payload schema is a JSON Schema 2020-12 document restricted to this profile, so that compatibility is
decidable and identical in every implementation:

- **Keywords:** `type` (a string or an array of `object`, `array`, `string`, `integer`, `number`, `boolean` and
  `null`), `properties`, `required`, `additionalProperties` (boolean or a profile schema), `items` (a profile
  schema), `enum`, `const`, `minLength`, `maxLength`, `pattern`, `format`, `minimum`, `maximum`, `minItems`,
  `maxItems`.
- **Annotations, ignored by compatibility:** `$schema`, `$id`, `title`, `description`, `examples`, `default`,
  `deprecated`, and every key starting with `x-`.
- **Anything else is refused** with `E-EVT-SCHEMA-PROFILE`. That includes `$ref`, `oneOf`, `anyOf`, `allOf`,
  `not`, `if`, `patternProperties` and `dependentSchemas`. The schemas `true` and `{}` mean "anything".

## 4. Compatibility [E5]

`accepts(R, W)` holds when every instance valid under writer schema W is valid under reader schema R. It is checked
structurally, and the rules are sufficient conditions: anything not proven compatible is incompatible.

1. If R is "anything", the result is true. If W is "anything" and R is not, the result is false.
2. **Types.** Each schema's type set is the set given, or every type when `type` is absent. `integer` is a subtype
   of `number`. Every writer type must be accepted by some reader type.
3. **`enum` / `const`.** If R has either, W must have either, and W's values must be a subset of R's values
   (compared as JSON). If R has neither, W's enum and const are unrestricted.
4. **Strings.** R `minLength` ≤ W `minLength` (absent = 0). R `maxLength` ≥ W `maxLength` (absent = ∞). If R has a
   `pattern`, W must have the same pattern. If R has a `format`, W must have the same format.
5. **Numbers.** R `minimum` ≤ W `minimum` and R `maximum` ≥ W `maximum`. An absent bound is unbounded, and an
   unbounded writer side fails a bounded reader.
6. **Arrays.** `accepts(R.items, W.items)` (absent = anything), with `minItems` and `maxItems` checked like lengths.
7. **Objects.** Absent `additionalProperties` means "anything"; `false` means nothing is allowed.
   - R `required` ⊆ W `required`.
   - For each property p in R: if p is in W, `accepts(R.p, W.p)`. Otherwise, if W's `additionalProperties` is
     `false`, there is no constraint. Otherwise `accepts(R.p, W.additionalProperties)`.
   - For each property p in W but not in R: `accepts(R.additionalProperties, W.p)`.
   - If W's `additionalProperties` is not `false`: `accepts(R.additionalProperties, W.additionalProperties)`.
8. **FULL compatibility** between versions A and B means `accepts(A, B)` **and** `accepts(B, A)`.
   **FULL_TRANSITIVE** means FULL against every previously registered version of the type. The reported
   `compatibility` is `"FULL_TRANSITIVE"`, or `"n/a"` for the first version.

When a check fails, `detail` names the prior version and the first failing JSON-pointer path. Implementations must
agree on the error code, not the wording.

## 5. Seed (VR-EVT-01/02)

`tools/evt_seed.py` registers every event type declared in the vendored corpus with its owning context and category
`domain`. It registers schema `1.0.0` from the generated AsyncAPI payloads, with kernel `$ref`s inlined and
annotations kept. The run is idempotent.

### 4.1 What FULL compatibility permits (consequence, not an extra rule)

FULL requires each version to accept every instance of the other, so the two versions validate essentially the
same documents. Within a MAJOR the following are compatible:
- annotation changes;
- reordering `required` or `enum`;
- adding a property whose schema is "anything" to an open object;
- re-expressing a constraint identically.

The following are breaking, both in this profile and in CIC-006-001's terms, and RUL-EVT-1 requires a new `.v(N+1)`
type for them:
- adding a typed property, even an optional one: in an open model, old writers may already have sent the name
  with another type; in a closed model, old readers reject it;
- adding a required property;
- widening or narrowing types, enums or bounds;
- closing an open model.
