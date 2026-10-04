---
id: CIC-027-001
title: SDK Constitution
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-027
dependencies: [CIC-005-001, CIC-006-001, CIC-011-001, CIC-000-002, CIC-001-001]
traces: [PRIN-009, PRIN-004, PRIN-013, PRIN-022]
certification: [CR-027-001-01, CR-027-001-02, CR-027-001-03, CR-027-001-04]
validation: [VR-027-001-01, VR-027-001-02]
---

# CIC-027-001 — SDK Constitution

## 1. SDK family

| SDK | Languages (tier 1) | Purpose |
|-----|--------------------|---------|
| Client SDK | TypeScript, Kotlin/Java, Python, Go | Call UCOS APIs from applications, channels, partner systems |
| Consumer SDK | Same | Consume UCOS events (Kafka-protocol or webhooks) with envelope parsing, idempotency, gap handling |
| Metadata SDK | TypeScript, Kotlin, Python | Author/validate packs offline (types, policies, lifecycles), run CEL locally, compile and test |
| Plugin SDK | Kotlin/Java, Go, Rust (WASM), TypeScript | Build plugins against CORPUS-028 contracts |
| UI SDK | TypeScript (Web Components + React bindings) | Metadata-driven rendering (CORPUS-012) |

Tier-2 languages (C#, Swift, Ruby, PHP) are generated with the same generator and must pass the
same conformance suite to be published.

## 2. Generation

- Typed clients and models are **generated** from the published OpenAPI 3.1, protobuf, and AsyncAPI
  contracts (CORPUS-005/006) by the UCOS generator (`tools/sdkgen`, templates per language). Hand
  edits to generated code are forbidden; extensions live in hand-written `ext` packages layered on top.
- SDK version = `<contract-bundle MAJOR>.<generator MINOR+contract MINOR>.<patch>`; the SDK records the
  contract bundle digest it was generated from (`sdk.contractDigest`).
- One package per bounded context plus a meta-package (`@ucos/sdk`), so applications import only what they use.

## 3. Mandatory runtime behaviors (hand-written core, identical semantics across languages)

| Behavior | Requirement |
|----------|-------------|
| Auth | OAuth 2.1 client credentials, auth code + PKCE helpers, DPoP proof generation, token caching/refresh, token exchange for agents |
| Context | `ContextBuilder` producing canonical `UCOS-Context` (CIC-011-001 §6); helpers for asOf |
| Idempotency | Auto-generate ULID `Idempotency-Key` per logical operation; reuse across retries |
| Concurrency | ETag tracking per aggregate; `If-Match` on mutations; typed `ConflictError` with latest revision fetch helper |
| Retries | Only for idempotent or idempotency-keyed operations; exponential backoff with full jitter; honor `Retry-After`; retry budget |
| Pagination | Async iterators over cursor pages |
| Errors | RFC 9457 problems mapped to typed errors by `code`; localized message lookup optional |
| Money/Quantity | Decimal-safe `Money` and `Quantity` types (no floats), arithmetic with explicit rounding modes, currency minor units from registry |
| Time | Instant/ZoneId types; no naive datetimes |
| Telemetry | OpenTelemetry instrumentation (spans per call, `traceparent` propagation), opt-in |
| Deprecation | Surface `Deprecation`/`Sunset` headers as warnings |

## 4. Dynamic (metadata-typed) objects

Because types are data (PRIN-004), SDKs expose CommercialObjects both as:
1. **Dynamic views**: `obj.get<T>("attributeCode")` validated at runtime against the EffectiveSchema fetched and cached by pinned URN.
2. **Generated typed facades** (optional, build-time): `ucos-sdkgen types --pack com.acme.telco@1.2.0` generates language types (e.g. `MobilePlan` with typed accessors) from pack TypeDefinitions. Facades are thin wrappers over dynamic views and never bypass server validation.

## 5. Consumer SDK

Provides: CloudEvents parsing (binary + structured), schema validation by `dataschema`, per-aggregate
ordering helpers (`ucossequence` gap detection with replay fetch via DOM-EVT API), idempotent handler
wrapper with pluggable dedupe store, webhook signature verification, DLQ hooks.

## 6. Compatibility and support

- Supported SDK MAJOR lines track supported API MAJOR lines (≥ 12 months after successor GA).
- Minimum runtime versions: Node 20 LTS, JVM 17, Python 3.11, Go 1.22.
- Breaking SDK surface changes only with SDK MAJOR; deprecations annotated ≥ 2 MINOR releases ahead.

## 7. Certification Rules

- **CR-027-001-01** SDK conformance suite (same scenarios for every language: auth, context, idempotent retry, ETag conflict, pagination, error mapping, money arithmetic, event consumption with duplicates and gaps) passes 100 % before publication.
- **CR-027-001-02** Money/Quantity property tests: no precision loss across 10⁶ random operations; round-trip JSON preserves values exactly.
- **CR-027-001-03** Generated code is reproducible: regenerating from the recorded contract digest yields byte-identical sources.
- **CR-027-001-04** Published packages are signed (npm provenance, Sigstore for Maven/PyPI/Go modules) with SBOM.

## 8. Validation Rules

- **VR-027-001-01** Every operation in published contracts has a generated client method in every tier-1 SDK.
- **VR-027-001-02** Every error code registered in the corpus maps to a typed error class (or the generic problem class with code constant).
