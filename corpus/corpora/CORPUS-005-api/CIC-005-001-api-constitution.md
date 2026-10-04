---
id: CIC-005-001
title: API Constitution and API Standards
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-005
dependencies: [CIC-000-002, CIC-000-003, CIC-001-001, CIC-011-001]
traces: [PRIN-009, PRIN-010, PRIN-015, PRIN-022]
certification: [CR-005-001-01, CR-005-001-02, CR-005-001-03, CR-005-001-04, CR-005-001-05]
validation: [VR-005-001-01, VR-005-001-02]
---

# CIC-005-001 — API Constitution

## 1. Contract-first

Every API is specified in OpenAPI 3.1 (REST), protobuf 3 (gRPC), or AsyncAPI 3.0 (events) in the
context's `-api` module **before** implementation. Server stubs and SDKs are generated (CORPUS-027).
Contracts are linted with Spectral ruleset `ucos-api-rules` (§10).

## 2. Resource design (REST)

- Base: `https://{region}.api.{tenant-domain}/v{major}/{context}/{resource}`.
- Resources are plural nouns; IDs are ULIDs in the path; full URNs in bodies.
- Standard methods: `GET` collection/item, `POST` create, `PATCH` (JSON Merge Patch, RFC 7396), `PUT`
  full replace only for sub-documents, `DELETE` only where the domain has a delete semantic (most use
  lifecycle transitions instead).
- Custom methods: `POST /{resource}/{id}:{verb}` (e.g. `:publish`, `:transition`, `:price`).
- Long-running operations: `202 Accepted` + `Location: /v1/operations/{id}`; Operation resource
  `{id, state: pending|running|succeeded|failed|cancelled, progress, result|error}`.

## 3. Mandatory headers

| Header | Direction | Rule |
|--------|-----------|------|
| `Authorization: Bearer <JWT>` | req | OAuth 2.1 access token (DPoP-bound for public clients) |
| `UCOS-Tenant` | req | Required unless the token is single-tenant |
| `UCOS-Context` / `UCOS-As-Of` | req | CIC-011-001 §6 |
| `Idempotency-Key` | req | REQUIRED on every POST that creates or has side effects; retained 24 h; replay returns the original response |
| `If-Match` | req | REQUIRED on PATCH/PUT/DELETE and state transitions; value = aggregate revision ETag |
| `traceparent`, `tracestate` | both | W3C Trace Context |
| `ETag` | resp | `"<revision>"` for aggregates; schema digest for metadata |
| `UCOS-Correlation-Id` | resp | ULID, equals event correlation_id for commands |
| `Deprecation`, `Sunset` | resp | RFC 8594 / RFC 9745 when the version is deprecated |
| `RateLimit`, `RateLimit-Policy` | resp | IETF RateLimit headers |

## 4. Query conventions

- Pagination: cursor-based only. `?limit=` (default 50, max 500) and `?cursor=`; response
  `{items: [], nextCursor?: string}`. Offset pagination forbidden.
- Filtering: `?filter=<CEL expression>` over the resource view, server-validated against an allow-list
  of filterable fields; simple equality shortcuts `?field=value` permitted.
- Sorting: `?orderBy=field1 desc,field2`.
- Field selection: `?fields=a,b.c` (sparse fieldsets).
- Expansion: `?expand=relationshipName` max depth 2.

## 5. Representation

- JSON (`application/json`), UTF-8, lowerCamelCase.
- Money: `{"amountMinor": "12345", "currency": "EUR", "scale": 2}` (amount as string to avoid JS precision loss).
- Quantity: `{"value": "1.5", "unit": "kg"}` (decimal string, UCUM).
- Time: RFC 3339 UTC with `Z`; durations ISO 8601.
- LocalizedText in responses: resolved string + `{"_l10n": {"locale": "fr", "fallback": true}}` when `?resolveText=true` (default for view endpoints).
- Enums: lower-kebab strings; clients MUST tolerate unknown values (MINOR additions).

## 6. Versioning and compatibility

- MAJOR in path. Additive changes (new optional fields, new endpoints, new enum values) are MINOR.
- Clients MUST ignore unknown fields; servers MUST NOT require new fields in an existing MAJOR.
- Deprecation window ≥ 12 months after successor GA; `Sunset` header ≥ 6 months before removal.
- Contract diff (oasdiff/buf breaking) gates every PR (CR-005-001-02).

## 7. Errors (RFC 9457 Problem Details)

```json
{
  "type": "https://errors.ucos.dev/pricing/no-price",
  "title": "No applicable price",
  "status": 422,
  "code": "E-PRC-NO-PRICE",
  "detail": "No price entry matched for line 3 in the given context",
  "instance": "/v1/pricing:price#corr=01J9…",
  "correlationId": "01J9…",
  "errors": [{"pointer": "/lines/2", "code": "E-PRC-NO-PRICE", "params": {"objectRef": "urn:…"}}],
  "retryable": false
}
```

Status mapping: validation 400; authN 401; PDP deny 403 (no detail leakage, obligation-controlled);
not found 404 (also used for unauthorized existence-hiding); conflict/revision mismatch 409; precondition
(If-Match) 412; business rule violation 422; rate limit 429; dependency failure 503 with `Retry-After`.
Error codes `E-<DOMAIN>-<NAME>` are registered per domain and localized by message key.

## 8. Security

- Every endpoint declares `x-ucos-permission` and `x-ucos-policy` in the contract; the gateway and the
  service PEP enforce them (CIC-009-001 §5).
- Scopes are coarse (`ucos:<context>:read|write|admin`); fine-grained authorization is PDP.
- No personal data in URLs or query strings.

## 9. Rate limiting and quotas

Token bucket per (tenant, client, route-class); limits are policy `api.rate-limits` scoped by
tenant plan and route class. Commands and queries have separate buckets.

## 10. Lint ruleset `ucos-api-rules` (excerpt, all errors)

`ucos-path-plural`, `ucos-camel-case-properties`, `ucos-no-offset-pagination`, `ucos-idempotency-key-on-post`,
`ucos-if-match-on-mutation`, `ucos-problem-json-errors`, `ucos-money-shape`, `ucos-permission-extension`,
`ucos-no-float-money`, `ucos-operation-id-matches-command`.

## 11. Certification Rules

- **CR-005-001-01** Every contract passes `ucos-api-rules` with zero errors.
- **CR-005-001-02** Breaking-change detector reports zero breaking changes within a MAJOR version.
- **CR-005-001-03** Contract tests (Schemathesis/Pact) show implementation responses conform to the contract for 100 % of operations.
- **CR-005-001-04** Idempotency test: replaying a POST with the same Idempotency-Key 100 times creates exactly one aggregate and returns identical responses.
- **CR-005-001-05** Every operation maps 1:1 to a command or query named in the owning DOM-*.yaml.

## 12. Validation Rules

- **VR-005-001-01** Every `apis` entry in DOM-*.yaml references commands/queries declared in the same file.
- **VR-005-001-02** Every error code referenced in the corpus follows `^E-[A-Z]{2,5}-[A-Z0-9-]+$`.
