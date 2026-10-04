---
id: CIC-028-001
title: Plugin Constitution
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-028
dependencies: [CIC-000-004, CIC-014-001, CIC-015-001, CIC-021-001, CIC-027-001]
traces: [PRIN-013, PRIN-012, PRIN-022, PRIN-010, DOM-EXT, DOM-CUS]
certification: [CR-028-001-01, CR-028-001-02, CR-028-001-03, CR-028-001-04, CR-028-001-05]
validation: [VR-028-001-01, VR-028-001-02, VR-028-001-03]
---

# CIC-028-001 — Plugin Constitution

## 1. Plugin kinds and isolation

| Kind | Examples | Contract | Isolation model |
|------|----------|----------|-----------------|
| `cel-library` | Domain functions for CEL (geo distance, checksum validators) | Pure functions with cost annotations | **I1** WASM sandbox in-process (no I/O, fuel-metered, memory ≤ 16 MB) |
| `price-model` | Actuarial rating, telecom rating formulas | `PriceModelPort.evaluate` (pure) | I1 |
| `constraint-solver` | CP/SAT configurators | `ConfiguratorPort` | I1 or I2 |
| `port-adapter` | DB, bus, search, graph, KMS adapters | Port interfaces (CIC-021-001 §1) | **I0** linked at build into composition root (certified, platform-owned) |
| `provider-adapter` | PSPs, tax engines, e-signature, e-invoicing, carriers, IdPs, KYC | Provider ports (PaymentProviderPort, TaxEnginePort, …) | **I2** out-of-process sidecar/remote over gRPC with mTLS; egress via proxy allow-list |
| `effect-dispatcher` | Lifecycle effect kinds, obligation handlers | `EffectDispatcherPort` | I2 |
| `value-source` | External segmentation, dimension value sources | `ValueSourcePort` | I2 |
| `ui-renderer` | Custom attribute widgets, page sections | UI SDK component contract | **I3** browser sandbox (iframe/Shadow DOM, CSP, postMessage API) |
| `bounded-context` | Industry contexts (e.g. underwriting, network provisioning) | Full context per CIC-002-001 (own APIs/events/DB) | **I4** separate deployment in the cell, own schema, consumes/produces via published ports only |

No plugin kind may write another context's storage, bypass the PDP, or receive raw personal data
without a declared purpose grant.

## 2. Plugin manifest (`ucos-plugin.yaml`)

```yaml
apiVersion: ucos.dev/plugin/v1
id: com.vendor.tax-engine           # reverse-DNS, unique in registry
version: 2.3.1
kind: provider-adapter
publisher: urn:ucos:global:org:<verified organization>
implements: [{port: TaxEnginePort, versions: ">=1.2 <2.0"}]
compatibility: {ucos: ">=1.4 <2.0", requiredPacks: ["ucos.std@^1.0"]}
artifacts: [{type: oci, ref: registry.vendor.com/tax-engine@sha256:...}]
isolation: I2
permissions:
  egress: ["api.vendor.com:443"]
  ucosApis: [{api: "ucos.party.v1/GetParty", purpose: "tax-determination", fields: ["addresses.billing"]}]
  events:   {consume: [], produce: []}
  secrets:  ["vendor-api-key"]
resources: {cpu: "500m", memory: "512Mi", maxConcurrency: 200, timeoutMs: 800}
configSchema: {...JSON Schema for tenant configuration...}
dataClassification: {receives: confidential, stores: none}
contributes:                            # metadata contributed on activation (governed)
  kinds: [], factKinds: [], effectKinds: [], reasonCodes: ["R-TAX-..."], policies: [], types: []
signatures: [{sigstore bundle}]
```

## 3. Lifecycle

```
submitted → scanned (SBOM, vuln, license, malware, manifest lint)
          → certified (L1: conformance suite of implemented ports; L2: + perf & security for I2/I4)
          → listed (registry, visible to tenants per publisher policy)
          → activated per tenant (ChangeSet: configuration + permission grant review)
          → suspended | revoked (certification revoked or security event → deactivation ≤ 5 min, CR-000-004-03)
          → deprecated → removed
```

Activation is per tenant (and optionally per context scope, e.g. tax plugin only for market=BR).
Multiple plugins for the same port are selected by policy (e.g. `payment.routing`, `tax.engine-selection`).

## 4. Runtime contract for I2 plugins

- gRPC with deadlines from caller; plugin must be idempotent for retried calls carrying the same `ucos-idempotency-key`.
- Health: `grpc.health.v1`; circuit breaker per tenant-plugin pair; fallback behavior declared by the calling domain (e.g. tax fallback = fail closed).
- Telemetry: plugin spans join the caller trace; plugin logs pass through the cell collector redaction.
- Data minimization: UCOS sends only fields declared in `permissions.ucosApis[].fields` for the declared purpose.

## 5. Customization boundaries (DOM-CUS)

Tenants customize through, in order of preference: (1) metadata (types, attributes, policies, rules,
lifecycles, catalogs) → (2) configuration of activated plugins → (3) tenant-private plugins
(certified at L1 in a tenant sandbox, I1–I3 only) → (4) bounded-context plugins (I4) for genuinely new
capabilities. Forking platform code is never a customization path.

## 6. Certification Rules

- **CR-028-001-01** Every listed plugin has a valid CertificationRecord for its digest at the level required by its isolation model (I1/I3: L1; I2/I4: L2).
- **CR-028-001-02** Sandbox escape tests (I1 WASM: I/O imports, fuel exhaustion, memory limits; I3: DOM/cookie/network access) all contained.
- **CR-028-001-03** Permission enforcement: an I2 plugin calling an undeclared UCOS API or egress host is blocked and reported.
- **CR-028-001-04** Revocation deactivates the plugin in all tenants within 5 minutes and callers apply declared fallbacks.
- **CR-028-001-05** Plugin cannot be activated without a ChangeSet approved by the tenant's governance plan.

## 7. Validation Rules

- **VR-028-001-01** Every manifest validates against the plugin manifest schema and declares isolation consistent with its kind (§1).
- **VR-028-001-02** Every `implements.port` names a port defined in the corpus.
- **VR-028-001-03** Every contributed reason code, fact kind, and effect kind is unique across the registry.
