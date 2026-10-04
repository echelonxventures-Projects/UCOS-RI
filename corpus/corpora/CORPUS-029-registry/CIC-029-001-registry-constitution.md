---
id: CIC-029-001
title: Registry Constitution and Type Pack Standard
version: 1.0.0
status: normative
authority: Chief Data Architect
corpus: CORPUS-029
dependencies: [CIC-000-002, CIC-000-003, CIC-002-001, CIC-007-001, CIC-015-001, CIC-028-001]
traces: [PRIN-001, PRIN-002, PRIN-004, PRIN-013, PRIN-019, DOM-META, DOM-EXT]
certification: [CR-029-001-01, CR-029-001-02, CR-029-001-03, CR-029-001-04]
validation: [VR-029-001-01, VR-029-001-02, VR-029-001-03]
---

# CIC-029-001 — Registry Constitution and Type Pack Standard

## 1. Registries

UCOS has exactly one registry per kind of shared identifier (PRIN-001). All are served by the
registry service (DOM-META) with read APIs `GET /v1/registry/{registry}` and are populated only by
governed pack/plugin activation or kernel seeds.

| Registry | Key | Owner domain |
|----------|-----|--------------|
| Namespaces | reverse-DNS namespace → owning Organization | DOM-ONT |
| Kinds | URN kind (CIC-000-002 §4) | DOM-META |
| Datatypes | datatype code | DOM-ONT |
| Context dimensions | dimension code | DOM-CTX |
| Fact kinds | fact kind code → owning context, resolution policy | DOM-CTX |
| Effect kinds / requirement kinds | code → dispatcher | DOM-LFC |
| Event types | type → owning context, schemas | DOM-EVT |
| Error codes | `E-<DOM>-<NAME>` → problem type, message key | DOM-META |
| Reason codes | `R-<DOM>-<NAME>` → decision types, message key | DOM-DEC |
| Purposes | privacy purpose code → legal bases | DOM-PRI |
| Meters | meter code → unit, aggregation | DOM-ENT |
| Units | UCUM codes + tenant custom units | DOM-ONT |
| Currencies | ISO 4217 + registered non-ISO (points, tokens) with minor units | DOM-ACC |
| Ports | port name → interface version | DOM-EXT |
| Packs, Plugins | id@version → manifest, certification | DOM-EXT |

## 2. Type Pack format

A **Type Pack** is a versioned, signed bundle of metadata — never code — delivering a commercial
model, industry vocabulary, or jurisdictional configuration (PRIN-019).

```
<pack-id>/
├── pack.yaml          # manifest: id, version, namespace, dependencies, contents index, compatibility
├── attributes.yaml    # AttributeDefinitions
├── facets.yaml        # FacetDefinitions
├── types.yaml         # TypeDefinitions
├── reltypes.yaml      # RelationshipTypeDefinitions
├── dimensions.yaml    # ContextDimensions
├── lifecycles.yaml    # LifecycleModels
├── registries.yaml    # contributed registry entries (meters, reason codes, purposes, units…)
├── policies/          # Policies with test vectors (one file per policy)
├── rules/             # Rules and RuleSets with test vectors
└── tests/             # scenario fixtures exercising the pack
```

Within a pack, references use short names resolved against the pack namespace (`Product` →
`urn:ucos:<namespace>:type:Product@<pack version>`); cross-pack references use full URNs with
version ranges declared in `pack.yaml.dependencies`.

## 3. Pack rules

1. A pack owns exactly one namespace; it may extend (subtype, add facets to its own types) but never modify definitions of other namespaces.
2. Pack versions follow CIC-000-003 §4; MAJOR pack versions with live tenant instances require registered migrations (CIC-026-001).
3. Installation into a tenant = ChangeSet whose items are the pack's definitions; definitions are published in dependency order (attributes → facets → reltypes → lifecycles → types → dimensions → policies/rules).
4. Uninstall is only possible when no live instance references any pack definition.

## 4. The `ucos.std` pack

`packs/ucos.std/` in this repository is the **normative** standard pack. It contains the commercial
types that realize the pack-tier domains (DOM-PRD, DOM-SVC, DOM-SUB, DOM-MBR, DOM-EXP) and core-tier
structural types (Bundle, Package, Asset, Capability), standard facets, attributes, relationship
types, context dimensions, and lifecycle models. It is validated by `tools/validate.py` (pack checks)
on every corpus revision.

## 5. Certification Rules

- **CR-029-001-01** Every pack passes static checks: references resolve, supertype graph acyclic, attribute conflicts absent (RUL-ONT-1), facet requirements satisfied (INV-ONT-3), lifecycle models sound (CIC-007-001 §6).
- **CR-029-001-02** Every pack's `tests/` scenarios pass on the reference implementation with no code changes.
- **CR-029-001-03** Installing then uninstalling a pack in an empty tenant leaves no residual definitions or registry entries.
- **CR-029-001-04** Registry uniqueness: no duplicate keys across all installed packs and plugins.

## 6. Validation Rules

- **VR-029-001-01** `packs/ucos.std` validates with zero errors under the pack checks of `tools/validate.py`.
- **VR-029-001-02** Every pack-tier domain in the registry is realized by ≥ 1 TypeDefinition in `ucos.std` named in its realization map (`pack.yaml.realizes`).
- **VR-029-001-03** Every context dimension listed in CIC-011-001 §1.1 exists in `ucos.std/dimensions.yaml`.
