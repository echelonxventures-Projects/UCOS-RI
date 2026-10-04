---
id: CIC-000-003
title: Artifact, Traceability, and Versioning Standard
version: 1.0.0
status: normative
authority: UCOS Constitutional Authority
corpus: CORPUS-000
dependencies: [CIC-000-001, CIC-000-002]
traces: [PRIN-011, PRIN-012]
certification: [CR-000-003-01]
validation: [VR-000-003-01, VR-000-003-02, VR-000-003-03, VR-000-003-04]
---

# CIC-000-003 — Artifact, Traceability, and Versioning Standard

## 1. Artifact header (mandatory)

Every Markdown artifact begins with YAML front matter validated by `schemas/artifact-header.schema.json`:

| Field | Type | Meaning |
|-------|------|---------|
| `id` | Artifact ID | Canonical identifier (CIC-000-002) |
| `title` | string | Human title |
| `version` | semver | Artifact version (§4) |
| `status` | `draft \| normative \| informative \| deprecated \| superseded` | Binding force |
| `authority` | string | Role that owns and approves the artifact |
| `corpus` | `CORPUS-NNN` | Containing corpus |
| `dependencies` | Artifact ID[] | Artifacts whose definitions this one relies on; MUST be acyclic |
| `traces` | ID[] | Upward traceability: principles, domains, artifacts this one realizes |
| `certification` | CR ID[] | Certification rules defined in this artifact |
| `validation` | VR ID[] | Validation rules defined in this artifact |

Domain specifications (`DOM-*.yaml`) carry the same fields under a top-level `header:` key.

## 2. Traceability model

```
PRIN-nnn ──realized-by──▶ CIC-xxx-yyy ──specifies──▶ DOM-CODE ──implemented-by──▶ module
                                     └──defines──▶ CR/VR ──verified-by──▶ test case ──evidence──▶ CertificationRecord
```

- Downward links are derived (reverse index of `traces`); they are never hand-maintained.
- Implementation modules declare `ucos.traces` in their build manifest (CIC-001-001 §6).
- Test cases declare `@Verifies("CR-…")` (or language equivalent); the certification pipeline joins them.

## 3. Rule definitions

A rule ID listed in `certification`/`validation` MUST be defined in the artifact body as a bullet
starting `- **<RULE-ID>**`. Each rule MUST be mechanically checkable (test, static analysis, schema
validation, or metric threshold). Rules phrased as aspirations are invalid.

## 4. Versioning (applies to artifacts, metadata definitions, APIs, events, packs)

| Change | Bump |
|--------|------|
| Removes or renames an element, tightens a constraint, changes semantics | MAJOR |
| Adds optional element, adds enum value consumers must tolerate, loosens constraint | MINOR |
| Editorial, clarification without semantic change | PATCH |

- MAJOR versions coexist: the previous MAJOR remains supported for the deprecation window defined in
  CIC-024 (default 12 months for APIs/events, indefinite read support for persisted metadata).
- `superseded` artifacts name their successor in `supersededBy`.

## 5. Certification Rules

- **CR-000-003-01** CI fails if `tools/validate.py` exits non-zero on the corpus revision being released.

## 6. Validation Rules

- **VR-000-003-01** Every artifact header validates against `schemas/artifact-header.schema.json`.
- **VR-000-003-02** Every ID in `dependencies` resolves to an existing artifact; the dependency graph is acyclic.
- **VR-000-003-03** Every ID in `traces` resolves to a principle, domain, or artifact.
- **VR-000-003-04** Every rule ID in `certification`/`validation` is defined in the body (§3) and no rule ID is defined twice in the corpus.
