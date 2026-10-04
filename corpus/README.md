# UCOS-COM Ω∞ — Complete Implementation Corpus (CIC)

The authoritative engineering source of truth for the Universal Commerce Operating Substrate.

## Layout

```
corpus.yaml                     Manifest: every corpus, every artifact, status, dependency order
schemas/                        JSON Schemas for artifact headers and domain specifications
corpora/CORPUS-NNN-<slug>/      Normative artifacts (Markdown + YAML front matter)
corpora/CORPUS-002-domain/domains/
    registry.yaml               Every constitutional domain: code, bounded context, owner, tier, status
    DOM-<CODE>.yaml             Full 25-section domain specification
packs/ucos.std/                 Normative standard Type Pack (CIC-029-001): attributes, facets, types,
                                relationship types, lifecycles, context dimensions, registries, policies, fixtures
tools/validate.py               Corpus validator (headers, dependencies, traceability, domain completeness)
amendments/AMD-NNNN-*.md        Amendment records (CIC-000-001 §5): decision, rationale, affected artifacts, impact
tools/pack_checks.py            Static Type Pack checks (references, C3 linearization, lifecycle soundness,
                                dimensions, policy test vectors, fixture instances vs effective schemas)
```

## Status (corpus 1.1.0)

| Measure | Value |
|---------|-------|
| Corpora with normative artifacts | 31 / 31 |
| Domains covered | 117 / 117 — 99 fully specified (25 sections), 5 realized by the `ucos.std` pack, 13 subsumed by a parent spec (declared under `subsumes`) |
| Tiers | kernel 39/39, core 64/64, pack 5/5, extension 9/9 (extension domains ship as I4 bounded-context plugins, `plugin:` block) |
| Rules | 763 certification/validation rules, each defined once and traced |
| `ucos.std` pack | 26 types, 72 attributes, 18 facets, 15 relationship types, 9 lifecycle models, 21 context dimensions, 204 policies (195 referenced by specs), 30 ports, 24 fixture instances |
| Amendments | AMD-0001 (1.1.0): the reference implementation is language- and toolchain-agnostic, contract-first and polyglot, with container-only builds |
| Executable checks | CEL policy test vectors executed by the validator (with `cel-python`) |

Domain registry statuses: `specified` (DOM file), `realized` (pack-tier, realized by a pack), `subsumed`
(covered by a parent spec in the same bounded context, which lists it under `subsumes` with coverage).

## Reading order

Follow the corpora in dependency order (`corpus.yaml` → `order`). CORPUS-000 defines the terms
"normative", "MUST", artifact identity, and the certification model used by every other corpus.

## Validating

```
pip install -r tools/requirements.txt  # pyyaml, jsonschema, cel-python (CEL policy vectors are skipped without it)
python3 tools/validate.py            # full validation, non-zero exit on any violation
python3 tools/validate.py --coverage # coverage report: which corpora/domains are specified
```

The validator is the gate defined in `CIC-000-004` (CR-000-004-01): no artifact is normative unless it validates.
It also validates every pack under `packs/`; a pack defect fails the corpus. CI runs it on every push
(`.github/workflows/validate.yml`).

The reference implementation is the private repository `UCOS-RI` (CIC-030-001 §5), which vendors this corpus at a release tag.
