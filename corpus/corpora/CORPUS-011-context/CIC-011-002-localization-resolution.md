---
id: CIC-011-002
title: Localization Resolution Algorithm
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-011
dependencies: [CIC-011-001]
traces: [PRIN-014, DOM-LOC]
certification: [CR-011-002-01, CR-011-002-02]
validation: [VR-011-002-01]
---

# CIC-011-002 — Localization Resolution Algorithm

## 1. Localizable values

`LocalizedText = {key?: MessageKey, default: string, values: map<BCP47, string>}` plus optional
`variants: [{scope: ApplicabilityScope, values: map<BCP47,string>}]` for context-specific wording
(e.g. channel-specific short names, jurisdiction-mandated disclosures).

Message templates use ICU MessageFormat 2.0; formatting of numbers, dates, money, units uses CLDR data
pinned per release (CLDR version recorded in the runtime manifest).

## 2. Locale chain

`LocaleChain(ctx)` builds an ordered, de-duplicated list:

1. `ctx.locale` (canonicalized BCP-47, e.g. `zh-Hant-TW`).
2. CLDR parent locales (`zh-Hant-TW → zh-Hant`; explicit CLDR parentLocales override truncation, e.g. `es-MX → es-419 → es`).
3. Tenant-configured fallback locales for `ctx.territory` (policy `localization.territory-fallbacks`), e.g. `CH → [de-CH, fr-CH, it-CH]`.
4. Tenant default locale.
5. `und` (root) → the `default` field.

## 3. Algorithm

```
function ResolveText(lt: LocalizedText, ctx):
    chain ← LocaleChain(ctx)
    if lt.variants non-empty:
        v ← Resolve('localized-variant', lt.id, '-', ctx, cfg{conflict: most-recent})   # CIC-011-001
        if v found:
            for loc in chain: if loc ∈ v.values: return (v.values[loc], loc, v.scope)
    if lt.key: 
        for loc in chain: if TranslationStore.has(lt.key, loc): return (TranslationStore.get(lt.key, loc), loc)
    for loc in chain: if loc ∈ lt.values: return (lt.values[loc], loc)
    return (lt.default, 'und')
```

Response carries `Content-Language` = locale actually served; when served locale ≠ requested, the
response includes `UCOS-Locale-Fallback: <requested>→<served>`.

## 4. Non-text localization

Units: values with `unitDimension` are converted to the unit system of `ctx.territory` (policy
`localization.unit-system`) for display only; stored values remain canonical UCUM.
Currency display: money formatting uses `ctx.locale`; currency conversion is never performed by
localization (pricing concern, CIC-011-004).

## 5. Certification Rules

- **CR-011-002-01** LocaleChain matches the CLDR-derived expected chains for all CLDR locales in the pinned CLDR version.
- **CR-011-002-02** Pseudo-localization test: every UI screen rendered in `en-XA` (accented) and `ar-XB` (RTL) shows no untranslated literal (no string bypassing ResolveText).

## 6. Validation Rules

- **VR-011-002-01** Every LocalizedText in published metadata has a non-empty `default`.
