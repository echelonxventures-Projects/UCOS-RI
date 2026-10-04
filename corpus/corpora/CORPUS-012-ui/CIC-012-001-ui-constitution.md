---
id: CIC-012-001
title: UI Constitution — Metadata-Driven Rendering
version: 1.0.0
status: normative
authority: Chief Product Architect
corpus: CORPUS-012
dependencies: [CIC-005-001, CIC-011-002, CIC-014-001, CIC-027-001, CIC-028-001, CIC-029-001]
traces: [PRIN-004, PRIN-009, PRIN-014, PRIN-016, PRIN-021]
certification: [CR-012-001-01, CR-012-001-02, CR-012-001-03, CR-012-001-04, CR-012-001-05]
validation: [VR-012-001-01, VR-012-001-02]
---

# CIC-012-001 — UI Constitution

## 1. Principle

UCOS user interfaces are **rendered from metadata**, never hand-built per commercial type (PRIN-004,
PRIN-016). A new TypeDefinition, facet, attribute, lifecycle transition, or policy becomes usable in
every UCOS surface (back-office console, partner portal, self-service) without UI code changes.
Channels (web storefronts, apps, kiosks, voice, AI agents) are **consumers of APIs**, not part of the
substrate; UCOS ships the UI SDK they may use (CIC-027-001 §1).

## 2. UI metadata model (`ucos.ui` registry, delivered in packs)

| Element | Definition | Source of truth |
|---------|------------|-----------------|
| **ViewDefinition** | `{urn, subject: typeRef \| aggregateKind, viewKind: detail\|edit\|create\|list\|card\|compare\|wizard, layout: Section[], scope: ApplicabilityScope}` | Pack / tenant metadata |
| **Section** | `{code, label: LocalizedText, fields: FieldRef[], visibleWhen: CEL, collapsible, order}` | Pack |
| **FieldRef** | `{attribute \| relationship \| computed, widget?: WidgetRef, readOnlyWhen: CEL, helpKey}` | Pack |
| **WidgetRef** | Registered widget for a datatype or attribute (`money-input`, `quantity-input`, `localized-text-editor`, `scope-editor`, `cel-editor`, `relationship-picker`, `geo-shape-map`, plugin I3 widgets) | Widget registry |
| **ActionBinding** | Lifecycle transitions and commands rendered as actions: label from transition, enabled state from `GET …/allowed-actions` (server-evaluated guard + PDP) | Lifecycle model |

**Derivation when no ViewDefinition exists** (default views, deterministic):
1. Sections = facets in linearized type order (CIC-029-001), one section per facet plus "General" for type-own attributes.
2. Field order = AttributeBinding `displayOrder`, then attribute code.
3. Widget = registry default by datatype; `enum` → select; `localized-text` → localized editor; `money` → money input with currency from context.
4. Contextualizable attributes render a scope-aware editor (base value + scoped overrides table).
5. Actions = transitions from the current state whose `allowed-actions` result is `allow`.

ViewDefinitions resolve through CIC-011-001 (fact kind `ui-view`, conflict `merge`) so tenants,
channels, roles, and locales can refine layouts without forking.

## 3. Server contract for UIs

Every bounded context exposes, for each aggregate kind:
- `GET /v1/{context}/{resource}/{id}/allowed-actions` → `[{transition|command, allowed, reasons[], requires[]}]` (evaluated with the caller's principal; never computed client-side).
- `GET /v1/ui/views:resolve?subject=&viewKind=` → resolved ViewDefinition (UI service in the `extension` context, read-only over packs).
- Field-level redaction obligations (CIC-009-001) are applied server-side; the UI receives `"_redacted": ["fieldCode"]` and renders a placeholder, never the value.

## 4. Rendering architecture

- UI SDK: framework-agnostic Web Components (`<ucos-view>`, `<ucos-field>`, `<ucos-action-bar>`, `<ucos-scope-editor>`) plus React bindings; design tokens via CSS custom properties; theming per tenant.
- Back-office console = shell (navigation, search, notifications, tasks) + metadata-rendered views; shell navigation itself is metadata (menu entries per installed pack and role).
- Plugins contribute I3 widgets and sections (CIC-028-001) inside sandboxed iframes communicating via a typed postMessage protocol (`ucos-ui-bridge/1`).
- Strict CSP, Trusted Types, no `eval`, Subresource Integrity on all assets.

## 5. Localization and formatting

All visible strings come from `LocalizedText` or message keys resolved by CIC-011-002; numbers,
money, dates, units are formatted with CLDR via `Intl`; RTL layouts are supported by logical CSS
properties only (no `left/right` in component CSS — lint rule `UCOS-L101`).

## 6. Accessibility

WCAG 2.2 Level AA is mandatory for every UI SDK component and every derived view: keyboard
operability, focus management on dialogs, visible focus, accessible names from attribute labels,
error identification linked to fields (`aria-describedby`), contrast ≥ 4.5:1 via tokens, reduced
motion support.

## 7. Performance budgets

Console: LCP ≤ 2.5 s, INP ≤ 200 ms, CLS ≤ 0.1 at p75 on mid-tier devices; JS ≤ 250 KB gzip initial
route; views render from a single batched resolve call (view + data + allowed-actions) — no
waterfalls beyond 2 round trips.

## 8. Certification Rules

- **CR-012-001-01** Every concrete type in `ucos.std` renders default detail/edit/create views with zero type-specific code (snapshot test generated from the pack).
- **CR-012-001-02** axe-core reports zero WCAG 2.2 A/AA violations on every UI SDK component story and on derived views for all `ucos.std` types.
- **CR-012-001-03** Pseudo-localization (`en-XA`, `ar-XB`) renders without truncation defects or untranslated literals (extends CR-011-002-02).
- **CR-012-001-04** Action enablement equals server `allowed-actions` in 100 % of lifecycle conformance scenarios (no client-side guard logic).
- **CR-012-001-05** Core Web Vitals budgets (§7) met in the L2 performance profile.

## 9. Validation Rules

- **VR-012-001-01** Every ViewDefinition references existing attributes/relationships of its subject's effective schema.
- **VR-012-001-02** Every widget referenced is registered for the field's datatype.
