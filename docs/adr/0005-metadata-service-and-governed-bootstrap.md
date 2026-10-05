# ADR 0005: S1 metadata service, governed definitions, and the bootstrap rule

- Status: accepted (2026-10-05)
- Traces: CIC-015-001, CIC-029-001 §3, DOM-ONT/LFC/CTX/POL/GOV/EVD/META, CIC-030-001 §2–3, PRIN-011

## Decisions

1. **One deployable, seven contexts.** `kernel/` composes ontology, lifecycle, context (dimensions), policy
   (PDP), governance, evidence and registry (DOM-META) into `metadata-service` for `ucos-lite`.
   - Each context keeps its own schema: `ucos_ontology`, which DOM-META shares per its spec, plus `ucos_lifecycle`,
     `ucos_context`, `ucos_policy`, `ucos_governance` and `ucos_evidence`.
   - Each context has its own definitions table, events and outbox.
   - Contexts interact only through the ports in `kernel/governed` (Owner, Gate, Decider, Evidence), wired in
     `cmd/`. `arch_test.go` enforces this (CR-001-001-01).
   - In `ucos-cell` the same ports become HTTP calls with no domain change.
2. **One governed path.** Every governed definition kind has an Owner that drafts, validates against a view, and
   publishes. The view is the published definitions plus the drafts of the ChangeSet under review.
   - Publish succeeds only when the governance Gate confirms the URN belongs to a ChangeSet that is `applying`.
     This holds for direct calls to `…:publish` as well as for the in-process saga (CR-015-001-01).
   - `InstallPack` drafts every pack definition in its owning context. It then opens one ChangeSet whose items
     reference those drafts and submits it (CIC-029-001 §3 rule 3). Installation is all-or-nothing: on failure
     the drafts are removed and the ChangeSet is cancelled.
3. **Bootstrap rule.** A tenant's first pack installation must be classified and planned by
   `governance.risk-classification`, `governance.approval` and `governance.freeze-windows`. Those policies are
   inside the pack being installed. When no published policy of that name exists, the PDP uses the draft
   carried by the ChangeSet under evaluation. Two consequences:
   - The policies govern their own installation; for `ucos.std` that means `critical`, two stages, and 24 h cool-off.
   - There is no hidden kernel default that a tenant cannot see. The evidence kinds `approval`, `attestation` and
     `decision-snapshot` are kernel seeds, because approvals happen before the pack's registry entries exist.
4. **Content addressing.**
   - Pack bundles are verified by sha256 over the exact bytes received (OCI-style), because pack policies contain
     non-integer numbers that JCS cannot canonicalize portably.
   - Definition digests and ChangeSet content digests use canonical JSON.
5. **Lite-only test ports** live on the internal admin address, which is never published, and are refused
   unless enabled by environment variable:
   - an adjustable ClockPort (`UCOS_CLOCK=adjustable`) for cool-off and freeze windows;
   - apply-saga fault injection (`UCOS_FAULTS=enabled`) for CR-015-001-04.

## Known limitations (tracked for later slices)
- Definition references resolve by short name within the tenant view. Cross-namespace references with version
  ranges arrive with a second pack.
- ChangeSets support `publish` only. `revise`, `deprecate`, `retire`, `activate` and `deactivate` arrive with
  upgrades (CIC-026-001).
- Uninstall is a direct, assurance-checked, evidenced operation. A governed uninstall ChangeSet comes with pack
  upgrades.
- Impact analysis reports zeros for pinned instances and behavioural simulation until COB (S3) and recorded
  decisions exist. The zeros are stated in the report rather than omitted.
- Bundle signatures (cosign) and ledger checkpoint signing and anchoring arrive with the platform signing key (S6).
- The PDP evaluates a single published policy per name. Layered combination across platform, tenant and
  organization arrives with tenant overrides (S2).
