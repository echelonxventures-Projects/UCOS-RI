---
id: CIC-011-003
title: Resolution Caching Strategy
version: 1.0.0
status: normative
authority: Chief Platform Architect
corpus: CORPUS-011
dependencies: [CIC-011-001]
traces: [PRIN-006, PRIN-015, DOM-RTM]
certification: [CR-011-003-01, CR-011-003-02, CR-011-003-03]
validation: [VR-011-003-01]
---

# CIC-011-003 — Resolution Caching Strategy

## 1. Cache tiers

| Tier | Location | Contents | Invalidation | Bound |
|------|----------|----------|--------------|-------|
| T0 | In-process, per request | Assembled ContextVector, schema handles | Request end | — |
| T1 | In-process LRU (Caffeine/W-TinyLFU) | Resolution results, compiled policies, effective schemas | Version-keyed (§2) + event invalidation | 256 MB default |
| T2 | Regional shared cache (`CachePort`, Redis protocol) | Resolution results, candidate sets | Version-keyed + TTL | Per tenant quota |
| T3 | Edge/CDN | Public, non-personal views (catalog pages, public prices) | Surrogate keys purged on events | — |

## 2. Version-keyed correctness

Every cacheable resolution key includes `storeVersion(subject)` — a monotonic counter per
`(tenant, factKind, subject)` maintained by the owning service and published in every fact-change
event (`ucosversion` extension, CIC-006-001). Consumers maintain a **version map** (T1, compacted
from the event stream). A cached entry is valid iff its embedded version equals the version map entry.
Therefore a stale read is bounded by event propagation latency (SLO p99 1 s), never by TTL.

Metadata (pinned URNs) is immutable → infinite TTL.

## 3. Personal-context rule

Results whose context contains a dimension with `sensitivity ≥ personal` MUST NOT be stored in T2/T3
under a key containing the raw value; the key uses the contextDigest (salted per tenant, salt rotated
every 24 h). T3 MUST NOT store any result whose context includes personal dimensions.

## 4. Stampede and negative caching

- Request coalescing (single-flight) per key in T1 and T2 (lock key TTL 2 s).
- Negative results (`NotFound`) cached with the same version key, max 60 s TTL.
- Probabilistic early refresh (XFetch, β = 1.0) for TTL-bounded tiers.

## 5. Degradation

If the version map lags (consumer lag > 5 s), resolvers switch the affected tenant to
**bypass-T2 mode** and emit `ucos_cache_bypass_active{tenant}`; regulated fact kinds (tax, policy)
always bypass when lag > 1 s.

## 6. Certification Rules

- **CR-011-003-01** Fault-injection test: after a fact write, no resolution served later than (event-propagation-time + 50 ms) returns the pre-write value.
- **CR-011-003-02** Cache key scan: no T2/T3 key contains a raw personal dimension value.
- **CR-011-003-03** Cache hit ratio for catalog/price view resolution ≥ 90 % in the L2 load profile.

## 7. Validation Rules

- **VR-011-003-01** Every fact-change event schema declares the `ucosversion` extension.
