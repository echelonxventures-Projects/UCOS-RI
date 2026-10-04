# ADR 0002 — First module language: Go (echo-service, S0)

- Status: accepted (2026-10-05)
- Traces: CIC-001-001 §1.1 rule 3, CIC-030-001 §3 (S0)

## Context
S0 needs one running implementation to demonstrate the platform mechanisms end to end. The language is a
per-module choice, and no language is privileged.

## Decision
`domains/echo` is written in Go 1.25:
- It produces a small static binary on a distroless runtime image.
- Its standard library covers HTTP, JSON and crypto.
- It has one third-party dependency, `pgx` (MIT).

The layering of CIC-001-001 §3 maps to Go packages `api`, `domain`, `application`, `infrastructure` and
`service`, plus `cmd/` as the composition root. `arch_test.go` enforces the layering (CR-001-001-01).

## Consequences
Later modules may use other languages. The S1 replaceability proof (CR-030-001-05) requires at least one
S1 module in a second language.
