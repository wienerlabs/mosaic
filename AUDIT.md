# Audit Log

This file records the audit history of the Mosaic codebase. New entries are
appended in reverse chronological order.

---

## 2026-04-19 — Phase 1 bootstrap (no audit)

| Field | Value |
|---|---|
| Auditor | None |
| Scope | All crates |
| Commit | `89e98fe` (initial bootstrap) |
| Findings | N/A — codebase is too young to audit |
| Status | **Not audited.** Do not use in production. |

The Phase 1 release ships a working Groth16 verifier mirroring the
algorithm of Light Protocol's `groth16-solana` but as a cleanroom
implementation. No external audit has been commissioned.

We plan to commission an audit when Phase 1 freezes (target Q3 2026) and
the snarkjs / arkworks adapter pipeline is exercised against production
fixtures.

---

## Audit roadmap

| Milestone | Target | Status |
|---|---|---|
| Internal review of `mosaic-core` trait surface | Phase 1 freeze | Pending |
| External audit of `mosaic-groth16` + reference program | Phase 2 release | Pending |
| External audit of `mosaic-plonk` | Phase 2 freeze | Pending |
| External audit of `mosaic-stark` + chunked-upload | Phase 3 release | Pending |
| Recurring audit (annual) | Post-1.0.0 | Pending |

---

## Reporting issues

Vulnerability reports should follow the [SECURITY.md](SECURITY.md) policy.
Audit findings — once we have audits — will be tracked in this file with
a fix commit reference.

---

## Format

Each audit entry follows this template:

```markdown
## YYYY-MM-DD — Auditor name

| Field | Value |
|---|---|
| Auditor | <firm or individual> |
| Scope | <crates and commit range> |
| Commit | `<sha>` |
| Findings | <link to report or short summary> |
| Status | <Closed / Mitigated / Open> |
```

Findings that are *fixed* in a follow-up commit must reference the fix
commit SHA. Findings that are *accepted-as-risk* must include a written
justification.
