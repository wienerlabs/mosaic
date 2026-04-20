# Audit Log

This file records the audit history of the Mosaic codebase. New entries are
appended in reverse chronological order.

---

## 2026-04-20 — Phase 1 scope frozen; **ready for external review**

| Field | Value |
|---|---|
| Tag | [`v0.1.0-phase1`](https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1) |
| Auditor | **None yet** — outreach in progress (issue [#61](https://github.com/wienerlabs/mosaic/issues/61)) |
| Scope | See § Phase-1 audit scope below |
| Commit | Tag head — SHA depends on final pre-audit-readiness commits |
| Findings | N/A — pre-audit |
| Status | **Phase 1 scope ready for review.** Do not use in production pending audit. |

### Phase-1 audit scope (locked at `v0.1.0-phase1`)

#### In scope
- [`crates/mosaic-core/`](crates/mosaic-core) — trait hierarchy, error
  taxonomy, syscall abstraction.
- [`crates/mosaic-groth16/`](crates/mosaic-groth16) — BN254 Groth16 verifier
  (host + SBF backends).
- [`crates/mosaic-serde/`](crates/mosaic-serde) — **snarkjs + arkworks
  adapters only**; `gnark`, `halo2`, `plonky3`, `risc0` modules are stubs
  and out-of-scope.
- [`crates/mosaic-chunked/`](crates/mosaic-chunked) — PDA layout, rolling
  SHA-256 protocol, instruction data model.
- [`crates/mosaic-program/`](crates/mosaic-program) — reference Solana
  program dispatcher, including chunked-upload instruction handlers.
- [`docs/adr/`](docs/adr) — five ADRs (trait hierarchy, error taxonomy,
  serialization, chunked upload, CU budget).
- [`docs/design/0001-chunked-upload-handlers.md`](docs/design/0001-chunked-upload-handlers.md)
  — chunked-upload implementation contract.
- [`docs/threat-model.md`](docs/threat-model.md) — T-1..T-10 adversarial
  input vectors.

#### Out of scope
- `crates/mosaic-plonk/` — Phase 2 stub, `UnimplementedProofSystem` return only.
- `crates/mosaic-stark/` — Phase 3 stub.
- `crates/mosaic-nova/` — Phase 3 stub.
- `crates/mosaic-serde/src/{gnark,halo2,plonky3,risc0}.rs` — stubs.
- `crates/mosaic-sdk/` — host-only client SDK. Out of audit scope because
  on-chain security does not depend on SDK correctness.
- `crates/mosaic-bench/` — measurement tooling.
- `crates/mosaic-fuzz/` — fuzz harnesses (audited *via* their findings, not
  as code under review).
- `tests/` — test harness, not production code.
- Upstream dependencies — audited by their own projects.

### Known unaudited components

See [SECURITY.md § Known unaudited components](SECURITY.md#known-unaudited-components).

### Review artifacts prepared for auditors

The following artifacts are intentionally maintained in the repository so
auditors can audit the audit trail itself:

| Artifact | Purpose |
|---|---|
| [`CHANGELOG.md`](CHANGELOG.md) | Phase-1 scope locked at `v0.1.0-phase1`. |
| [`docs/adr/*.md`](docs/adr) | Every architectural decision with context + consequences. |
| [`docs/design/*.md`](docs/design) | Implementation contracts for non-trivial protocols. |
| [`docs/threat-model.md`](docs/threat-model.md) | Adversarial input vectors T-1..T-10. |
| [`docs/lint-policy.md`](docs/lint-policy.md) | Every `#[allow(clippy::…)]` justified. |
| [`docs/compute-unit-budget.md`](docs/compute-unit-budget.md) | Per-system CU caps + measured baselines. |
| [`docs/audit/rfq.md`](docs/audit/rfq.md) | Pre-audit request-for-quote sent to candidate firms. |
| [`docs/audit/outreach-email.md`](docs/audit/outreach-email.md) | Outreach + response templates. |
| `supply-chain/` | `cargo-vet` attestation configuration. |

### Phase-1 self-review checklist

Completed internally before opening for external review. Items the
auditor is invited to challenge are marked ⚠.

- [x] Zero `unimplemented!()` / `todo!()` / `panic!()` in library code paths.
- [x] Every `OnChainError` discriminant pinned by `discriminant_stability` test.
- [x] Differential test harness passes (arkworks reference vs Mosaic host).
- [x] Round-trip byte equality: snarkjs / arkworks / canonical.
- [x] Chunked-upload integration tests cover happy path + 6 security gates.
- [x] `bpf-bench` measures actual on-chain CU against ADR-0005 caps.
- [x] `#![forbid(unsafe_code)]` workspace-wide (migration to `deny` tracked [#58](https://github.com/wienerlabs/mosaic/issues/58)).
- [x] `cargo-deny`, `cargo-audit` in CI.
- [ ] ⚠ `cargo-vet` bootstrap landed; full import chain pending #59.
- [ ] ⚠ Poseidon on-chain syscall path not wired for Solana 2.x (#8).
- [ ] ⚠ Fixtures are programmatic (arkworks-synthesized JSON),
      not Circom-compiled (#24).

---

## Audit roadmap

| Milestone | Target | Status |
|---|---|---|
| Internal review of `mosaic-core` trait surface | Phase 1 freeze | **Done** ([`v0.1.0-phase1`](https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1)) |
| Pre-audit outreach (4 firms) | 2026-Q2 start | In progress (issue [#61](https://github.com/wienerlabs/mosaic/issues/61)) |
| External audit firm selection | 2026-Q2 end | Pending quotes |
| External audit of `mosaic-groth16` + reference program | Phase 2 release | Pending |
| External audit of `mosaic-plonk` | Phase 2 freeze | Pending |
| External audit of `mosaic-stark` + chunked-upload verifier path | Phase 3 release | Pending |
| Recurring audit (annual) | Post-1.0.0 | Pending |

---

## Reporting issues

Vulnerability reports follow the [SECURITY.md](SECURITY.md) policy.
Audit findings — once we have audits — are tracked in this file with
fix commit references.

## Entry template

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

Findings that are *fixed* in a follow-up commit reference the fix commit
SHA. Findings that are *accepted-as-risk* include a written justification.
