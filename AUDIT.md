# Audit Log

This file records the audit history of the Mosaic codebase. New entries are
appended in reverse chronological order.

For external review firms: start with
[`docs/audit-coverage-runbook.md`](docs/audit-coverage-runbook.md)
— it gives you the local-reproduce + extend recipes for every
audit-coverage surface listed below.

---

## 2026-04-27 — v0.8.3-shared-primitive-lift release (sessions 60-68)

| Field | Value |
|---|---|
| Tag | [`v0.8.3-shared-primitive-lift`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.3-shared-primitive-lift) |
| Auditor | Internal (Wiener Labs) |
| Scope | Shared-primitive consolidation (sessions 63, 66) + consumer migrations (sessions 64, 65, 68) + CI workflow expansion (session 61) + audit-coverage runbook (session 70) |
| Findings | Zero soundness regressions; one false positive caught + fixed inline (snake_case digit allowance, session 52) |
| Status | ✅ Every BN254 polynomial-eval site and every BN254 pairing site in the workspace goes through one of the 8 audit-grade shared primitives |

### What this milestone changes for an external auditor

The workspace now exposes **8 shared primitives** in
`mosaic-zk-primitives` covering Fr arithmetic, transcript challenge
derivation, KZG opening LHS construction, generic pairing
verification, and Horner polynomial evaluation. Every BN254 verifier
in the workspace (mosaic-{groth16, plonk, hyperplonk, halo2, nova})
calls into these primitives instead of inlining its own
implementation. A future soundness-critical change (e.g. tighter
G2 length validation, a different pairing return-code convention
if Solana ever changes the alt_bn128 wire format) needs only one
edit.

CI now runs every sessions-47-59 bench + fuzz harness on every PR
(representative subset, ~25 min wall-clock) and the full 23-target
fuzz inventory nightly at 60 min/harness.

### Lib test totals at v0.8.3

  mosaic-core              16
  mosaic-zk-primitives     74  (+10 since v0.8.2: horner + n-pair)
  mosaic-groth16           26
  mosaic-plonk             32
  mosaic-hyperplonk        82
  mosaic-halo2             75
  mosaic-nova              59
  mosaic-stark            117
  mosaic-serde             23
  mosaic-chunked           20
  mosaic-sdk               13
  mosaic-program            7
  ─────────────────────  ───
  total                   544

### What this milestone does NOT change

No on-chain ABI, behaviour, or wire-format change. The
shared-primitive lifts are byte-identical refactors verified by
the existing test suite remaining green across the migration
commits.

---

## 2026-04-27 — v0.8.2-fuzz-bench-coverage release (sessions 47-59)

| Field | Value |
|---|---|
| Tag | [`v0.8.2-fuzz-bench-coverage`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.2-fuzz-bench-coverage) |
| Auditor | Internal (Wiener Labs) |
| Scope | Bench + fuzz dimension extension of the v0.8.1 audit-coverage milestone |
| Findings | One false positive caught + fixed inline (HyperPlonk anchor + XOR cancellation, session 58); zero soundness regressions |
| Status | ✅ All 6 production verifiers covered by both BPF CU bench AND host criterion bench AND a 23-target fuzz harness inventory |

The v0.8.2 milestone has three measurement-surface dimensions:

| Surface | Coverage |
|---|---|
| Property tests | 137 across 12 crates (sessions 36-52) |
| BPF CU bench | 7 systems (sessions 47, 49) |
| Host criterion bench | 5 systems (session 51) |
| Fuzz harnesses | 23 targets across 6 systems (sessions 54-59) |

Per-system fuzz inventory at v0.8.2 (carried into v0.8.3):

  Phase-1 Groth16 (3 original)
    fuzz_groth16_proof_bytes, fuzz_vk_bytes, fuzz_public_inputs

  Phase-2 KZG-PLONK (4)
    fuzz_plonk_{proof_bytes, vk_bytes, public_inputs, combined}

  Phase-3 HyperPlonk + Halo2 + Nova + FRI-STARK (16)
    fuzz_<system>_{proof_bytes, vk_bytes, public_inputs, combined}

---

## 2026-04-27 — Workspace-wide proptest sweep (sessions 37-42, post-v0.8.0)

| Field | Value |
|---|---|
| Tag | _no separate tag_ — work appended to the `v0.8.0-phase3-polish` line via main branch commits `cfef56a..0fb0ea9` |
| Auditor | Internal (Wiener Labs) |
| Scope | Property-based test coverage for every host-callable byte-format, Fiat-Shamir, state-machine, and SDK surface in the workspace |
| Findings | Three internal false positives surfaced and documented inline (see "Yan kazanım" section in each session commit message); zero soundness regressions |
| Status | ✅ Audit-grade proptest coverage now spans 9 of 11 workspace crates |

### What this milestone changes for an external auditor

The workspace now ships **324 lib tests across 11 crates**, of which
**+111 are property-based tests added in this sweep**. Every Phase-1,
Phase-2, and Phase-3 verifier crate, plus the snarkjs adapter, the
chunked-upload state machine, the client SDK, and the on-chain program
dispatch surface, is now property-tested under proptest with explicit
audit-grade rationale comments at each test's docstring.

The intention is to give an external review firm a single point of
entry to the soundness density of every byte-format and state-transition
boundary: instead of having to derive the audit-relevant invariants
from prose, they can read the proptest body and verify it pins the
property they care about.

### Property categories pinned by the sweep

| Category | Crates covered | Representative property |
|---|---|---|
| Canonical byte layout | halo2, hyperplonk, nova, plonk, groth16 | `proof_view_parses_any_canonical_payload` reassembles A‖B‖C exactly |
| Fiat-Shamir avalanche | halo2 (4-round), hyperplonk (3-round), nova (3-round), plonk (6-round) | `quotient_t_mutation_xi_v_only` — round-4 absorb cascades to ξ + v but leaves β/γ/α/u stable |
| Single-byte tamper rejection | halo2, hyperplonk verifiers | `random_commit_byte_flip_rejects` over commit + opening regions |
| State-machine monotonicity | chunked | `finalized_session_rejects_appends` pins no-double-finalize + no-post-finalize-append |
| Borsh wire-format round-trip | sdk, program | `verify_proof_data_borsh_roundtrip` pins the four-field order against silent reorderings |
| BE-comparison + Fr arithmetic | groth16 | `add_mod_r_preserves_range` for the batch-coefficient sum |
| snarkjs adapter byte ordering | serde | `g2_layout_c1_then_c0` pins the Solana c1 ‖ c0 swap |
| Builder/setter independence | sdk | `builder_setters_are_independent` against copy-paste setter aliasing |
| Instruction-tag dispatch | program | `process_rejects_unknown_tag` exhaustive over u8 ∉ known dispatch ranges |

### Documented false positives (inline rationale + scope narrowing)

1. **Halo2 verifier random-byte-flip selector slot**
   The trivially-zero dummy fixture has `b = 0` for every wire, so
   flipping a `Q_R` byte preserves the gate expression `Q_R · b = 0`.
   Scope was narrowed to commit-region bytes; the selector-slot
   property is deferred to the fixture-driven differential harness.

2. **HyperPlonk verifier `anchor + XOR` cancellation**
   The pattern `proof[off] = anchor; proof[off] ^= bit_mask;` collapses
   to a no-op when `bit_mask == anchor`. Surfaced by proptest shrinking
   on the first run; rewritten as direct `proof[off] = new_val` with
   `new_val ∈ [1, 255]`. Same pattern audited and avoided across the
   rest of the sweep.

3. **`is_multiple_of` MSRV warning** _(pre-existing, not from this sweep)_
   The challenges modules use `usize::is_multiple_of`, stable since
   Rust 1.87. Workspace MSRV is 1.85. CI passes because the lint is in
   the pedantic group; documented here as an unresolved drift between
   nightly clippy's stable-version detection and our MSRV pin.

### What this does NOT yet cover

- **Fixture-driven differential testing for Phase-3 bodies.** The
  existing `tests/differential` harness covers Groth16 + PLONK against
  arkworks; HyperPlonk, Halo2, Nova, and FRI-STARK still need
  Espresso / PSE / sonobe / Plonky3 reference fixtures wired in.
  This is the last named pre-audit gap in `README.md § Security`.
- **`mosaic-program::chunked::dispatch` integration tests.** The
  current SBF integration test under `tests/verify_proof_sbf.rs` exercises
  the verify-proof path; the chunked dispatch path needs a parallel
  `solana-program-test` harness with synthesized `AccountInfo`.
- **Arkworks adapter property tests.** Generating random valid
  `ArkProof` / `ArkVk` fixtures requires a small inline circuit; this
  was deferred from session 40.

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
- [x] Scope-boundary axes documented (under-constrained circuits, malleable proofs, validator determinism, replay safety) — [`docs/threat-model.md`](docs/threat-model.md#scope-boundaries-and-application-responsibilities).
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
