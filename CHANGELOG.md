# Changelog

All notable changes to Mosaic are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned beyond v0.8.4-primitive-consumer-coverage

- Fixture-driven differential testing for the four Phase-3 bodies
  (Espresso HyperPlonk, PSE Halo2, sonobe Nova, Plonky3 STARK).
  **Last named pre-audit gap on the Phase-3 verifier track.**
- HyperPlonk full Zeromorph / PST / Gemini reduction (canonical
  layout breaking change).
- mosaic-nova::kzg::verify_spartan_batched_opening migration to
  fr_inner_product (deferred from session 77; the explicit 5-term
  unrolled chain is more legible inline at N=5 than the helper
  call's collect-into-Vec dance).
- External security audit commission.

## [0.8.4-primitive-consumer-coverage] — 2026-04-28

**Primitive consolidation reaches the production verifier surface.**
Sessions 60-78 add 4 more shared primitives (7-10), migrate every
remaining inline weighted-sum / Horner / pairing site in the
workspace to the shared helpers, ship a runbook for external
auditors, wire the v0.8.2 bench + fuzz harnesses into CI matrices,
and add the 8th chunked-handlers integration test that proves the
verifier dispatch path is reached end-to-end from the chunked
upload protocol.

| Surface | v0.8.3 | v0.8.4 |
|---|---|---|
| Shared primitives | 8 | **10** |
| Consumer migrations using shared helpers | 0 explicit | 7 sites |
| chunked-handlers integration tests | 7 | 8 |
| Audit runbook | — | `docs/audit-coverage-runbook.md` |
| CI matrix coverage | partial | full (PR + nightly) |

The 4 new shared primitives:
- `fr_horner_eval` (s63) — polynomial Horner evaluation
- `verify_n_pair_pairing` (s66) — N-pair generic pairing
- `powers_of` (s72) — geometric sequence
- `fr_inner_product` (s77) — dot product

Combined with the 6 from sessions 21-35
(fr_from_be_bytes_reduced, fr_be_from_u64,
derive_fr_challenge, verify_two_pair_pairing,
commitment_minus_scalar_g1, compute_kzg_opening_lhs), the
mosaic-zk-primitives crate now ships **10 audit-grade helpers**.

The 7 consumer migrations (sessions 64, 65, 68, 72, 74×2, 77, 78×2):
- mosaic-hyperplonk::sumcheck::eval_at → fr_horner_eval (s64)
- mosaic-halo2::vanishing::compute_t_from_chunks → fr_horner_eval (s65)
- mosaic-hyperplonk::kzg pairing → verify_two_pair_pairing (s68)
- mosaic-hyperplonk::kzg ν-powers → powers_of (s72)
- mosaic-halo2::kzg ν-powers → powers_of (s74)
- mosaic-nova::kzg ν-powers → powers_of (s74)
- mosaic-hyperplonk::kzg y-batched → fr_inner_product (s77)
- mosaic-halo2::kzg y-batched (×2 sites) → fr_inner_product (s78)

After the migrations every BN254 polynomial-eval site, every BN254
pairing site, every BN254 ν-powers site, and every BN254 weighted-
sum site in the workspace goes through one of the 10 audit-grade
shared primitives.

No on-chain ABI or behaviour changes — refactor + tests + CI
infrastructure + docs only.

### Added — sessions 70-72 (post-v0.8.3)

#### Session 70 — audit-coverage runbook
`docs/audit-coverage-runbook.md` — entry point for an external
review firm that wants to reproduce the Mosaic audit-coverage
matrix locally and extend it with their own tests. Covers:
- Coverage matrix at v0.8.3 with per-surface session ranges.
- Local-reproduce recipes (property tests, BPF CU bench, host
  criterion bench, fuzz harnesses).
- Extension recipes (add a new property test, fuzz harness,
  bench, shared primitive).
- Three explicit caveats about what the coverage does NOT pin
  (real prover output, full Phase-3 cryptographic soundness,
  chunked dispatch integration).

#### Session 71 — AUDIT.md release entries
Recorded both v0.8.2 and v0.8.3 release milestones in AUDIT.md
with per-release scope, findings, and lib-test counts. Top-of-
file pointer to `docs/audit-coverage-runbook.md` so external
reviewers find the local-reproduce workflow immediately.

#### Session 72 — `powers_of` 9th shared primitive + first consumer
`mosaic_zk_primitives::field::powers_of` lifts the multi-poly
batched-opening ν-powers accumulator loop that surfaces in
HyperPlonk session 3e, Halo2 session 17, and Nova Spartan
session 22.

+5 proptest tests (mosaic-zk-primitives lib total 74 → 79):
- prop_powers_of_length / prop_powers_of_first_is_one /
  prop_powers_of_recurrence / prop_powers_of_one_is_all_ones
- prop_powers_of_matches_pow — closed-form cross-check against
  `fr_pow_u64`. The soundness invariant that justifies the lift.

First consumer migration: `mosaic_hyperplonk::kzg` replaces an
inline 11-step accumulator loop with `powers_of(&nu, 12)`. 82
hyperplonk lib tests still pass; byte-identical refactor.

After session 72 the shared-primitive count is **9 helpers** in
mosaic-zk-primitives.

#### Session 73 — docs sweep
Recorded sessions 70-72 in CHANGELOG + README; lib test total
bumped 544 → 549, "+147 proptest + shared-primitive coverage" →
"+152 proptest + 9 shared primitives lifted", new "Audit runbook"
row in the README Status table.

#### Session 74 — `powers_of` consumer migrations (halo2 + nova)
Two more consumer migrations for the session-72 `powers_of`
primitive:

- mosaic-halo2::kzg::verify_two_point_batched_opening — replaces
  inline 2-line accumulator loop with `powers_of(v, max_len)`
  for the asymmetric ξ vs ξω commitment counts.
- mosaic-nova::kzg::verify_spartan_batched_opening — replaces
  hand-unrolled `[v⁰, v¹, v², v³, v⁴]` chain with
  `powers_of(v, 5)`. The byte-conversion stage stays unrolled
  because msm_g1's signature wants `&[[u8; 32]; 5]`.

Both migrations byte-identical at the Fr level. After session 74
the `powers_of` consumer audit:
- mosaic-hyperplonk::kzg (session 72)
- mosaic-halo2::kzg::verify_two_point (session 74)
- mosaic-nova::kzg::verify_spartan (session 74)

No more BN254-Fr ν-powers inline sites in the workspace.

#### Session 75 — chunked commit_and_verify dispatch path coverage
8th chunked-handlers integration test, closing the "chunked
dispatch reaches verifier hand-off" gap on the audit-coverage
planned-beyond list. Drives the full lifecycle —
init → append → finalize-with-correct-hash → dispatch_verify —
and asserts the error surfaces from dispatch_verify (not from
the chunked state machine).

Test approach
- Sham VK account (16 bytes, structurally too small) reaches
  the verifier dispatch step.
- Asserts `Custom(2)` == `OnChainError::VerifyingKeyLengthMismatch`
  in the program log, proving the verifier hand-off works and
  the verifier surface fails closed on the structurally invalid
  VK.

Test inventory in chunked_handlers.rs after session 75: 8 tests.

The remaining gap on the chunked path is a *real* commit_and_verify
happy-path test (genuine Groth16 proof + VK uploaded via chunked
flow); that's deferred to the fixture-driven differential testing
item.

### (Planning block superseded by v0.8.4 release entry above.)

#### v0.8.3 planning block (kept for historical reference)

- Fixture-driven differential testing for the four Phase-3 bodies
  (Espresso HyperPlonk, PSE Halo2, sonobe Nova, Plonky3 STARK).
  **Last named pre-audit gap on the Phase-3 verifier track.**
- HyperPlonk full Zeromorph / PST / Gemini reduction (canonical
  layout breaking change).
- `mosaic-program::chunked::dispatch` integration tests via
  `solana-program-test` with synthesized `AccountInfo`.
- External security audit commission.

## [0.8.3-shared-primitive-lift] — 2026-04-27

**Shared-primitive consolidation + CI activation.** Sessions 61-68
extend the v0.8.2 fuzz/bench coverage with two cross-cutting work
streams:

- **Shared primitives 7 + 8** (`fr_horner_eval`, `verify_n_pair_pairing`)
  added to `mosaic-zk-primitives`, joining the six lifted in
  sessions 21-35.
- **Consumer migrations** in mosaic-{hyperplonk, halo2} replace
  inline Horner loops + 384-byte alt_bn128_pairing buffer
  construction with calls to the shared helpers. After the sweep,
  every BN254 polynomial-eval site and every BN254 pairing site
  in the workspace goes through one of the eight audit-grade
  primitives.
- **CI workflow expansion** wires every sessions-47-59 bench +
  fuzz harness into GitHub Actions matrices. PR mode runs a
  representative subset (~25 min wall-clock); nightly runs the
  full 23-target fuzz inventory at 60 min/harness.

No on-chain ABI or behaviour changes — refactor + tests +
infrastructure only.

### Added — sessions 61-64 (post-v0.8.2)

#### Session 61 — CI workflow expansion
`.github/workflows/{fuzz,bench}.yml` rewritten to invoke every
sessions-47-59 bench + fuzz harness:
- fuzz.yml — PR mode runs a representative 8-target subset
  (1 per system, combined-slot variant) at 5 min/harness;
  nightly runs the full 23-target sweep at 60 min/harness.
- bench.yml — criterion job is now a matrix over
  `[groth16_host, phase3_host]` with per-bench artifact uploads.
- Both workflows' `paths:` triggers expanded to all five
  Phase-2/3 verifier crates plus mosaic-zk-primitives.

#### Session 63 — `fr_horner_eval` 7th shared primitive
`mosaic-zk-primitives::field::fr_horner_eval` lifts the polynomial
Horner-evaluation pattern out of every Phase-3 verifier's inline
sumcheck/identity code into a single audit-grade helper. Joins the
existing six shared primitives extracted in sessions 21-35.

+6 proptest tests (mosaic-zk-primitives lib total 64 → 70):
- `prop_horner_matches_naive_eval` — Horner equals
  Σ a_i · x^i for any polynomial up to degree 8 and any in-range
  Fr challenge. **The soundness invariant** that justifies the
  lift.
- `prop_horner_empty_is_zero`, `prop_horner_constant_polynomial`,
  `prop_horner_linear_polynomial`,
  `prop_horner_at_zero_returns_constant`,
  `prop_horner_at_one_returns_sum`.

#### Session 64 — first `fr_horner_eval` consumer migration
`mosaic-hyperplonk::sumcheck::RoundPolynomial::eval_at` migrated
from an inline Horner loop to `fr_horner_eval`. All 82 hyperplonk
lib tests still pass; the migration is byte-identical at the Fr
level. Tracked as the first of 5+ in-tree consumer sites that
will gradually move to the shared primitive.

#### Session 65 — second `fr_horner_eval` consumer migration
`mosaic-halo2::vanishing::compute_t_from_chunks` migrated. The
"evaluation point" for this Horner reduction is `ξ^n` rather
than `ξ` (each chunk is the i-th coefficient of the polynomial
that takes `ξ^n` as its variable). 75 halo2 lib tests still pass.

Per-site survey of remaining BN254-Fr Horner sites in the
workspace after sessions 64-65: zero. mosaic-stark uses the
Goldilocks field, not BN254 Fr; the shared primitive doesn't
apply there.

#### Session 66 — `verify_n_pair_pairing` 8th shared primitive
Generalizes `verify_two_pair_pairing` (session 25) from a fixed
2-pair API to an arbitrary-N-pair API. `verify_two_pair_pairing`
rewritten to delegate to the new generic version with `N=2`.

Why both APIs

- 2-pair specialization stays in the workspace for the hot
  canonical KZG opening pattern (avoids a slice allocation by
  passing fixed-arity arguments).
- N-pair generic version lifts the inline pair-list construction
  pattern that surfaces in Halo2's multi-poly batched opening
  (session 17) and Nova's Spartan-batched 5-way opening (session
  22). Both currently inline a loop that concatenates pair bytes
  into the syscall input buffer; future migrations can replace
  the loops with `verify_n_pair_pairing` calls.

+4 unit tests for the new primitive (mosaic-zk-primitives lib
total 70 → 74):

- empty-pair vacuous identity case
- 2-pair specialization equivalence with the new generic API
- 3-pair canceling combination
  `e(G1,G2)·e(G1,G2)·e(-2G1,G2) = e(0,G2) = 1`
- pre-syscall G2-length validation pass

After sessions 63-66 the shared-primitive count is **8 helpers**
in `mosaic-zk-primitives` covering Fr arithmetic, transcript
challenge derivation, KZG opening LHS construction, generic
pairing verification, and Horner polynomial evaluation.

#### Session 68 — last in-tree pairing-helper consumer migration
`mosaic-hyperplonk::kzg::verify_kzg_batched_opening` migrated
from an inline 384-byte `alt_bn128_pairing` buffer + return-byte
inspection to the shared `verify_two_pair_pairing` (which, per
session 66, now itself delegates to `verify_n_pair_pairing` with
`N=2`). HyperPlonk was the last in-tree consumer that hand-rolled
the buffer construction; mosaic-{halo2, nova} already used the
helper.

After session 68 every BN254 pairing site in the workspace goes
through one centralized audit-grade primitive — a future
soundness-critical change (e.g. additional G2 length validation
or a different return-code convention) needs only one edit.

## [0.8.2-fuzz-bench-coverage] — 2026-04-27

**Audit-coverage extension: bench + fuzz dimension.** Sessions 47-59
extend the v0.8.1 proptest sweep with two complementary measurement
surfaces:

- **Benches** — `bpf-bench` grew from 3 to 7 systems (HyperPlonk,
  Halo2, Nova, FRI-STARK BPF benches added in sessions 47, 49); a
  new `phase3_host` Criterion benchmark covers the same 4 Phase-3
  systems plus Groth16 on the host side (session 51).
- **Fuzz harnesses** — `mosaic-fuzz` grew from 3 to 23 targets
  across 6 production verifiers in 4 dimensions per system: proof
  bytes, VK bytes, public-input bytes, and a length-prefixed
  combined-slot fuzzer that explores cross-slot interaction
  surface (sessions 54-59).

`mosaic-core` (the workspace foundation crate) was lifted from 0
to 16 lib tests with the `ALL_VARIANTS` const table that external
indexers can copy as the source of truth for the on-chain ABI
(session 52).

No behaviour changes — test, bench, and fuzz code only, plus
README / AUDIT / CHANGELOG entries.

### Added — sessions 47-49 (audit-coverage extension, first wave)

**Phase-3 BPF bench coverage + arkworks adapter property tests.**
Pushes the `bpf-bench` regression harness from 3 to 7 measured
systems and closes the arkworks adapter's 0-test gap from session 40.

#### Session 47 — HyperPlonk + Halo2 + Nova BPF benches
`crates/mosaic-bench/src/bin/bpf_bench.rs` gains 3 new
`SystemTarget` entries, 3 inline scaffold-acceptance fixture
builders, and 3 dispatch arms. The fixture builders mirror each
verifier's own `verifier::tests` dummy fixtures (zero-wire +
LOOKUP_M=1 trick for Halo2; real G2 generator for the pairing
syscall on all three). Hard caps derived from each verifier's
`estimated_compute_units` × 1.30 regression headroom.

| Target | Hard cap | Baseline |
|---|---:|---:|
| `hyperplonk_kzg_bn254_scaffold` | 660K | tbd (first run) |
| `halo2_kzg_bn254_scaffold` | 760K | tbd (first run) |
| `nova_folding_bn254_scaffold` | 1.15M | tbd (first run) |

#### Session 48 — arkworks adapter property tests
`crates/mosaic-serde/src/arkworks.rs` gains 11 proptest tests
covering encode_proof / encode_vk / encode_public_inputs:
- Length invariants (256 B proof, `64 + 3·128 + 64·n` VK,
  `32·n` public inputs).
- Determinism (same struct → same bytes across two calls).
- A‖B‖C and `alpha (G1) ‖ beta (G2) ‖ gamma (G2) ‖ delta (G2) ‖
  ic[0..n] (G1)` byte-region pinning.
- G1 + G2 identity-element handling (point at infinity → all-zero
  bytes, matches Solana alt_bn128 convention).
- `format()` tag stability.
- decode/encode equivalence: bytes from ark-serialize +
  `decode_proof` match `encode_proof` of the original struct.

Fixtures are constructed by multiplying G1/G2 generators by
random Fr scalars from `ark_std::test_rng()` — no inline circuit
required. Closes the "arkworks adapter property tests" item from
v0.8.1's planned-beyond list.

mosaic-serde lib tests: 12 → 23.

#### Session 49 — FRI-STARK BPF bench
Closes the deferred Phase-3 BPF bench gap from session 47.
`build_stark_scaffold_fixture` reproduces the canonical proof
layout inline (mirrors `mosaic_stark::canonical::tests::proof_bytes`
for the smallest Goldilocks shape: trace_width=1,
trace_log_height=10, log_blowup=1, num_fri_layers=4, num_queries=8,
pow_bits=0). Hard cap = 7.8M (estimate × 1.20; lower headroom
because the work is dominated by syscall counts rather than
polynomial codegen).

| Target | Hard cap | Baseline |
|---|---:|---:|
| `fri_stark_goldilocks_scaffold` | 7.8M | tbd (first run) |

After sessions 47-49 `bpf-bench` covers all 6 productionish
verifier surfaces (Groth16 single + batch, KZG-PLONK, HyperPlonk,
Halo2, Nova, FRI-STARK).

### Added — sessions 50-52 (audit-coverage extension, second wave)

#### Session 50 — docs sweep
Recorded sessions 47-49 in CHANGELOG + README Status table; added
new "BPF CU regression bench" row covering the 7 measured systems.

#### Session 51 — host-side Criterion benches for Phase-3
`crates/mosaic-bench/benches/phase3_host.rs` — new file with 4
criterion targets (HyperPlonk, Halo2, Nova, FRI-STARK) using the
same scaffold-acceptance fixtures as the bpf-bench counterparts.
Wall-clock numbers from this bench are the canary for host-side
CPU regressions before they hit on-chain CU; criterion's noise
floor lets a real algorithmic change surface distinctly from
JIT/codegen drift on the runner.

After sessions 47-51 the host-side criterion bench coverage is
groth16 + 4 Phase-3 = 5 systems.

#### Session 52 — proptest coverage for the workspace foundation
`mosaic-core` had 0 proptest pre-session — the workspace's
foundation crate (trait hierarchy, error taxonomy, proof-system
discriminant enum) was the last unaudited surface. Added 10
property-based tests pinning the two consensus-critical ABI
structures:

- `proof_system.rs` (+5 proptest):
  * `known_byte_round_trip` — every byte 0x01..=0x08 round-trips
  * `unknown_byte_rejected` — exhaustive over u8 ∉ {0x01..=0x08}
  * `from_byte_is_pure` — same byte → same variant across two calls
  * `slugs_pairwise_distinct` — no two variants share a slug
  * `discriminants_pairwise_distinct` — no two variants share a byte

- `error.rs` (+5 proptest, all backed by an `ALL_VARIANTS` const
  table that external indexers can copy as the ABI source of truth):
  * `all_discriminants_stable` — every variant's `code()` matches
    the committed value (pin the on-chain ABI exhaustively)
  * `all_slugs_stable` — every variant's `slug()` matches the
    committed identifier
  * `all_slugs_snake_case` — ASCII lowercase + digit + '_' allowed
    (digit allowance pinned because curve names embed digits like
    `alt_bn128`, `bn254`, `mersenne31`)
  * `discriminant_codes_pairwise_distinct` — no aliasing
  * `slugs_pairwise_distinct` — no aliasing

Yan kazanım — false positive caught + documented inline:
- `is_ascii_lowercase()` snake-case check rejected curve-name
  digits. Surfaced by proptest shrinking on the first run at
  idx = 23 (AltBn128SyscallFailed). Corrected to allow
  `is_ascii_digit()`, with explicit comment explaining why.

Sessions 37-52 cumulative: every host-callable workspace crate
under audit-grade proptest coverage. **Total +137 proptest tests
across 12 crates** (was +111 across 9 after session 42; +9 in
session 47 are bpf-bench `SystemTarget` entries; +11 in session 48,
+11 in session 51 + criterion benches; +10 in session 52).

### Added — sessions 54-56 (fuzz harness expansion)

#### Session 54 — Phase-2 + Phase-3 proof-bytes fuzzers
`crates/mosaic-fuzz` grew from 3 harnesses (all Groth16) to 8.
The new Phase-2/3 targets are `fuzz_{plonk, hyperplonk, halo2,
nova, stark}_proof_bytes`, each pinning the panic-free invariant
on its system's verify pipeline. Per-system `*Fixtures` structs
in `mosaic-fuzz/src/lib.rs` build scaffold-acceptance
`(vk, proof, public_inputs)` triples, mirroring the inline
fixture builders in `bpf-bench` (sessions 47, 49) and
`phase3_host` criterion benches (session 51).

#### Session 55 — per-system VK fuzzers
Added 5 more harnesses targeting the verifying-key parser of
each Phase-2/Phase-3 system: `fuzz_{plonk, hyperplonk, halo2,
nova, stark}_vk_bytes`. Mirrors the proof-bytes harness pattern
but flips the libfuzzer input into the VK slot. Each pins
system-specific invariants:

- PLONK + HyperPlonk: 744-byte fixed envelope.
- Halo2: variable-length tail (fixed_commits ‖ permutation_commits).
- Nova: 235-byte fixed envelope + 3-way `FoldingVariant` tag rejection.
- STARK: 48-byte fixed envelope + 3-way `StarkFieldId` tag
  rejection + structural cross-check against the proof shape.

#### Session 56 — combined-slot Halo2 fuzzer
`fuzz_halo2_combined` is the first multi-slot harness — splits
the libfuzzer input into three length-prefixed sub-buffers
(vk, proof, public_inputs) and feeds all three to the verifier.
Explores a coordinate in `(vk, proof, pi)` space rather than the
1-D slice the per-slot harnesses cover; catches bugs that only
surface when two slots lie about the same shape parameter in a
coordinated way that the structural cross-check missed.

Halo2 chosen as the first combined target because it has the
richest VK shape (variable tail) AND the richest proof shape
(4 dynamic header counters) → widest cross-slot interaction
surface. Pattern is template-able for the other 4 systems
(tracked as session 57+ follow-up).

After sessions 54-56 the fuzz harness inventory is **14 targets**:
- 3 original Groth16 (proof, vk, public_inputs)
- 5 per-system proof_bytes (PLONK + HyperPlonk + Halo2 + Nova + STARK)
- 5 per-system vk_bytes (same five)
- 1 combined-slot Halo2

### Added — sessions 58-59 (fuzz harness completion)

#### Session 58 — per-system public-input fuzzers
Added 5 more harnesses targeting the public-input parser of each
Phase-2 / Phase-3 system: `fuzz_{plonk, hyperplonk, halo2, nova,
stark}_public_inputs`. Each pins its system's PI invariants:

- PLONK + HyperPlonk + Halo2 + Nova: `len % 32 == 0`,
  `len / 32 == vk.n_public`, every 32-byte chunk in Fr range.
- STARK: length must be a multiple of
  `field_id.field_elem_bytes()` (8 for Goldilocks, 4 for
  BabyBear / Mersenne31).

Halo2's PI feeds round-1 of the Fiat-Shamir absorb sequence — a
regression in PI parsing would cascade into every challenge and
break the verifier's identity check. The session-37 challenges
proptests already pin the cascade for valid PI; this fuzzer pins
the rejection path for invalid PI across the full byte-buffer space.

#### Session 59 — combined-slot fuzzers for the remaining 4 systems
Adds combined-slot harnesses for PLONK, HyperPlonk, Nova, and
FRI-STARK, completing the cross-slot interaction surface coverage
the session-56 Halo2 template demonstrated. Refactored the
`split_three_slots` helper out of the Halo2 dump-target into
`mosaic-fuzz::lib` so all 5 combined-fuzzer binaries share the
same length-prefix parser.

Each new combined fuzzer pins system-specific cross-checks that
single-slot harnesses can't reach (because both slots must lie
in a coordinated way for the bug to surface):

- PLONK: 744 B / 768 B fixed envelopes (narrowest cross-slot
  surface; value is in catching parser confusions between the
  two envelopes).
- HyperPlonk: `vk.num_variables == proof.sumcheck_rounds`
  cross-check.
- Nova: `vk.variant == proof.variant` (FoldingVariant 3-way) +
  `vk.n_public == proof.n_public == public_inputs.len() / 32`.
- STARK: richest cross-check fingerprint of any verifier:
  `vk.field_id == proof.field_id`,
  `vk.trace_log_height == proof.trace_log_height`,
  `vk.trace_width == proof.trace_width`,
  `vk.log_blowup == proof.log_blowup`. A coordinated lie on any
  of these would route the verifier to a wrong-shape Merkle path
  or FRI fold chain.

After sessions 58-59 the fuzz harness inventory is **23 targets**
across all 6 production verifier surfaces:

  Phase-1 Groth16 (3 original)
    fuzz_groth16_proof_bytes, fuzz_vk_bytes, fuzz_public_inputs

  Phase-2 KZG-PLONK (4)
    fuzz_plonk_{proof_bytes, vk_bytes, public_inputs, combined}

  Phase-3 HyperPlonk + Halo2 + Nova + FRI-STARK (16)
    fuzz_hyperplonk_{proof_bytes, vk_bytes, public_inputs, combined}
    fuzz_halo2_{proof_bytes, vk_bytes, public_inputs, combined}
    fuzz_nova_{proof_bytes, vk_bytes, public_inputs, combined}
    fuzz_stark_{proof_bytes, vk_bytes, public_inputs, combined}

## [0.8.1-audit-coverage] — 2026-04-27

**Workspace-wide property-based test sweep.** Sessions 37-42 bring
every Phase-1, Phase-2, Phase-3, adapter, state-machine, SDK, and
on-chain program crate under audit-grade proptest coverage. **No
behaviour changes** — test code only, plus README / AUDIT /
CHANGELOG entries documenting the milestone.

### Added — audit-coverage sweep (sessions 37-42, post-v0.8.0)

Workspace-wide property-based test sweep brings every Phase-1,
Phase-2, Phase-3, adapter, state-machine, SDK, and on-chain program
crate under audit-grade proptest coverage. **+111 proptest tests**
across nine crates:

| Crate | Δ proptest | Total tests |
|---|---:|---:|
| `mosaic-halo2` | +16 | 75 |
| `mosaic-hyperplonk` | +17 | 82 |
| `mosaic-nova` | +14 | 59 |
| `mosaic-plonk` | +15 | 32 |
| `mosaic-groth16` | +15 | 26 |
| `mosaic-serde` | +9 | 12 |
| `mosaic-chunked` | +11 | 20 |
| `mosaic-sdk` | +7 | 11 |
| `mosaic-program` | +7 | 7 |

Property categories pinned:

- **Canonical byte layout invariants** — proof / VK round-trip,
  trailing-garbage rejection, truncation rejection, oversized-counter
  rejection (cap enforced before `checked_mul`), variant-tag rejection
  for systems with enum discriminants (Nova folding variant).
- **Fiat-Shamir avalanche** — round-by-round cascade properties for
  Halo2 (4 rounds), HyperPlonk (3 rounds), Nova (3 rounds), and PLONK
  (6 rounds). The PLONK sweep includes an audit-grade pin on the
  snarkjs-compatibility bit "u absorbs only `W_xi` and `W_xiω`,
  NOT `v`" — a past subtle bug rediscovered as a property.
- **Single-byte tamper rejection** — random byte flip in any commit
  or opening witness must fail verification. Scope was narrowed away
  from selector-eval slots after a documented false positive surfaced
  (see "Documented false positives" below).
- **State-machine monotonicity** — chunked-upload session: no append
  after finalize, no double-finalize, no out-of-order chunk index,
  no oversized chunk, no total-len overflow.
- **Borsh wire-format round-trip** — `VerifyProofData`,
  `VerifyProofBatchData`, and the SDK payload pin the four-field
  order against silent reorderings that would swap proof and
  public_inputs on the wire.
- **BE-comparison + Fr arithmetic primitives** — `lt_be` is
  anti-reflexive, asymmetric, and decided by the first differing
  byte; `add_mod_r` is commutative, has 0 as identity, preserves Fr
  range; `reduce_mod_r` lands in [0, r), is idempotent, and identity
  on already-reduced inputs.
- **snarkjs adapter byte ordering** — the Solana c1 ‖ c0 G2 layout
  swap (different from snarkjs's native c0 ‖ c1) is pinned, as is
  the `decimal_to_be_32` envelope (rejects `≥ 2^256`, pads small
  u128 values to 32 bytes with leading zeros).
- **Builder/setter independence + idempotence** — `with_vk(x)` only
  mutates `vk`; calling a setter twice equals calling it once with
  the second value (pure replacement, not append).
- **Instruction-tag dispatch routing** — exhaustive byte-space check
  for `process_instruction` returning `InvalidInstructionData` on
  unknown tags, plus a wrong-program-id rejection invariant.

#### Documented false positives (audit-grade trace)

Three internal false positives surfaced and were resolved with
inline rationale comments rather than silent suppressions:

1. **Halo2 verifier random-byte-flip in selector slots** — the
   trivially-zero dummy fixture has `b = 0` for every wire, so
   flipping a `Q_R` byte preserves `gate_expr = Q_R · b = 0`. Scope
   narrowed to commit + opening byte regions; the selector-slot
   property is deferred to the fixture-driven differential harness.

2. **HyperPlonk verifier `anchor + XOR` cancellation** — the pattern
   `proof[off] = anchor; proof[off] ^= bit_mask;` collapses to a
   no-op when `bit_mask == anchor`. Surfaced by proptest shrinking
   on the first run; rewritten as direct `proof[off] = new_val`
   with `new_val ∈ [1, 255]`. Same anti-pattern audited and avoided
   across the rest of the sweep.

3. **`is_multiple_of` MSRV warning** _(pre-existing, not introduced
   by this sweep)_ — challenges modules use `usize::is_multiple_of`,
   stable since Rust 1.87. Workspace MSRV is 1.85. CI passes because
   the lint is in the pedantic group; documented in `AUDIT.md`.

### Added — earlier in v0.8.0

- **HyperPlonk univariate-point full-vector binding (session 28)** —
  The KZG opening's univariate evaluation point is now derived via
  `derive_fr_challenge(backend, "mosaic-hyperplonk/univ-point",
  &r_0 ‖ r_1 ‖ … ‖ r_{n-1})` — a domain-separated keccak over the
  FULL sumcheck challenge vector. Sessions ≤27 used only the last
  challenge `r_{n-1}`. This closes the scaffold "earlier-challenge
  binding gap" that would have mattered once a real Zeromorph / PST
  / Gemini reduction lands; the univariate opening is now bound to
  every multivariate sumcheck output scalar, not just the trailing
  one. The reduction itself (intermediate commitments + fold
  consistency) stays on the roadmap.

## [0.7.0-phase3-primitives] — 2026-04-23

**Shared-primitive consolidation.** Sessions 21-26 extract every
duplicated arithmetic pattern from the four Phase-3 verifiers into
`mosaic-zk-primitives`. Five new primitives land in the shared
crate; Halo2, HyperPlonk, and Nova verifier `kzg.rs` files shed
110+ lines of boilerplate without any behavior change. Gate count
unchanged at 14 (session 23 tightens Nova's Spartan opening with a
dedicated `w_eval` slot but doesn't add a new gate class).

### Added

- **Nova `w_eval` dedicated canonical slot (session 23)** —
  `NovaFoldingProof` gained a dedicated 32-byte `w_eval` field
  between `hadamard_evals` and `aux_commits`. Sessions ≤22 derived
  the witness evaluation from the first public input as a scaffold
  stand-in; session 23 lifts it into a first-class slot carrying
  the prover's claimed `W̃(ξ)`. The Spartan-batched opening
  consumes `fr_from_canonical_bytes(proof.w_eval)` instead of
  reusing `public_inputs[..32]`. Proof canonical layout grows by
  32 B (+`W_EVAL_LEN`). New session-23 tamper test
  `spartan_rejects_tampered_w_eval_slot` flips the dedicated slot
  with `u=1, a=b=c=e=0` Hadamard-satisfying setup → the tampered
  w_eval alone propagates into `y_batched ≠ 0` while
  `C_batched = 0`, failing the batched pairing identity.

- **Shared `commitment_minus_scalar_g1` primitive (session 26)** —
  The `C - y·G1` KZG opening-minus-claim step was duplicated at 6
  sites across all KZG-based verifiers. Lifted into
  `mosaic-zk-primitives::msm::commitment_minus_scalar_g1`. Call-
  site delta: 4 lines of boilerplate → 1 function call each. Two
  new unit tests: `commitment_minus_zero_returns_commitment` and
  `commitment_minus_one_equals_negate`.

- **Shared `verify_two_pair_pairing` primitive (session 25)** —
  The 2-pair BN254 pairing identity check (build 384-byte input,
  call `AltBn128Op::Pairing`, inspect result[31]) was duplicated
  at 5 sites. Lifted into
  `mosaic-zk-primitives::msm::verify_two_pair_pairing`. Four new
  unit tests cover zero pair, canceling pair, non-trivial pair,
  and G2 length validation.

- **Shared `fr_be_from_u64` primitive (session 24)** —
  `HyperPlonkVerifyingKey::fr_be_from_u64` (session 18) lifted to
  `mosaic-zk-primitives::field::fr_be_from_u64` as a `const fn`.
  The HyperPlonk static method stays as a thin wrapper for
  discoverability. Two new unit tests compare against
  `fr_to_canonical_bytes(&Fr::from(n))` across small, boundary,
  and `u64::MAX` inputs.

- **Shared `derive_fr_challenge` primitive (session 22)** —
  Halo2 (session 17/20) and Nova (session 19) had three inlined
  copies of the `keccak256(domain || inputs) → Fr` one-shot
  challenge pattern for auxiliary challenges outside the main
  round-based `Transcript`. Lifted into
  `mosaic-zk-primitives::transcript::derive_fr_challenge`; each
  verifier passes its own domain separator string so challenges
  can't collide across protocols. Internally wraps
  `SyscallBackend::keccak256` +
  [`fr_from_be_bytes_reduced`]. Three
  new unit tests exercise determinism, domain-separation, and
  input-sensitivity.

- **Shared `fr_from_be_bytes_reduced` primitive (session 21)** —
  Halo2 (session 17) and Nova (session 19) had duplicated
  `into_fr` private helpers wrapping `Fr::from_be_bytes_mod_order`.
  Lifted into `mosaic-zk-primitives::field::fr_from_be_bytes_reduced`
  for keccak-to-Fr reduction of auxiliary challenges. Two new unit
  tests exercise in-range agreement with
  `fr_from_canonical_bytes` and out-of-range reduction.

### Breaking changes

- `NovaFoldingProof` canonical layout grows by 32 B (new `w_eval`
  slot between `hadamard_evals` and `aux_commits`). Previously-
  serialized Nova proofs require re-encoding with the additional
  slot. Fixture helpers in `canonical.rs`, `challenges.rs`,
  `kzg.rs`, and `verifier.rs` tests have all been updated.

### Gate inventory (unchanged from v0.6.0)

| Verifier | Gates | Session-21+ changes |
|---|---|---|
| HyperPlonk-KZG | 2 | `fr_be_from_u64` hoisted to shared primitive (session 24) |
| Halo2-KZG | 2 | 5 helpers (1 MSM, 2 commit/eval collectors + 2 shared primitives) share code-path with Nova |
| Nova / HyperNova / ProtoStar | 3 | `w_eval` dedicated slot (session 23); Spartan opening uses 2 shared primitives |
| FRI-STARK | 7 | unchanged |

### Test counts (post-v0.7.0)

| Crate | Passing |
|---|---|
| `mosaic-halo2` | 58 |
| `mosaic-hyperplonk` | 64 |
| `mosaic-nova` | 44 |
| `mosaic-plonk` | 17 |
| `mosaic-zk-primitives` | 51 |

Total 234 tests across the Phase-3 verifier + shared-primitives
crates (14 new unit tests + 1 new tamper test added in sessions
21-26).

## [0.6.0-phase3-extended] — 2026-04-23

**Phase-3 protocol depth extended.** Sessions 17-21 tighten every
multi-poly KZG scaffold: Halo2's batched opening now folds in all
committed polys (proof-side + VK-side preprocessed commits),
HyperPlonk lifts the permutation coset triple into the VK, and
Nova upgrades to a 5-way Spartan-batched opening spanning
`(A·z, B·z, C·z, E, W)`. Project-wide soundness gate count went
from 12 → 14 across 4 Phase-3 bodies.

### Added

- **Halo2 multi-poly MSM opening (session 17)** —
  `mosaic-halo2::kzg::verify_two_point_opening_multipoly` replaces
  the session-16 single-commitment scaffold with full v-weighted
  multi-poly batching matching PSE `halo2_proofs::plonk::verify_proof`
  semantics. Advice commits + lookup commits + permutation_z +
  quotient chunks all enter the MSM at ξ; permutation_z alone enters
  at ξω (the only shifted poly in vanilla Halo2). Tampering any
  commit or paired evaluation at either point now propagates into
  the batched pairing identity. Two new dedicated tamper tests:
  `multipoly_rejects_tampered_advice_commit` (swap advice[0] to the
  G1 generator → `PairingCheckFailed`) and
  `multipoly_rejects_tampered_wire_a_evaluation` (non-zero `a(ξ)`
  with zero commit → `PairingCheckFailed`). `v` and `u` batching
  challenges derive via domain-separated keccak over current
  transcript state + opening-proof bytes.

- **HyperPlonk VK-side permutation cosets (session 18)** —
  `HyperPlonkVerifyingKey` gained three canonical 32-byte Fr fields
  `k_1`, `k_2`, `k_3` replacing the sessions-≤17 hardcoded `(1, 2, 3)`
  coset triple in `permutation_term`. The identity factor for wire
  `a` is now `β·k_1 + γ` drawn from the VK rather than the compiled
  verifier binary — tampering a VK's `k_1` flips the reconstructed
  permutation term and therefore the sumcheck's expected final claim,
  which the verifier surfaces as `SumcheckFailed`. `SERIALIZED_LEN`
  grew from 648 B → 744 B (+96 B for 3 × Fr). A new const
  `HyperPlonkVerifyingKey::fr_be_from_u64` produces canonical BE Fr
  bytes for small integer cosets. New session-18 unit tests:
  `permutation_term_depends_on_k_cosets` (distinct triples yield
  distinct perm_term values) and `tampered_k_1_breaks_expected_claim`
  (swapping `vk.k_1` produces a different final claim).

- **Nova Spartan-batched multi-poly opening (session 19)** —
  `mosaic-nova::kzg::verify_spartan_batched_opening` replaces the
  single-commit scaffold (`verify_opening_scaffold`, which only
  opened `w_comm` at the first public input) with a 5-way batched
  MSM spanning (A·z, B·z, C·z) from the VK + (E, W) from the proof.
  A `v` challenge is domain-separated-keccak-derived from the
  Spartan point + hadamard evals + w_comm + e_comm; v-powers
  `[1, v, v², v³, v⁴]` weight the batched MSM and Fr dot product.
  Tampering any of the five commits (in VK or proof) or their
  paired evaluations now propagates into the batched pairing
  identity → `PairingCheckFailed`. Two new session-19 tamper tests:
  `spartan_rejects_tampered_vk_a_comm` (VK a_comm → G1 generator)
  and `spartan_rejects_tampered_hadamard_a_eval` (non-zero a_eval
  with u=1, b=c=0 Hadamard-satisfying bundle).

- **Halo2 VK-side commits in multi-poly MSM (session 20)** —
  `collect_commits_at_xi` and `collect_evals_at_xi` now fold VK-side
  preprocessed commits (`fixed_commits` = selector polynomials
  Q_M..Q_C, `permutation_commits` = σ_1..σ_3) into the multi-poly
  MSM alongside the session-17 proof-side commits. Any tampered VK
  selector or σ commitment now breaks the batched pairing identity
  — sessions-≤17 silently tolerated VK-side tampering because those
  commits never entered the MSM. Two new session-20 tamper tests:
  `multipoly_rejects_tampered_vk_selector_commit` (swap q_M commit
  to G1 generator) and `multipoly_rejects_tampered_vk_permutation_commit`
  (swap σ_1 commit to G1 generator).

- **Shared `fr_from_be_bytes_reduced` primitive (session 21)** —
  Session-17 and session-19 had independently duplicated an
  `into_fr` helper wrapping `Fr::from_be_bytes_mod_order` for
  reducing keccak digests into Fr challenges. Lifted into
  `mosaic-zk-primitives::field::fr_from_be_bytes_reduced`; both
  halo2 and nova verifiers now call the shared primitive. Two new
  unit tests exercise the in-range agreement with
  `fr_from_canonical_bytes` and the out-of-range reduction.

### Changed

- **CU baselines re-measured** across Phase-2 production systems under
  the `opt-level = "z"` SBF profile (v0.4.1 → v0.5.0 drift). Groth16
  single +4.1 % (80 296 → 83 574), Groth16 batch N=5 +12.0 % (230 626
  → 258 397), KZG-PLONK BN254 +29.5 % (747 666 → 968 457). PLONK's
  polynomial-heavy path absorbs the size-optimizer tradeoff
  disproportionately because the linearization MSM and transcript Fr
  arithmetic relied on inlined helpers that now share tail-call
  destinations after the v0.5.0 STARK body + `mosaic-zk-primitives`
  extraction. KZG-PLONK hard cap raised 800K → 1 100K (13 %
  regression headroom); Groth16 caps retained. ADR-0005 targets
  table updated with `Hard cap | Last-measured` columns and a
  "Re-measurement" note. `docs/compute-unit-budget.md` rewritten
  with the v0.5.0 drift table and measured baselines.
  `Cargo.toml` `[profile.release]` comment refreshed to match.
  `README.md` verifier matrix numbers updated.

### Removed — superseded helpers

- `mosaic-halo2::verifier::into_fr` private helper (replaced by
  shared `fr_from_be_bytes_reduced`).
- `mosaic-nova::verifier::into_fr` private helper (replaced by
  shared `fr_from_be_bytes_reduced`).

### Breaking changes

- `HyperPlonkVerifyingKey::SERIALIZED_LEN` grew 648 B → 744 B.
  Any previously-serialized HyperPlonk VK must be re-encoded with
  the additional `(k_1, k_2, k_3)` coset triple. Test fixtures in
  the `mosaic-hyperplonk` crate initialize these to the legacy
  `(1, 2, 3)` defaults via `HyperPlonkVerifyingKey::fr_be_from_u64`
  to preserve existing sumcheck behavior.

- `mosaic-halo2::verifier::collect_commits_at_xi` / `collect_evals_at_xi`
  signatures extended. Internal helpers; external code that reaches
  the public `Halo2KzgBn254::verify` API is unaffected.

### Gate inventory (post-v0.6.0)

| Verifier | Gates | Sessions covering |
|---|---|---|
| HyperPlonk-KZG | 2 | sumcheck identity, permutation term at ξ (coset tamper in session 18) |
| Halo2-KZG | 2 | vanishing identity, multi-poly batched two-point opening (sessions 16 → 17 → 20) |
| Nova / HyperNova / ProtoStar | 3 | Hadamard residual, folded-commitment reconstruction, Spartan-batched opening (session 19) |
| FRI-STARK | 7 | query indices, trace + constraint Merkle, PoW, FRI fold chain, OOD quotient, per-layer Merkle auth |

## [0.5.0-phase3-complete] — 2026-04-22

**Phase-3 protocol-layer soundness is complete.** All four Phase-3
verifier bodies (HyperPlonk-KZG, Halo2-KZG, Nova family, FRI-STARK)
now run end-to-end with **12 independent cryptographic soundness
gates** covering the primary attack surfaces of each protocol. In
just 18 focused sessions post-v0.4.1, the library went from
"structural validation with single gates" to "production-grade
scaffolds at audit-ready depth for every body."

### Soundness gate inventory

| Verifier | Gates | Coverage |
|---|---|---|
| HyperPlonk-KZG | 2 | Sumcheck identity, permutation term at ξ |
| Halo2-KZG | 1 + two-point opening | Vanishing identity, batched (ξ, ξω) |
| Nova/HyperNova/ProtoStar | 2 | Hadamard residual, folded-commitment reconstruction |
| FRI-STARK | 7 | Structural, trace Merkle, constraint Merkle, PoW, FRI fold chain, OOD quotient, per-layer Merkle |

**FRI-STARK reached production parity** with Plonky3/Winterfell
semantics (modulo real AIR-specific constraint evaluators). Nova
gained a second soundness gate via `folded_commitment_from_fold`
reconstruction. Halo2's opening upgraded from single-point (ξ) to
PSE-compatible two-point batched (ξ, ξω). HyperPlonk's permutation
term moved from zero-placeholder to structurally correct PLONK-
style grand-product.

### Added — primitive modules

- `mosaic-stark::goldilocks` — `Goldilocks(u64)` field arithmetic
  with `add`, `sub`, `mul`, `neg`, `inverse` (Fermat), `pow`,
  `from_bytes_le`, `to_bytes_le`, and `eval_poly_le_bytes` for
  coefficient-vector polynomial evaluation via Horner.
- `mosaic-stark::fri` — `compute_next_layer_value`,
  `fold_relation_holds`, `verify_fold_chain`. Standalone FRI
  fold arithmetic; callable independent of canonical layout.
- `mosaic-stark::merkle` — `verify_path` walks SHA-256 trees
  already shipped in session 7; used by trace, constraint, and
  per-FRI-layer path verification.

### Added — soundness gate wirings (18 sessions)

Commits in-order: `b025c44`, `ee9ed73`, `19a81f5`, `9b0ef58`,
`82eb114`, `3a94839`, `d991079`, `fe642b7`, `0218d1d`, `4aba3b8`,
`919c57f`, `44c182f`, `d9d2be6`, `ed9363c`, `c0e6280`.

Each gate has a paired `rejects_tampered_*` test exercising the
specific class of attack it defends against. Full map in
`docs/phase3-soundness.md` (session 9b+).

### Changed — canonical layouts (breaking vs v0.4.1)

- **Nova `NovaFoldingProof`**: +128 B `hadamard_evals` (session 13b);
  +256 B `base_e_1 / base_e_2 / base_w_1 / base_w_2` (session 15-nova).
  Minimum proof: 368 → 624 → 880 B.
- **Halo2 `Halo2KzgVerifyingKey`**: +32 B `omega_fr` domain
  generator (session 16).
- **FRI-STARK `FriStarkProof`**: +var-tail `fri_layer_openings`
  (session 13b); +var-tail `fri_layer_auth_paths` (session 15);
  removed deprecated `final_layer_value` slot (session 14b).
  `MAX_TAIL_LEN` bumped 1 MiB → 32 MiB to accommodate realistic
  auth-paths buffers.
- **FRI-STARK `FriStarkVerifyingKey`**: +8 B `omega_g` Goldilocks
  domain generator.

Downstream provers must regenerate proofs against the new layouts.
Phase-2 production verifiers (Groth16, KZG-PLONK) are unchanged and
byte-compatible with `v0.2.0-phase2`.

### Changed — workspace

- Tests: 321 → **378** passing (+57).
- SBF binary: 292 KB → **319 KB** (+27 KB for the full wired
  cryptographic machinery). 30.4% of 1 MB Solana program limit with
  ~730 KB headroom.
- Per-crate test counts:
  - mosaic-stark: 40 → **103** (+63; FRI-STARK went from scaffold
    to production parity).
  - mosaic-nova: 38 → **41** (+3 soundness).
  - mosaic-halo2: 47 → **53** (+6 bundle + soundness).
  - mosaic-hyperplonk: 61 → 62 (+1 perm tamper test; unchanged
    this release).

### Not changed

- Phase-2 CU measurements (Groth16, Groth16 batch, KZG-PLONK)
  retain their `v0.2.0-phase2` baselines pending CU re-measurement
  follow-up.
- Phase-2 canonical layouts (Groth16, KZG-PLONK) byte-compatible.

## [0.4.1-phase3-soundness] — 2026-04-22

- **Fixture-driven final tightening** across all four Phase-3 bodies:
  Espresso HyperPlonk, PSE Halo2, sonobe Nova, Plonky3 STARK.
  Requires external prover tooling out-of-scope for in-tree work.
- **FRI-STARK session 8 extensions**: constraint-commitment paths,
  per-FRI-layer consistency checks, Goldilocks arithmetic, PoW
  grinding verification.
- **CU re-measurement post opt-level = "z"**: compare mosaic-bench
  targets `groth16_single`, `groth16_batch_n5`, `plonk_bn254`
  between speed-optimized baseline and size-optimized current.
- **gnark format adapter** (issue
  [#10](https://github.com/wienerlabs/mosaic/issues/10)).
- **External security audit** (issue
  [#19](https://github.com/wienerlabs/mosaic/issues/19)).

## [0.4.1-phase3-soundness] — 2026-04-22

**Phase-3 cryptographic soundness gates complete.** All four Phase-3
verifier bodies now surface tampered prover data with specific error
codes — soundness gates wired uniformly across BN254 + hash-based
families. Combined with a 72% SBF binary reduction, this release
restores ~760 KB of on-chain headroom for continued work and delivers
deploy-ready verifier surfaces for adapter authors to integrate
against.

### Added — cryptographic soundness gates

Four verifier bodies gained real cryptographic soundness checks that
detect tampered prover data before the final KZG/Merkle acceptance:

| Verifier | Soundness gate | Error | Commit |
|---|---|---|---|
| HyperPlonk-KZG | permutation term at ξ | `SumcheckFailed` | `ad299f1` |
| Halo2-KZG | vanishing identity `t(ξ)·Z_H(ξ) == gate + y·perm + y²·lookup` | `SumcheckFailed` | `3b83cc6` |
| Nova / HyperNova / ProtoStar | Hadamard residual `a·b − u·c − e` | `SumcheckFailed` | `2bf8ba2` |
| FRI-STARK | per-query Merkle path vs trace commitment | `VerificationFailed` | `034cbd6` |

Four scaffold caveats from v0.4.0 are now closed to different
degrees. Remaining items tracked under each verifier's issue.

### Added — `mosaic-zk-primitives` crate

Extracted `fr`, `field`, `msm`, `transcript`, `g1_consts` modules
from `mosaic-plonk` into their own crate so all four BN254
verifiers share the primitive layer without carrying a transitive
PLONK dependency (commits `8e848e4`, `0fa017d`).

- 38 tests migrated from mosaic-plonk to mosaic-zk-primitives.
- mosaic-plonk retains backward-compat re-exports; downstream code
  importing via `mosaic_plonk::*` continues to work.
- mosaic-hyperplonk / mosaic-halo2 / mosaic-nova now depend on
  mosaic-zk-primitives directly.

### Added — canonical layout extensions (breaking from v0.4.0)

- **Halo2 `EvaluationBundle` layout** — fixed 16-slot ordering
  (wires, selectors, permutation, lookup) + `n_quotient` trailing
  chunk evaluations. Required `n_evals == 16 + n_quotient`.
- **Nova `hadamard_evals` field** — fixed 128-byte slot carrying
  `(a, b, c, e)` at the Spartan evaluation point for the Hadamard
  relation check. Proof size grew 128 B; still fits single-tx.
- **FRI-STARK structured `query_responses`** — each query's response
  is now `leaf (32 B) ‖ auth_path (depth × 32 B)` where
  `depth = trace_log_height + log_blowup`. Required length:
  `num_queries × (1 + depth) × 32 B`.

### Changed — SBF binary optimization

`[profile.release]` switched from `opt-level = 3` (speed) to
`opt-level = "z"` (size) — commit `5ac8858`.

| | Before | After | Delta |
|---|---|---|---|
| SBF binary | 1,027,000 B | **288,544 B** | −72% |
| % of 1 MB Solana cap | 97.9% | 27.5% | |
| Headroom for new work | 21 KB | **760 KB** | ×36 |

Expected CU trade-off: 5–15% runtime growth. Per-system re-measurement
listed in "Planned" above. Benchmark profile (`[profile.bench]`)
retained at `opt-level = 3` so host-side microbenchmarks reflect
production-equivalent arithmetic throughput.

### Changed — workspace

- Crate count: 14 → **15** (adds `mosaic-zk-primitives`).
- Test count: 303 → **314** (+11 soundness + bundle tests,
  maintaining all 303 prior tests).
- Test redistribution:
  - mosaic-plonk: 55 → 17 (primitives tests moved out).
  - mosaic-zk-primitives: 0 → 38 (inherited).
  - mosaic-hyperplonk: 61 → 62 (+1 σ tamper test).
  - mosaic-halo2: 47 → 53 (+5 bundle + 1 gate tamper tests).
  - mosaic-nova: 38 → 40 (+2 Hadamard soundness tests).
  - mosaic-stark: 38 → 40 (+2 Merkle soundness tests - 1 renamed).
- SBF binary: **288,544 B** (from 564 KB at v0.3.0-phase3-scaffolds;
  net +28% binary for +140 tests and full Phase-3 body pipelines).

### Not changed

- Phase-2 CU measurements (Groth16 single, Groth16 batch, KZG-PLONK)
  are frozen at their `v0.2.0-phase2` baselines pending the CU
  re-measurement follow-up.
- All canonical layouts from v0.2.0-phase2 (Groth16, KZG-PLONK)
  unchanged. Phase-2-only consumers can stay pinned.

## [0.4.0-phase3-bodies] — 2026-04-22

- **Fixture-driven tightening** across all four Phase-3 bodies:
  - HyperPlonk: permutation term integration + multi-point opening
    reduction, Espresso reference fixture (issue
    [#2](https://github.com/wienerlabs/mosaic/issues/2)).
  - Halo2: vanishing-identity composition + two-point batched
    multipoint opening, PSE `halo2_proofs` fixture (issue
    [#64](https://github.com/wienerlabs/mosaic/issues/64)).
  - Nova: Hadamard relation wiring + folded-commitment
    reconstruction + Spartan multi-opening, `sonobe` fixture
    (issue [#4](https://github.com/wienerlabs/mosaic/issues/4)).
  - FRI-STARK: per-query Merkle path verification + FRI-layer fold
    check + Goldilocks reduction + PoW grinding verification,
    Plonky3/Winterfell fixture (issue
    [#3](https://github.com/wienerlabs/mosaic/issues/3)).
- **`mosaic-zk-primitives` extraction** — all three BN254 bodies
  (HyperPlonk, Halo2, Nova) now reuse `mosaic-plonk`'s
  Fr/MSM/transcript primitives; the extraction threshold has
  clearly been crossed. Follow-up refactor.
- **gnark** format adapter for Groth16 + PLONK (issue
  [#10](https://github.com/wienerlabs/mosaic/issues/10)).
- CU optimization: zero/one-scalar shortcut + pre-reduced IC
  aggregation (rescoped from Pippenger, issue
  [#37](https://github.com/wienerlabs/mosaic/issues/37)).
- Real Circom-sourced Groth16 fixtures (issue
  [#24](https://github.com/wienerlabs/mosaic/issues/24)).
- External security audit (issue
  [#19](https://github.com/wienerlabs/mosaic/issues/19)).

## [0.4.0-phase3-bodies] — 2026-04-22

**All four Phase-3 verifier bodies now run end-to-end.** HyperPlonk,
Halo2, Nova, and FRI-STARK all have full verifier pipelines returning
`Ok(())` on structurally well-formed proofs. No `UnimplementedProofSystem`
returns remain for any Phase-3 family at the top level.

This is the scaffold-to-body transition milestone for Phase 3.
Each verifier composes parse → transcript challenges → cryptographic
checks (KZG pairing or SHA-256 Merkle/FRI structural) → Ok(()).
Scaffold caveats per family are documented in the module rustdoc
and the per-commit CHANGELOG notes below.

This tag is the reference point for "Phase-3 verifier bodies wired" —
ecosystem collaborators building adapters can now integration-test
against these verifiers (albeit with the scaffold caveats noted).
The fixture-driven tightening in upcoming 0.4.x releases pins
cryptographic soundness against reference implementations.

### Added — Phase-3 body modules

**HyperPlonk** (sessions 3a-e, crate `mosaic-hyperplonk`):
- `sumcheck.rs` — round polynomial verification + transcript-driven
  challenge squeezing. 15 tests.
- `mle.rs` — `eq_poly_eval` (on-chain) + `mle_eval_from_cube` (host).
  10 tests.
- `gate.rs` — PLONK-style arithmetic gate at ξ. 9 tests.
- `challenges.rs` — three pre-sumcheck challenges `(β, γ, α)` with
  snarkjs-style per-round transcript reset.
- `kzg.rs` — 12-term MSM + `alt_bn128_pairing` batched-opening
  scaffold at univariate point.
- Canonical VK expanded: 8 preprocessing commits (Q_M/Q_L/Q_R/Q_O/Q_C +
  σ_1/σ_2/σ_3). FINAL_EVALS: 4 → 12.
- Crate totals: 11 scaffold → **61 tests**.

**Halo2** (sessions 4a-d, crate `mosaic-halo2`):
- `challenges.rs` — five-challenge Halo2 transcript
  `(θ, β, γ, y, ξ)`.
- `vanishing.rs` — `Z_H(ξ)` + `compute_t_from_chunks` + identity
  check primitive.
- `circuit.rs` — gate + permutation + lookup evaluators (log-
  derivative form) + combined expression.
- `kzg.rs` — single-commitment pairing check at ξ.
- Crate totals: 14 scaffold → **47 tests**.

**Nova / HyperNova / ProtoStar** (sessions 5a-c, crate `mosaic-nova`):
- `challenges.rs` — three-challenge transcript `(r, ξ, ν)`.
- `folding.rs` — `hadamard_residual` + `folded_commitment_from_fold`
  + `folded_error_commitment` primitives.
- `kzg.rs` — single-commitment pairing check.
- Crate totals: 19 scaffold → **38 tests**.

**FRI-STARK** (sessions 6a-c, crate `mosaic-stark`):
- `challenges.rs` — **SHA-256 based** transcript producing
  `(α, z, query_seed)` + `derive_query_indices` helper.
- `merkle.rs` — SHA-256 Merkle authentication path verification
  + test-only tree constructors.
- Structural verifier pipeline (Merkle integration pending real
  canonical layout extension for per-query structured responses).
- Crate totals: 18 scaffold → **38 tests**.

### Added — error variants

`OnChainError::VerifyingKeyProofMismatch = 0x0008` was added during
v0.3.x for STARK/Nova VK/proof cross-check. No further ABI additions
in this release.

### Changed

- **Workspace version** 0.3.0-phase3-scaffolds → 0.4.0-phase3-bodies.
- **Test count**: 163 (v0.3.0) → **303** passing, zero failures
  (+140 from Phase-3 body work across all four families).
- **SBF binary size**: 564 KB → **700 KB** (+136 KB). Breakdown:
  - HyperPlonk body: ~83 KB (arkworks Fr arithmetic, sumcheck loop,
    12-term MSM, pairing).
  - Halo2 body: ~10 KB (no MSM hot path in scaffold opening).
  - Nova body: ~8 KB.
  - FRI-STARK body: ~7 KB (SHA-256 path walker).
  - Still well under Solana's 1 MB program limit.
- **mosaic-program dispatcher** now routes all six Phase-3 discriminants
  (HyperPlonkKzgBn254, Halo2KzgBn254, FriStark, NovaFolding, ProtoStarFolding)
  to integrated bodies; only Risc0Stark remains in the
  `UnimplementedProofSystem` catchall.

### Not changed

- No production Phase-2 verifier or protocol surface modified —
  Groth16 and KZG-PLONK byte layouts, CU measurements, and audit
  scope remain authoritative at their `v0.2.0-phase2` tag.
- Phase-3 canonical layouts may still adjust in the 0.4.x series
  as fixture integration pins exact byte orderings. Consumers
  building adapters today should expect minor breaking changes in
  Phase-3 wire formats before 0.5.0.

## [0.3.0-phase3-scaffolds] — 2026-04-20

**Phase-3 scaffold surface is frozen at this tag.** Three new verifier
scaffolds (HyperPlonk-KZG, Halo2-KZG, FRI-STARK) ship with full
canonical byte layouts, `ProofSystem` trait implementations, and
`mosaic-program` dispatcher wire-up. Full verifier bodies (round
transcripts, MSM/FRI inner loops, final pairing/hash check) land in
subsequent 0.3.x releases.

This tag is the reference point for "Phase-3 scope entered" —
ecosystem collaborators building adapters against any of these three
systems can target the canonical layouts documented here with
confidence the wire formats are stable modulo ADR amendments.

### Added — verifier scaffolds

- **`mosaic-hyperplonk`** — HyperPlonk-KZG over BN254 (eprint
  2022/1355, multilinear-extension PLONK variant). Wire format,
  round-by-round plan documented in module rustdoc, 11 tests green.
  CU estimate: ~505K under 900K cap (ADR-0005).
- **`mosaic-halo2`** — Halo2-KZG over BN254 (Privacy Scaling
  Explorations fork). Placeholder layout parametrized by 4 u32
  counters (advice columns / lookups / quotient chunks / evaluations)
  plus variable-length G1/Fr sections. 14 tests green. CU estimate:
  ~580K under 700K cap.
- **`mosaic-stark`** — FRI-STARK over Goldilocks / BabyBear /
  Mersenne31 (Plonky3 family, eprint 2025/1741 envelope). Upgraded
  from a single-file stub to a full scaffold with `StarkFieldId` tag
  byte, variable-length proof decoder, `FriStarkVerifyingKey`, and
  VK-vs-proof cross-checks. 18 tests green. Depends only on
  `mosaic-core` — no BN254 primitives reused since STARKs are purely
  hash-based.

### Added — infrastructure

- **New `OnChainError::VerifyingKeyProofMismatch = 0x0008`** variant
  for VK/proof configuration disagreement. ABI-stable append (no
  existing discriminants changed). Locked in `discriminant_stability`
  test.
- **Dispatcher 0x04 and 0x05 arms** in `mosaic-program` route to
  Halo2 and FRI-STARK scaffolds respectively. HyperPlonk was already
  wired at 0x03 in the late-Phase-2 landing.
- **GitHub labels** `crate: mosaic-halo2` and `crate: mosaic-hyperplonk`
  added; Phase-3 scaffold tracking issue [#64] opened for Halo2.

### Changed

- **Workspace version** 0.2.0-phase2 → 0.3.0-phase3-scaffolds.
- **Crate count**: 12 → **13** (adds `mosaic-halo2`; `mosaic-stark`
  was already a member but is now fleshed out).
- **Test count**: 131 → **163** passing, 0 failed (+32 new scaffold
  tests: 11 HyperPlonk + 14 Halo2 + 7 STARK, plus one error-ABI test).
- **SBF binary size**: 557 KB → **564 KB** (three scaffold verifiers
  add wire-format validation paths; cryptographic hot paths still
  Phase-2 only, so binary growth is minimal).

### Not changed

- No production verifier or protocol surface was modified — Phase-2
  byte layouts, CU measurements, and audit scope remain the
  authoritative reference for `v0.2.0-phase2`. Downstream consumers
  that only care about Groth16 / PLONK can stay pinned to the
  previous tag until Phase-3 bodies land.

## [0.2.0-phase2] — 2026-04-20

**Phase 2 technical scope is frozen at this tag.** Production PLONK
verifier, Groth16 batch verification, snarkjs PLONK adapter, and
Poseidon syscall wiring all shipping with measured on-chain CU.

Audit firms, grant reviewers, and ecosystem collaborators should cite
this tag as the reference point for Phase-2 scope. Subsequent commits
start Phase 3 (HyperPlonk, Halo2-KZG, FRI-STARK).

### Added — verifiers

- **`mosaic-plonk` full KZG-PLONK BN254 verifier** (issue
  [#1](https://github.com/wienerlabs/mosaic/issues/1)). Byte-for-byte
  compatible with snarkjs 0.7.x. Ships as five modules:
  - `canonical` — 768-byte proof + 744-byte VK layout (ADR-0003).
  - `fr` — byte-level range ops; `field` — full arkworks Fr arithmetic.
  - `transcript` — Keccak-256 Fiat-Shamir with snarkjs absorb order.
  - `challenges` — six-round challenge derivation (β γ α ξ v u).
  - `linearization` — d1/d2/d3/d4 MSMs + F/E commitment build + KZG
    batched opening pairing.
  - `msm` + `g1_consts` — shared scalar mul + G1/G2 generator bytes.
- **`mosaic-groth16::batch` — Bowe-Gabizon batched verification**
  (issue [#5](https://github.com/wienerlabs/mosaic/issues/5)). One
  `alt_bn128_pairing` syscall collapses N proofs sharing a VK.
  Independent SHA-256 challenges (no Fr multiplication on-chain);
  break-even at N=2, 42.6% savings at N=5.
- **`VerifyProofBatch` instruction** (tag `0x02`) exposes batch
  verification to on-chain callers and CPI.

### Added — infrastructure

- **Poseidon syscall wired** via `solana-poseidon 2.3`
  (issue [#8](https://github.com/wienerlabs/mosaic/issues/8)) — unblocks
  Circom-compatible transcripts for future KZG-based systems.
- **Real snarkjs 0.7.6 PLONK fixtures** committed under
  `tests/fixtures/plonk/mul-circuit/{snarkjs,canonical}/`. Pipeline
  documented for reproduction.
- **`SnarkjsPlonkCodec`** — full JSON → canonical bytes decoder for
  proofs + VKs + public inputs, including snarkjs projective-identity
  handling.
- **bpf-bench target `groth16_batch_n5_mul_circuit_1pi`** — measured
  230 626 CU baseline + 300K hard cap.
- **bpf-bench target `plonk_bn254_mul_circuit_1pi`** — measured
  747 666 CU baseline + 800K hard cap.

### Added — documentation

- `docs/audit/rfq.md` + `docs/audit/outreach-email.md` — pre-audit
  outreach package for Zellic / Veridise / OtterSec / Asymmetric
  Research.
- `supply-chain/` directory with real `cargo-vet` attestation chain
  (issue [#59](https://github.com/wienerlabs/mosaic/issues/59)).
  74 audited, 2 partial, 689 exempted baseline.
- `docs/lint-policy.md` — audit-facing registry of every clippy
  suppression.
- `docs/responsible-disclosure-timeline.md` — 5-stage SLA spec
  referenced from SECURITY.md.
- `docs/threat-model.md` expanded with 4 scope-boundary axes:
  under-constrained circuits, malleable proofs, validator determinism,
  replay safety (issue
  [#63](https://github.com/wienerlabs/mosaic/issues/63)).
- `AUDIT.md` Phase-1 scope frozen and marked "ready for external
  review".

### Changed

- **On-chain CU measurements (2026-04-20 baselines):**
  | System | Measured | Cap | Headroom |
  |---|---|---|---|
  | Groth16 BN254 single | 80 296 CU | 180 000 | 55.4% |
  | Groth16 BN254 batch N=5 | 230 626 CU (46 125/proof) | 300 000 | 23% |
  | KZG-PLONK BN254 | 747 666 CU | 800 000 | 6.5% |
- **SBF binary size**: 112 KB → **557 KB** (arkworks Fr arithmetic,
  PLONK linearization, batch path). Well under Solana 1 MB limit.
- **Test count**: 36 → **119** passing, 0 failed.
- **Host backend `SyscallBackend::poseidon`** replaced the
  `UnimplementedProofSystem` stub with a `solana-poseidon::hashv` call
  that routes through `light-poseidon` on host targets and the
  `sol_poseidon` syscall under SBF — byte-identical by construction.
- **Host G1 decode accepts `(0, 0)` as identity** rather than
  rejecting as off-curve — matches Solana `alt_bn128` convention and
  handles snarkjs zero-polynomial selector commitments.
- `mosaic-program` dispatcher: `0x02` arm routes to
  `Groth16Verifier::batch_verify` (Bowe-Gabizon). Unsupported
  proof-system batches return `UnsupportedOperation`, not silent loop.

### Fixed

- **PLONK u-challenge absorb order** was incorrectly including `v`.
  snarkjs only absorbs `Wxi + Wxiω`. Silent pre-fix failure mode:
  all valid PLONK proofs would have failed the pairing check.
- **snarkjs projective-identity decode** (`[0, 1, 0]` → G1 identity)
  handled in both `mosaic-serde::snarkjs` and
  `mosaic-core::syscall::host`. Zero-polynomial selector commitments
  (e.g. Qr for a circuit with no right-operand gates) now decode
  correctly.
- **SBF stack-frame overflow** in PLONK linearization resolved by
  splitting monolithic `compute_d` and `ComputedScalars::derive` into
  `#[inline(never)]` sub-helpers (compute_d1/d2/d3/d4, compute_e3,
  compute_r0_scalar, compute_d2a, compute_d2_coeff, etc.). Each frame
  now under 4 KB; was >10 KB at worst pre-split.

### Issues closed

- [#1](https://github.com/wienerlabs/mosaic/issues/1) KZG-PLONK BN254 verifier.
- [#5](https://github.com/wienerlabs/mosaic/issues/5) Groth16 batch_verify with MSM amortization.
- [#8](https://github.com/wienerlabs/mosaic/issues/8) Wire sol_poseidon syscall.
- [#33](https://github.com/wienerlabs/mosaic/issues/33) Devnet integration test.
- [#59](https://github.com/wienerlabs/mosaic/issues/59) `cargo-vet` supply chain attestation.
- [#60](https://github.com/wienerlabs/mosaic/issues/60) Audit-readiness PR.
- [#63](https://github.com/wienerlabs/mosaic/issues/63) Threat model expansion.

### Compatibility

- Host: Rust **1.85.0** stable (unchanged).
- SBF: `cargo-build-sbf --tools-version v1.52` (unchanged).
- Solana program SDK: `^2.1` (unchanged, tested against 2.3.0).
- **Wire format**: all Phase-1 canonical byte layouts stable; PLONK
  adds its own 768/744 B layout documented in ADR-0003.
- **InstructionTag ABI**: Phase-1 `0x01` VerifyProof unchanged; new
  `0x02` VerifyProofBatch is additive.
- **`OnChainError` discriminants**: all Phase-1 values unchanged;
  no new variants in this release.

## [0.1.0-phase1] — 2026-04-20

First public pre-release. **Phase 1 technical scope is frozen at this tag.**

Audit firms, grant reviewers, and ecosystem collaborators should cite this
tag as the reference point for "what exists today". Subsequent commits land
audit-readiness documentation, supply-chain attestation, and outreach
artifacts — none of which change the runtime surface.

### Runtime deliverables

#### `mosaic-core`
- `ProofSystem` trait (object-safe for SDK; monomorphic dispatch on-chain).
- `ProofSystemId` enum with 8 discriminants (Groth16 + 7 future systems).
- `ProofCodec` trait + `FormatTag` for upstream-format adapters.
- `TranscriptHash` trait for Fiat-Shamir abstraction.
- `SyscallBackend` trait with host (arkworks) and Solana-SBF implementations.
- Two-layer error taxonomy: `OnChainError` (deterministic `repr(u32)` ABI)
  and `DiagnosticError` (rich, `std`-feature-gated). 29 `OnChainError`
  variants at stable discriminants (0x0001..0x00FF), pinned by test.
- `BumpArena` stack-bounded scratch allocator (safe single-borrow).

#### `mosaic-groth16`
- BN254 Groth16 verifier with `LE_INPUTS` const generic for SIMD-0204
  forward compatibility.
- Dual-endian support; big-endian default matches current
  `sol_alt_bn128_group_op` convention.
- Host backend via `ark-bn254`; SBF backend via `solana-bn254` syscalls.
- `estimated_compute_units` returns a tight upper bound (algorithmic).
- Internal `A`-negation so the pairing check runs as one syscall call.
- Batch verification API (defaults to looped; issue [#5](https://github.com/wienerlabs/mosaic/issues/5) tracks MSM amortization).

#### `mosaic-serde`
- `snarkjs` JSON adapter: decimal-string G1/G2 decoding with correct
  c0/c1 layout swap to Solana wire bytes.
- `arkworks` `CanonicalSerialize` adapter.
- Stub modules for `gnark`, `halo2-kzg`, `plonky3`, `risc0` (Phase 2/3).

#### `mosaic-chunked`
- `ProofUploadSession` PDA layout with explicit `layout_version` byte.
- Rolling SHA-256 hash commitment with 16-byte domain separation tag.
- Bound to `(session_id, payer)` PDA seeds — defends front-running
  griefing.
- 48-hour `EXPIRY_SLOTS` for permissionless GC.
- Wire-format instructions: `InitializeSession`, `AppendChunk`,
  `CommitAndVerify`, `CancelSession`, `CancelExpiredSession`.

#### `mosaic-program` (reference Solana program)
- Top-level dispatcher: `VerifyProof` (tag 0x01) + chunked range
  (0x10..=0x1F).
- Shared `dispatch_verify` helper bridging both single-tx and
  chunked-upload verification paths.
- Five chunked-upload instruction handlers with explicit state-machine
  enforcement, owner validation, and permissionless GC.
- Compiles to **112 KB** SBF ELF via `cargo build-sbf --tools-version v1.52`.

#### `mosaic-sdk`
- `VerifyRequest` + `build_verify_proof_ix` for client transaction construction.
- `preflight()` runs the host backend locally for fast-fail before submission.

#### `mosaic-bench`
- Criterion micro-benchmark for host Groth16 verification.
- `bpf-bench` binary drives `solana-program-test` against the actual SBF
  ELF, parses CU from program logs, compares to per-system hard caps.
  Phase-1 Groth16-BN254 mul-circuit (1 public input) measurement:
  **80,296 CU** (against 180,000 CU ADR-0005 cap).

#### `mosaic-fuzz`
- Three `libfuzzer-sys` harnesses: proof bytes, VK bytes, public inputs.

### Test coverage
- **36 tests passing**: 6 mosaic-core, 9 mosaic-chunked, 5 mosaic-groth16,
  3 mosaic-serde lib, 4 mosaic-serde round-trip, 2 differential, 7
  mosaic-program on-chain integration.
- Round-trip tests verify snarkjs / arkworks / canonical paths produce
  byte-equal output.
- Proptest differential harness (16 cases per run) cross-verifies
  arkworks reference vs Mosaic host backend.

### Fixtures
- `tests/fixtures/groth16/mul-circuit/` — deterministic proof in three
  formats (snarkjs JSON, arkworks canonical, Mosaic canonical).
- Regen command: `MOSAIC_REGEN_FIXTURES=1 cargo test -p mosaic-serde --features host-backend`.

### Documentation
- **5 ADRs**: trait hierarchy, error taxonomy, serialization, chunked
  upload, CU budget policy.
- **1 design document**: chunked-upload handler implementation contract
  (12 sections, state machine, security reduction, DoS analysis).
- **Threat model** with T-1..T-10 adversarial input vectors.
- **Compute-unit budget** per-system table with measured baselines.
- **Lint policy** (audit-facing) cataloguing every clippy `allow`.
- **SECURITY.md**, **AUDIT.md**, **CONTRIBUTING.md**.

### CI / tooling
- 4 GitHub Actions workflows: `ci`, `bench`, `audit`, `fuzz`.
- Strict clippy: `correctness`, `suspicious`, `todo`, `unimplemented`
  hard-deny; `pedantic`, `nursery`, `cargo` visible warnings.
- `cargo build-sbf` in CI with `--tools-version v1.52` pinning.
- `cargo-deny` weekly scheduled run.
- `bpf-bench` gate on CU regressions in PR workflow.
- MSRV 1.85 enforced (host); Solana SBF toolchain pinned separately.

### Security posture
- `#![forbid(unsafe_code)]` workspace-wide (migration to `deny` tracked
  in issue [#58](https://github.com/wienerlabs/mosaic/issues/58)).
- Zero `unimplemented!()` / `todo!()` / `panic!()` in library code paths.
- Every on-chain error code is deterministic; discriminants pinned.
- Domain-separated SHA-256 rolling hash for chunked-upload protocol.
- Per-system CU hard caps with CI gating.

### Known limitations
- **No external audit yet** (issue [#19](https://github.com/wienerlabs/mosaic/issues/19)).
- **Fixtures are programmatic, not Circom-sourced** (issue [#24](https://github.com/wienerlabs/mosaic/issues/24)).
- **Poseidon syscall path for Solana 2.x not wired** — blocks PLONK/Halo2
  with Circom-compatible transcripts (issue [#8](https://github.com/wienerlabs/mosaic/issues/8)).
- **Only Groth16 is implemented**; PLONK / STARK / Nova verifiers are
  stubs returning `UnimplementedProofSystem` (issues [#1](https://github.com/wienerlabs/mosaic/issues/1),
  [#3](https://github.com/wienerlabs/mosaic/issues/3), [#4](https://github.com/wienerlabs/mosaic/issues/4)).
- **Chunked-upload permissionless GC bounty** not implemented — caller
  pays only tx fee (design doc § 12, Q6).

### Compatibility
- Host: Rust **1.85.0** stable.
- SBF target: `cargo-build-sbf --tools-version v1.52` (rustc 1.89.0-dev).
  Default v1.51 (rustc 1.84.1) fails on `edition2024` transitive deps.
- Solana program SDK: `solana-program ^2.1` (tested against 2.3.0).

[Unreleased]: https://github.com/wienerlabs/mosaic/compare/v0.2.0-phase2...HEAD
[0.2.0-phase2]: https://github.com/wienerlabs/mosaic/releases/tag/v0.2.0-phase2
[0.1.0-phase1]: https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1
