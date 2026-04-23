# Changelog

All notable changes to Mosaic are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
  bytes for small integer cosets — all test VK fixtures initialize
  `(k_1, k_2, k_3)` with it to preserve existing sumcheck behavior.
  New session-18 unit tests:
  `permutation_term_depends_on_k_cosets` (distinct triples yield
  distinct perm_term values) and `tampered_k_1_breaks_expected_claim`
  (swapping `vk.k_1` produces a different final claim).

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
  transcript state + opening-proof bytes. `docs/phase3-soundness.md`
  extended with session-17 primitive + tamper-test map. Halo2 is
  now at **2 gates** (vanishing identity + multi-poly batched
  opening), bringing the project-wide gate count from 12 → 13.

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

### Planned beyond v0.5.0-phase3-complete

- **Fixture-driven differential testing** across all four Phase-3
  bodies (Espresso HyperPlonk, PSE Halo2, sonobe Nova, Plonky3 STARK).
  Requires external prover tooling; closes cryptographic soundness
  verification beyond in-tree scaffold construction.
- **HyperPlonk multi-point KZG reduction** — Zeromorph / Pst /
  Gemini univariate reduction in `kzg.rs` remains a scaffold
  shortcut (uses last sumcheck challenge as univariate point). The
  session-18 VK-side `k_i` cosets tighten the permutation argument;
  the multi-point → univariate reduction itself pins in a future
  session against Espresso's reference impl.
- **Nova Spartan-batched multi-poly opening** — current scaffold
  opens `w_comm` only; full version covers (A·z, B·z, C·z) + E + W.
- **External security audit** (issue [#19](https://github.com/wienerlabs/mosaic/issues/19)).

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
