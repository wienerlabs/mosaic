# Changelog

All notable changes to Mosaic are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v0.3.0 / Phase 3

- **HyperPlonk-KZG** verifier (issue [#2](https://github.com/wienerlabs/mosaic/issues/2)).
- **Halo2-KZG** verifier + adapter (issue [#11](https://github.com/wienerlabs/mosaic/issues/11)).
- **gnark** format adapter for Groth16 + PLONK (issue [#10](https://github.com/wienerlabs/mosaic/issues/10)).
- **FRI-STARK** verifier via chunked-upload (issue [#3](https://github.com/wienerlabs/mosaic/issues/3)).
- **Nova / HyperNova / ProtoStar** folding-scheme verifiers (issue [#4](https://github.com/wienerlabs/mosaic/issues/4)).
- CU optimization: Pippenger MSM (issue [#37](https://github.com/wienerlabs/mosaic/issues/37)) + Fr in-place (issue [#38](https://github.com/wienerlabs/mosaic/issues/38)) → PLONK ~600K target.
- Real Circom-sourced Groth16 fixtures (issue [#24](https://github.com/wienerlabs/mosaic/issues/24)).
- External security audit (issue [#19](https://github.com/wienerlabs/mosaic/issues/19)).

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
