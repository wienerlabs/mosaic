# Changelog

All notable changes to Mosaic are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v0.1.0

- Real Circom-sourced Groth16 fixtures (issue [#24](https://github.com/wienerlabs/mosaic/issues/24)).
- External security audit (issue [#19](https://github.com/wienerlabs/mosaic/issues/19)).
- Devnet integration test with deployed program (issue [#33](https://github.com/wienerlabs/mosaic/issues/33)).
- Expanded threat model sections (issue [#63](https://github.com/wienerlabs/mosaic/issues/63)).
- `cargo-vet` supply chain attestation (issue [#59](https://github.com/wienerlabs/mosaic/issues/59)).

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

[Unreleased]: https://github.com/wienerlabs/mosaic/compare/v0.1.0-phase1...HEAD
[0.1.0-phase1]: https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1
