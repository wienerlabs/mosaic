# Mosaic

> **Proof-system-agnostic on-chain verification for Solana.**
> One API. Multiple proving systems. No Groth16 wrapping required.

[![CI](https://img.shields.io/github/actions/workflow/status/wienerlabs/mosaic/ci.yml?branch=main)](.github/workflows/ci.yml)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)
[![MSRV: 1.85.0](https://img.shields.io/badge/MSRV-1.85.0-orange.svg)](rust-toolchain.toml)
[![Release: v0.9.1-halo2-multi-column-kzg-binding](https://img.shields.io/badge/release-v0.9.1--halo2--multi--column--kzg--binding-green.svg)](https://github.com/wienerlabs/mosaic/releases/tag/v0.9.1-halo2-multi-column-kzg-binding)
[![Audit: ready for review](https://img.shields.io/badge/audit-ready%20for%20review-yellow.svg)](AUDIT.md)

The Solana ecosystem has exactly one production-grade ZK verifier today
(Light Protocol's `groth16-solana`). Every other proof system — PLONK,
HyperPlonk, Halo2-KZG, FRI-STARK, Risc0, Nova, ProtoStar — either requires
awkward Groth16 wrapping (see Bonsol/Anagram's Risc0-in-Circom workaround)
or cannot be verified on Solana L1 at all.

Mosaic fixes that. Pick a proving system via a generic parameter; swap
systems without touching program logic.

```rust
use mosaic_core::{ProofSystem, ProofSystemId};
use mosaic_groth16::Groth16Verifier;
// (Future: use mosaic_plonk::PlonkKzgBn254;)

let backend = mosaic_core::syscall::host::HostBackend::new();
let verifier = Groth16Verifier::<_, false>::new(&backend);

verifier.verify(&vk_bytes, &proof_bytes, &public_inputs_bytes)?;
//        ^^ same call shape for every supported proving system
```

## Status

**Phase-3 bodies (this release)**: all four Phase-3 verifier
pipelines now run end-to-end and return `Ok(())` on structurally
well-formed proofs. Scaffold caveats per family are documented for
fixture-driven tightening in upcoming 0.4.x releases. Phase-2
production verifiers (Groth16, PLONK) remain unchanged at their
frozen CU budgets.

| Component | Status | On-chain CU |
|---|---|---|
| `mosaic-core` (traits, errors, syscall abstraction) | ✅ Production | — |
| `mosaic-groth16` single verify | ✅ Production | 83,574 |
| `mosaic-groth16` batch verify (N=5, Bowe-Gabizon) | ✅ Production | 258,397 (52K/proof, **-38%**) |
| `mosaic-plonk` KZG-PLONK BN254 verifier | ✅ Production | 968,457 |
| `mosaic-hyperplonk` KZG BN254 verifier | 🟠 Phase-3 body (structural, scaffold caveats) | target ~505K |
| `mosaic-halo2` KZG BN254 verifier (PSE fork) | 🟠 Phase-3 body (structural, scaffold caveats) | target ~580K |
| `mosaic-stark` FRI-STARK (Goldilocks / BabyBear / Mersenne31) | 🟠 Phase-3 body (structural, scaffold caveats) | target ~9.4M |
| `mosaic-nova` Nova / HyperNova / ProtoStar folding | 🟠 Phase-3 body (structural, scaffold caveats) | target ~885K |
| `mosaic-serde` snarkjs adapter (Groth16 + PLONK) | ✅ Production | — |
| `mosaic-serde` arkworks adapter | ✅ Production | — |
| `mosaic-serde` gnark / halo2 / plonky3 / risc0 | 🚧 Stub (Phase 3) | — |
| `mosaic-chunked` data model | ✅ Implemented | — |
| `mosaic-chunked` instruction handlers | ✅ Production | — |
| Reference Solana program | ✅ 319 KB SBF ELF (30.4% of 1 MB cap; 12 cryptographic gates wired) | — |
| Differential test harness (arkworks + snarkjs fixture) | ✅ Production (Groth16 + PLONK; Phase-3 extension tracked) | — |
| Property-test coverage (proptest, sessions 36-72) | ✅ 549 lib tests across 12 crates (+152 proptest + 9 shared primitives lifted in audit-coverage sweep) | — |
| Audit runbook | ✅ [`docs/audit-coverage-runbook.md`](docs/audit-coverage-runbook.md) — reproduce + extend recipes for external review firms | — |
| BPF CU regression bench (`bpf-bench`) | ✅ 7 systems: Groth16 (single + batch), KZG-PLONK, HyperPlonk, Halo2, Nova, FRI-STARK | — |
| Host criterion bench (wall-clock baseline) | ✅ 5 systems: Groth16, HyperPlonk, Halo2, Nova, FRI-STARK | — |
| Fuzz harnesses (sessions 54-59) | ✅ 23 targets across all 6 production verifiers (5 proof-bytes + 5 vk-bytes + 5 public-inputs + 5 combined-slot for PLONK + 4 Phase-3, plus 3 original Groth16) | — |
| External audit | 🔴 Not yet commissioned | — |

See [`AUDIT.md`](AUDIT.md) for audit history and [`SECURITY.md`](SECURITY.md)
for the responsible-disclosure policy.

## Quick start

### Add to your program

```toml
[dependencies]
mosaic-core      = { version = "0.1", features = ["solana"] }
mosaic-groth16   = { version = "0.1", features = ["solana"] }
solana-program   = "2.1"
```

### Verify a Groth16 proof on-chain

```rust
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::solana::SolanaSyscallBackend,
};
use mosaic_groth16::Groth16Verifier;

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let backend = SolanaSyscallBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);
    let (vk, rest)        = decode_lp(instruction_data)?;
    let (proof, pi_bytes) = decode_lp(rest)?;
    verifier.verify(vk, proof, pi_bytes).map_err(Into::into)
}
```

### Set the compute budget on the client

```rust
use solana_sdk::compute_budget::ComputeBudgetInstruction;

let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(200_000);
let verify_ix = mosaic_sdk::build_verify_proof_ix(&request)?;

transaction.add(&cu_ix);
transaction.add(&verify_ix);
```

See [`docs/compute-unit-budget.md`](docs/compute-unit-budget.md) for per-system targets.

### Generate a proof off-chain (snarkjs → Mosaic)

```rust
use mosaic_serde::snarkjs::SnarkjsCodec;

let bundle = SnarkjsCodec::decode_bundle(&proof_json, &vk_json, &public_inputs_json)?;
// bundle.vk, bundle.proof, bundle.public_inputs are now canonical bytes
```

### Pre-flight verification (catch bugs before on-chain)

```rust
mosaic_sdk::preflight(&request)?;
// Runs the same verifier locally with arkworks. Fails fast.
```

## Workspace topology

```
mosaic/
├── crates/
│   ├── mosaic-core/      # ProofSystem, SyscallBackend, errors
│   ├── mosaic-groth16/   # BN254 Groth16 verifier
│   ├── mosaic-plonk/     # KZG-PLONK (Phase 2 stub)
│   ├── mosaic-stark/     # FRI-STARK (Phase 3 stub)
│   ├── mosaic-nova/      # Folding scheme (Phase 3 stub)
│   ├── mosaic-serde/     # snarkjs / arkworks / gnark / halo2 / plonky3 / risc0 adapters
│   ├── mosaic-chunked/   # Large-proof upload protocol
│   ├── mosaic-program/   # Reference Solana on-chain program
│   ├── mosaic-sdk/       # Client-side Rust SDK
│   ├── mosaic-bench/     # Criterion + bpf-bench
│   └── mosaic-fuzz/      # libFuzzer harnesses
├── docs/
│   ├── adr/              # Architecture decision records (5 ADRs)
│   ├── threat-model.md
│   └── compute-unit-budget.md
└── tests/
    ├── differential/     # arkworks vs Mosaic oracle tests
    ├── integration/      # On-chain devnet tests (Phase 2)
    └── fixtures/         # Sample proofs from each framework
```

## Design principles

1. **Object-safe `ProofSystem` trait.** Single byte-slice API; the on-chain
   dispatcher monomorphizes via `match`, the SDK uses `Box<dyn ProofSystem>`.
2. **Two-layer error model.** `OnChainError` (deterministic, repr-u32) for
   on-chain; `DiagnosticError` (rich, feature-gated) for off-chain. See
   [ADR-0002](docs/adr/0002-error-taxonomy.md) and SIMD-0129.
3. **Syscall abstraction.** `SyscallBackend` lets host tests use arkworks
   while on-chain calls real syscalls. Same verifier code, different backend.
4. **No hand-rolled cryptography.** Verifier crates depend on `ark-bn254`
   (host) or Solana syscalls (SBF). New primitives go through the abstraction
   or wait for upstream availability.
5. **Forward-compatible byte layout.** `LE_INPUTS` const generic + `FormatTag`
   wire enum mean SIMD-0204 (LE alt_bn128) and SIMD-0233 (native G2) land as
   non-breaking changes.

## MSRV

Rust **1.85.0** — host workspace (cargo, clippy, rustfmt, tests).
Rust **1.89.0-dev** — Solana SBF target via `cargo build-sbf --tools-version v1.52`.

The default `cargo-build-sbf` (platform-tools v1.51, rustc 1.84.1) can't
parse `edition2024` in some transitive dependencies (`constant_time_eq` via
`blake3`). We therefore pin `--tools-version v1.52` in CI and recommend the
same locally.

## Security

- **Phase-1 scope freeze:** [`v0.1.0-phase1`](https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1).
  External audit-ready (pending firm engagement per issue [#19](https://github.com/wienerlabs/mosaic/issues/19) / [#61](https://github.com/wienerlabs/mosaic/issues/61)).
- **Phase-2 scope freeze:** [`v0.2.0-phase2`](https://github.com/wienerlabs/mosaic/releases/tag/v0.2.0-phase2).
  Production PLONK + Groth16 batch verification.
- **Phase-3 scaffold freeze:** [`v0.3.0-phase3-scaffolds`](https://github.com/wienerlabs/mosaic/releases/tag/v0.3.0-phase3-scaffolds).
  HyperPlonk + Halo2 + FRI-STARK wire formats locked.
- **Phase-3 bodies freeze:** [`v0.4.0-phase3-bodies`](https://github.com/wienerlabs/mosaic/releases/tag/v0.4.0-phase3-bodies).
  All four Phase-3 verifier bodies (HyperPlonk, Halo2, Nova, FRI-STARK)
  run end-to-end.
- **Phase-3 soundness release:** [`v0.4.1-phase3-soundness`](https://github.com/wienerlabs/mosaic/releases/tag/v0.4.1-phase3-soundness).
  All four bodies gained cryptographic soundness gates; SBF binary
  reduced 72% via `opt-level = "z"`; `mosaic-zk-primitives` crate
  extracted.
- **Phase-3 complete release:** [`v0.5.0-phase3-complete`](https://github.com/wienerlabs/mosaic/releases/tag/v0.5.0-phase3-complete).
  **12 independent cryptographic soundness gates across 4 bodies.**
  FRI-STARK at Plonky3/Winterfell production parity (7 gates); Nova,
  Halo2, HyperPlonk extended to protocol-appropriate depth.
- **Phase-3 extended release:** [`v0.6.0-phase3-extended`](https://github.com/wienerlabs/mosaic/releases/tag/v0.6.0-phase3-extended).
  **14 soundness gates.** Multi-poly MSM batching in Halo2 (proof-
  and VK-side commits) + Nova (Spartan 5-way batched opening)
  folds every committed polynomial into the batched pairing
  identity. HyperPlonk permutation cosets (k_1, k_2, k_3) lifted
  from hardcoded `(1, 2, 3)` into the VK. CU baselines re-measured
  under the `opt-level = "z"` profile (PLONK cap 800K → 1.1M).
- **Phase-3 primitives release:** [`v0.7.0-phase3-primitives`](https://github.com/wienerlabs/mosaic/releases/tag/v0.7.0-phase3-primitives).
  Five shared primitives extracted to `mosaic-zk-primitives` from
  inlined duplication across Halo2 / HyperPlonk / Nova verifiers —
  `fr_from_be_bytes_reduced`, `derive_fr_challenge`, `fr_be_from_u64`,
  `verify_two_pair_pairing`, `commitment_minus_scalar_g1`. Nova
  proof canonical gains a dedicated `w_eval` slot (session 23),
  replacing the scaffold reuse of `public_inputs[0]`. 14 new unit
  tests cover the lifted primitives.
- **Phase-3 polish release:** [`v0.8.0-phase3-polish`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.0-phase3-polish).
  Sixth primitive `compute_kzg_opening_lhs` consolidates the full
  `A = C − y·G1 + ξ·W` pairing-LHS construction across every KZG
  verifier. HyperPlonk univariate opening point now binds the
  FULL sumcheck challenge vector (not just the trailing challenge).
  `ProofSystem::estimated_compute_units` turns shape-aware for the
  three Phase-3 bodies (halo2/hyperplonk/nova). `mosaic-sdk` gains
  five opt-in Cargo features (`plonk`, `hyperplonk`, `halo2`,
  `nova`, `stark`, plus `all-phase3`) so client preflight covers
  every proof system. Cast-safe borrow-chain rewrite eliminates
  four `as u8` truncation warnings in `fr::sub_r` + `msm::negate_g1`.
  **+27 proptest tests** (zk-primitives 51→64, stark 103→117) plus
  clippy cleanup + complete `# Errors` rustdoc for zk-primitives.
- **Audit-coverage release:** [`v0.8.1-audit-coverage`](https://github.com/wienerlabs/mosaic/releases/tag/v0.8.1-audit-coverage).
  Workspace-wide property-based test sweep (sessions 37-42) brings
  every Phase-1, Phase-2, Phase-3, adapter, state-machine, SDK, and
  on-chain program crate under audit-grade proptest coverage.
  **+111 proptest tests** across nine crates:

  | Crate | Δ | Total |
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

  Property categories: canonical byte layout invariants, full
  Fiat-Shamir round-by-round avalanche (Halo2 4-round, HyperPlonk
  3-round, Nova 3-round, PLONK 6-round including the snarkjs-
  compatibility "u-absorbs-only-W_xi-and-W_xiω" bit), single-byte
  tamper rejection over commit and opening regions, state-machine
  monotonicity (chunked upload session), Borsh wire-format round-
  trip (instruction payloads), BE-comparison + Fr arithmetic
  invariants, snarkjs adapter c1‖c0 ordering and `decimal_to_be_32`
  range envelope, builder/setter independence, instruction-tag
  dispatch routing.

  Three false positives surfaced and were documented inline: the
  Halo2 verifier random-byte-flip test required scope-narrowing
  away from selector slots that interact with the dummy fixture's
  trivially-zero wires; the HyperPlonk verifier's `anchor + XOR`
  tamper pattern was rewritten to direct `proof[off] = new_val`
  after `bit_mask = anchor` cancellation was caught by proptest
  shrinking; the same byte-anchor pattern was avoided across the
  rest of the sweep.

  Only fixture-driven differential testing remains before external
  audit engagement (tracked: extending `tests/differential` from
  Groth16 + PLONK to all four Phase-3 bodies).
- **Vulnerability reports:** see [SECURITY.md](SECURITY.md) and the
  [disclosure-timeline SLA](docs/responsible-disclosure-timeline.md).
- **Audit history:** see [AUDIT.md](AUDIT.md).
- **Threat model:** see [docs/threat-model.md](docs/threat-model.md).
- **Supply chain:** `cargo-deny` + `cargo-audit` run in CI; `cargo-vet`
  attestation bootstrap at [`supply-chain/`](supply-chain/README.md).
- **Lint policy:** [`docs/lint-policy.md`](docs/lint-policy.md) is the
  audit-facing registry of every clippy suppression.
- **Changelog:** [CHANGELOG.md](CHANGELOG.md).

## License

Dual-licensed under either of:

- [Apache License 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option. SPDX: `Apache-2.0 OR MIT`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are welcomed under
the dual-license terms above.
