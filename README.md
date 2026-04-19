# Mosaic

> **Proof-system-agnostic on-chain verification for Solana.**
> One API. Multiple proving systems. No Groth16 wrapping required.

[![CI](https://img.shields.io/badge/ci-pending-lightgrey)](.github/workflows/ci.yml)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)
[![MSRV: 1.85.0](https://img.shields.io/badge/MSRV-1.85.0-orange.svg)](rust-toolchain.toml)
[![Status: Phase 1](https://img.shields.io/badge/status-phase%201%20bootstrap-yellow.svg)](#status)

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

**Phase 1 (this release)**: workspace bootstrap.

| Component | Status |
|---|---|
| `mosaic-core` (traits, errors, syscall abstraction) | ✅ Implemented |
| `mosaic-groth16` (BN254 verifier) | ✅ Implemented (host + SBF backends) |
| `mosaic-serde` snarkjs adapter | ✅ Implemented |
| `mosaic-serde` arkworks adapter | ✅ Implemented |
| `mosaic-serde` gnark / halo2 / plonky3 / risc0 | 🚧 Stub (Phase 2/3) |
| `mosaic-plonk` / `mosaic-stark` / `mosaic-nova` | 🚧 Stub (Phase 2/3) |
| `mosaic-chunked` data model | ✅ Implemented |
| `mosaic-chunked` instruction handlers | 🚧 TODO(mosaic-006) |
| Reference Solana program | ✅ Compiles to SBF |
| Differential test harness | ✅ Scaffolded |
| Fuzz harnesses (3) | ✅ Scaffolded |
| Audit | 🔴 Not yet performed |

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

- **Vulnerability reports:** see [SECURITY.md](SECURITY.md).
- **Audit history:** see [AUDIT.md](AUDIT.md).
- **Threat model:** see [docs/threat-model.md](docs/threat-model.md).

## License

Dual-licensed under either of:

- [Apache License 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option. SPDX: `Apache-2.0 OR MIT`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are welcomed under
the dual-license terms above.
