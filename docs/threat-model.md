# Mosaic — Threat Model

> *Living document.* Last reviewed 2026-04-19. Re-review on every audit.

## Scope

Threats covered:

- Adversarial proof, VK, and public-input bytes submitted on-chain.
- Adversarial chunked-upload sequences targeting the session PDA.
- Validator-divergence attacks targeting consensus determinism.
- Memory-safety and arithmetic-overflow attacks within library code.
- Timing side-channels reachable from on-chain (limited — see below).

Threats **not** covered:

- Compromise of the proving trust setup (out of scope; verifier assumes
  trusted setup integrity).
- Compromise of the upstream framework (snarkjs, arkworks, gnark, …).
- Solana validator infrastructure compromise.
- DoS via legitimate-but-expensive proofs (mitigated by CU budgets, not
  full prevention).
- Client-side key management (the SDK is not a wallet).

## Trust boundaries

```
┌────────────────────────────────────────────────────────────────────┐
│ Untrusted: arbitrary bytes from any caller                         │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Mosaic adapters (mosaic-serde) — convert to canonical bytes        │
│   Input: framework-specific format. Output: canonical bytes.       │
│   Failure mode: returns Err; never panics.                         │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ On-chain dispatcher (mosaic-program)                                │
│   Input: canonical bytes. Output: ProgramResult.                    │
│   Trust: assumes byte format only; no semantic trust.              │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Verifier (mosaic-groth16, …)                                        │
│   Input: canonical bytes. Output: Result<(), OnChainError>.        │
│   Trust: trusts SyscallBackend to be deterministic and correct.    │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ SyscallBackend (mosaic-core::syscall)                               │
│   Solana SBF: trusts validator implementation of alt_bn128/SHA-256. │
│   Host: trusts arkworks + sha2 + tiny-keccak.                       │
└────────────────────────────────────────────────────────────────────┘
```

## Threats and mitigations

### T-1 Adversarial proof bytes — pairing accept on invalid proof

**Risk**: Crafted bytes pass length checks but cause the pairing syscall to
return `1` for an invalid proof.

**Mitigation**: We delegate cryptographic correctness to the
`alt_bn128_pairing` syscall. The Solana validator implementations are the
authoritative oracle. We do not re-implement pairing in `forbid(unsafe_code)`
Rust.

**Residual risk**: Soundness errors in the validator implementations would
break Mosaic. We mirror with the host backend (arkworks) for differential
testing, which would surface a divergence between the two implementations.

### T-2 Adversarial public inputs — values ≥ scalar field order `r`

**Risk**: Bypasses Groth16 soundness if accepted with `pi >= r`.

**Mitigation**: `Groth16Verifier::verify` bounds-checks every public input
against `BN254_FR_MODULUS_BE` *before* invoking the syscall. Violations
return `OnChainError::PublicInputOutOfRange`.

**Validation**: Unit test in `crates/mosaic-groth16/src/canonical.rs::tests::fr_modulus_bound`.

### T-3 Off-curve / wrong-subgroup G1 / G2 inputs

**Risk**: Crafted "points" that aren't on the curve.

**Mitigation**: The `alt_bn128_pairing` syscall rejects off-curve inputs with
non-success status, surfacing as `OnChainError::AltBn128SyscallFailed`.
Host backend explicitly calls `is_on_curve` and `is_in_correct_subgroup_assuming_on_curve`.

**Residual risk**: A subtle bug in the syscall's subgroup check (cf. the
2022 BN254 subgroup-check bug in geth) would propagate. Differential testing
against arkworks catches divergence; cannot catch *both* impls being wrong
in the same way.

### T-4 Length-mismatch crash via crafted byte slices

**Risk**: A crafted proof / VK byte slice causes a panic via slice indexing.

**Mitigation**: Every byte-level access uses `split_at`, `chunks_exact`, or
explicit `.get()` with `?`. Library-wide `clippy::indexing_slicing = "warn"`
catches regressions.

**Validation**: `cargo-fuzz` harnesses in `mosaic-fuzz/` (proof bytes, VK
bytes, public inputs).

### T-5 Validator divergence on error codes (consensus failure)

**Risk**: Two validator implementations (Agave, Firedancer, Jito-Solana)
return different `ProgramError` codes on the same input, forking the network.
Cf. SIMD-0129.

**Mitigation**: `OnChainError` is a small `repr(u32)` enum; every reachable
code path maps to a stable discriminant. Off-chain `DiagnosticError` cannot
reach on-chain entry points (compile-time enforced). All length / format
checks return concrete variants, never wildcards. `mosaic-core::error::tests::discriminant_stability` pins the most load-bearing discriminants.

### T-6 Chunked-upload reordering / commitment forgery

**Risk**: Adversary uploads a different proof than the one whose hash they
precommitted to in `InitializeSession`.

**Mitigation**: Rolling SHA-256 binds each chunk's content and order;
`CommitAndVerify` checks the running hash against the precommitted final
hash. Mismatch yields `ChunkCommitmentMismatch`.

**Residual risk**: SHA-256 second-preimage attack. Considered
cryptographically intractable; if SHA-256 falls, the entire Solana state
hash falls with it.

### T-7 PDA squatting / cross-session aliasing

**Risk**: Adversary pre-creates a session PDA with a chosen `session_id`.

**Mitigation**: `session_id` is a 32-byte client-supplied value; if two
clients pick the same value, the second `InitializeSession` will fail
because the PDA is already initialized. Clients are expected to use
cryptographic randomness (the SDK does this via `rand::thread_rng`).

### T-8 Timing side-channels

**Risk**: Pairing or MSM timing leaks witness data.

**Mitigation**: On-chain code runs on validators, not in an environment where
timing is observable to the prover. The `subtle` crate's constant-time
primitives are used for length-equal comparisons in non-host paths.

**Out of scope**: Host-side prover timing. Provers should use
constant-time crypto themselves; Mosaic verifies, it does not prove.

### T-9 Memory unsafety

**Risk**: Use-after-free, buffer overflow, etc.

**Mitigation**: Every library crate has `#![forbid(unsafe_code)]`. Any future
use of `unsafe` requires an `allow` exception list in `deny.toml` and a
`SAFETY:` block.

### T-10 Arithmetic overflow

**Risk**: Silent wrapping in length / index arithmetic causes incorrect
behavior on hostile input.

**Mitigation**: `clippy::arithmetic_side_effects = "warn"`. All chunk-size
and offset calculations use `checked_add` / `try_from`. `dev` profile has
`overflow-checks = true`; `release` has it off but the patterns are
checked-arithmetic regardless.

## Audit history

See `AUDIT.md`.
