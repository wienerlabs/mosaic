//! # mosaic-groth16
//!
//! Cleanroom Groth16 verifier for BN254. Accepts proofs and verifying keys in
//! the canonical Mosaic byte layout (see [`canonical`]) and dispatches all
//! cryptographic operations through [`mosaic_core::SyscallBackend`], so the
//! same code runs against:
//!
//! - The Solana SBF runtime (via the `solana` feature).
//! - Host tests (via the `host-backend` feature, backed by arkworks).
//!
//! ## Verification equation
//!
//! Given proof `(A, B, C)` and prepared VK `(αβ, γ, δ, IC[])`, Groth16 checks:
//!
//! ```text
//! e(-A, B) · e(α, β) · e(L, γ) · e(C, δ) = 1
//! ```
//!
//! where `L = IC[0] + Σ public_inputs[i] · IC[i+1]` is a multi-scalar
//! multiplication over the IC vector. We negate `A` internally so that all
//! four pairings can be batched into one `sol_alt_bn128_group_op(Pairing, …)`
//! call (192 B per pair × 4 pairs = 768 B input).
//!
//! ## Compute-unit budget
//!
//! For a VK with `n` public inputs:
//! - `n × G1_MUL` (~3 200 CU each) + `n × G1_ADD` (~100 CU each) for `L`.
//! - 1 × `Pairing` over 4 pairs (~36 000 CU).
//! - Deserialization + input checks (~5 000 CU).
//!
//! Typical Circom circuit (5 public inputs) ≈ 60 000 CU, well under the
//! ≤180 000 CU phase-1 target documented in `docs/compute-unit-budget.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod canonical;
pub mod verifier;

pub use canonical::{Groth16Proof, Groth16VerifyingKey};
pub use verifier::Groth16Verifier;

/// Wire-stable byte sizes for canonical-format Groth16 artifacts.
pub mod sizes {
    /// G1 affine point: 32-byte x || 32-byte y.
    pub const G1_LEN: usize = 64;
    /// G2 affine point: 64-byte x (Fq2) || 64-byte y (Fq2).
    pub const G2_LEN: usize = 128;
    /// Field element (BN254 scalar field).
    pub const FR_LEN: usize = 32;
    /// Proof: A (G1) || B (G2) || C (G1).
    pub const PROOF_LEN: usize = G1_LEN + G2_LEN + G1_LEN; // 256
}
