//! # mosaic-hyperplonk
//!
//! HyperPlonk-KZG verifier over BN254 — **Phase 3 scaffold**.
//!
//! HyperPlonk (eprint [2022/1355](https://eprint.iacr.org/2022/1355))
//! replaces PLONK's univariate polynomials with **multilinear extensions
//! over the boolean hypercube** `{0, 1}^n`, where `n = log₂(circuit size)`.
//! The consequences:
//!
//! - **No FFT-friendly trusted setup required.** The evaluation domain
//!   is combinatorial rather than algebraic, removing the size-must-be-
//!   power-of-2 constraint at the SRS level.
//! - **Sumcheck protocol** replaces the single-polynomial identity.
//!   Prover sends `log n` round-polynomials; verifier reduces one
//!   multilinear evaluation claim to another via challenge-driven
//!   random evaluation.
//! - **Proof size** grows `O(log n)` vs PLONK's `O(1)`, but verifier
//!   time is still `O(log n)` (vs PLONK's `O(1)` with `O(n)`
//!   preprocessing hidden in the domain).
//!
//! ## Phase-3 scope
//!
//! Phase 3 ships the full verifier; this Phase-2 freeze contains only
//! the scaffold:
//!
//! - [`verifier::HyperPlonkKzgBn254`] implements
//!   [`mosaic_core::ProofSystem`] and wire-format length-checks inputs,
//!   then returns [`mosaic_core::OnChainError::UnimplementedProofSystem`].
//! - [`canonical`] defines a placeholder byte layout with the TODO
//!   markers pointing at the exact fields that need to be pinned.
//! - Shared cryptographic primitives (Fr arithmetic, MSM, Keccak
//!   transcript, G1/G2 generator constants) come from `mosaic_plonk`
//!   — HyperPlonk is adjacent to PLONK at the protocol layer, shares
//!   the whole lower layer.
//!
//! Tracking issue: [#2](https://github.com/wienerlabs/mosaic/issues/2).
//!
//! ## CU target
//!
//! ADR-0005 budget: ≤900 000 CU. Rough decomposition based on the
//! reference Espresso HyperPlonk verifier for a 2^10-gate circuit:
//!
//! | Step | Estimate |
//! |---|---|
//! | Transcript init + challenges (9 rounds × log 2^10 = 100) | ~15 000 |
//! | Sumcheck verification (10 rounds × 3-coeff polynomial) | ~200 000 |
//! | Multilinear evaluation reduction (MLE → univariate) | ~80 000 |
//! | Linear combination of commitments via MSM | ~150 000 |
//! | KZG batched opening pairing check | ~30 000 |
//! | Decode + dispatch overhead | ~30 000 |
//! | **Total (estimated)** | **~505 000** |
//!
//! Well under the 900K cap, with room for safety margin as arkworks
//! overhead surfaces during implementation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod canonical;
pub mod sumcheck;
pub mod verifier;

pub use canonical::{HyperPlonkProof, HyperPlonkVerifyingKey};
pub use sumcheck::{verify_sumcheck, RoundPolynomial, SumcheckOutput};
pub use verifier::HyperPlonkKzgBn254;
