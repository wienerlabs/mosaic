//! # mosaic-plonk
//!
//! BN254 KZG-PLONK verifier — **Phase 2** target. Phase 1 ships the byte
//! layout, types, and verifier skeleton so Phase-2 implementers can
//! plug in cryptographic steps without relitigating the wire format.
//!
//! ## What's in this crate today
//!
//! - [`canonical`] — byte layout for [`canonical::PlonkProof`] (768 B)
//!   and [`canonical::PlonkVerifyingKey`] (744 B fixed header).
//! - [`verifier::PlonkKzgBn254`] — `ProofSystem` impl that parses
//!   inputs but returns [`mosaic_core::OnChainError::UnimplementedProofSystem`]
//!   from `verify()`.
//! - [`transcript`] — Fiat-Shamir scaffolding (Poseidon or Keccak).
//!
//! ## What's NOT in this crate today
//!
//! - Round-by-round verifier logic (challenge derivation, linearization,
//!   KZG opening check). Tracked by
//!   [issue #1](https://github.com/wienerlabs/mosaic/issues/1).
//! - Differential test against arkworks or snarkjs PLONK reference.
//! - snarkjs-PLONK adapter in `mosaic-serde::snarkjs`.
//!
//! ## CU target
//!
//! ≤600 000 CU per ADR-0005 § Per-system targets. Current estimate:
//!
//! | Step | CU |
//! |---|---|
//! | Transcript initialization + absorb VK | ~5 000 |
//! | Round 1 (wire commitments absorb + challenges) | ~3 000 |
//! | Round 2 (Z commitment absorb + β, γ) | ~3 000 |
//! | Round 3 (T1..T3 absorb + α) | ~4 000 |
//! | Round 4 (evaluations absorb + v) | ~3 000 |
//! | Linearization MSM (~20 scalar muls) | ~200 000 |
//! | KZG batched opening check (1 pairing of 2 pairs) | ~24 000 |
//! | Public input polynomial evaluation | ~20 000 |
//! | Sundry (decode, error paths) | ~10 000 |
//! | **Total (estimated)** | **~272 000** |
//!
//! Leaves ~328 000 CU headroom under the 600K cap.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod canonical;
pub mod challenges;
pub mod field;
pub mod fr;
pub mod transcript;
pub mod verifier;

pub use canonical::{PlonkProof, PlonkVerifyingKey};
pub use verifier::PlonkKzgBn254;
