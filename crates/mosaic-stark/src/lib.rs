//! # mosaic-stark
//!
//! FRI-STARK verifier over small prime fields (Goldilocks / BabyBear /
//! Mersenne31) — **Phase 3 scaffold**.
//!
//! Unlike the KZG-based verifiers in `mosaic-plonk`, `mosaic-hyperplonk`
//! and `mosaic-halo2`, STARKs are purely hash-based. They use no elliptic
//! curves, no pairings, no trusted setup. The verifier hot path is:
//!
//! 1. **Merkle authentication** for committed traces and constraints.
//! 2. **FRI low-degree testing** — log₂(domain) layers of fold + query.
//! 3. **Out-of-domain quotient check** — univariate polynomial consistency.
//!
//! This makes the SBF cost profile very different:
//!
//! | Cost driver | KZG verifier | STARK verifier |
//! |---|---|---|
//! | Pairing | 1× (~200K CU) | 0 |
//! | MSM | linearization step | 0 |
//! | SHA-256 / keccak | transcript only | **dominant** (FRI + Merkle) |
//! | Proof size | ≤2 KB | 50–200 KB (chunked upload required) |
//! | Field arithmetic | 256-bit BN254 Fr | 32/64-bit Goldilocks/BabyBear |
//!
//! ## Phase-3 scope
//!
//! Phase 3 implementation targets the [eprint 2025/1741] Winterfell-on-
//! Solana technique:
//!
//! - Batched `sol_sha256` calls via `hashv` (≈30 CU/byte vs ~200 CU/byte
//!   for one-shot hashing).
//! - `#[inline(never)]` on FRI inner loops to keep SBF stack frames
//!   under 4 KB.
//! - Bump-arena allocation sized to the requested heap frame (typically
//!   256 KiB for a 2¹⁶-row trace).
//! - Hard integration with `mosaic-chunked`: full proof uploaded across
//!   multiple transactions, then verified via `CommitAndVerify`.
//!
//! [eprint 2025/1741]: https://eprint.iacr.org/2025/1741
//!
//! ## What ships in this Phase-2 freeze
//!
//! - [`canonical`] — placeholder wire format parametrized by field id
//!   (Goldilocks / BabyBear / Mersenne31), trace width, trace log-height,
//!   FRI layer count, query count, and PoW grinding bits.
//! - [`verifier::FriStark`] implements [`mosaic_core::ProofSystem`],
//!   wire-validates then returns
//!   [`mosaic_core::OnChainError::UnimplementedProofSystem`].
//!
//! Tracking issue: [#3](https://github.com/wienerlabs/mosaic/issues/3).
//!
//! ## CU target (ADR-0005)
//!
//! | Step | CU estimate |
//! |---|---|
//! | Trace + constraint Merkle root absorb | 150 K |
//! | FRI commit phase (log₂(N) layer absorbs) | 400 K |
//! | Query phase (N_queries × (opening + auth path)) | 8 000 K |
//! | Out-of-domain quotient consistency check | 500 K |
//! | Grinding PoW verification | 100 K |
//! | Chunked-upload decode + dispatch | 250 K |
//! | **Total (2¹⁶-row trace, 80 queries)** | **~9 400 K** |
//!
//! Under the 14 M CU max-compute cap with headroom. Real fixtures will
//! tighten this during Phase-3 implementation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod canonical;
pub mod challenges;
pub mod fri;
pub mod goldilocks;
pub mod merkle;
pub mod verifier;

pub use canonical::{FriStarkProof, FriStarkVerifyingKey, StarkFieldId};
pub use challenges::{derive_challenges, derive_query_indices, StarkChallenges};
pub use fri::{compute_next_layer_value, fold_relation_holds};
pub use goldilocks::Goldilocks;
pub use merkle::verify_path;
pub use verifier::FriStark;
