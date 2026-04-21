//! # mosaic-halo2
//!
//! Halo2-KZG verifier over BN254 — **Phase 3 scaffold**.
//!
//! Halo2 was originally built by Zcash on the Pasta curves with inner
//! product arguments (IPA). The [Privacy Scaling Explorations
//! fork](https://github.com/privacy-scaling-explorations/halo2) ported
//! it to BN254 with KZG commitments, making it verifiable on Solana's
//! `alt_bn128` syscall surface. That PSE fork is the target for
//! `mosaic-halo2`.
//!
//! ## What Halo2-KZG brings that PLONK doesn't
//!
//! - **Custom gates** — circuit author picks the polynomial constraint
//!   shape per region; one constraint can span many rows.
//! - **Lookup arguments** (plookup / log-derivative) for table-style
//!   operations. Verifier cost: one additional KZG opening per lookup.
//! - **Permutation over many columns** with a single grand-product.
//! - **Vanishing argument split into `k` quotient chunks** to stay under
//!   the trusted-setup domain size.
//!
//! Consequences for verifier complexity:
//!
//! - Proof size grows with both circuit width (columns) and lookup
//!   count — typically 4–8 KB for Halo2-KZG vs PLONK's flat 768 B.
//! - Transcript is longer; more KZG openings batched.
//! - Linearization has more terms than vanilla PLONK but the same shape
//!   (commitment MSM → KZG pairing check).
//!
//! ## Phase-3 scope
//!
//! Phase 3 ships the full verifier. This Phase-2 freeze contains only
//! the crate scaffold:
//!
//! - [`verifier::Halo2KzgBn254`] implements
//!   [`mosaic_core::ProofSystem`], wire-format-validates inputs, then
//!   returns [`mosaic_core::OnChainError::UnimplementedProofSystem`].
//! - [`canonical`] defines a placeholder byte layout derived from the
//!   PSE Halo2-KZG proof encoding. Real layout pinned in an ADR
//!   amendment when the Phase-3 verifier lands.
//! - Shared primitives (Fr arithmetic, MSM, transcript, G1/G2
//!   generator constants) come from `mosaic_plonk` — same pattern as
//!   `mosaic_hyperplonk`.
//!
//! Tracking issue: TODO(mosaic-halo2) — see README for the roadmap.
//!
//! ## CU target
//!
//! ADR-0005 budget: ≤700 000 CU. Estimate for a 2^10-row circuit with
//! 5 advice columns + 1 lookup:
//!
//! | Step | CU |
//! |---|---|
//! | Transcript init + challenges (multi-round, ~8 squeezes) | ~20 000 |
//! | Permutation argument evaluation | ~80 000 |
//! | Lookup argument evaluation | ~60 000 |
//! | Quotient-chunk aggregation (k-piece sum) | ~50 000 |
//! | Linearization MSM (~25 terms for custom-gate + lookup) | ~300 000 |
//! | KZG multipoint opening pairing | ~30 000 |
//! | Decode + dispatch | ~40 000 |
//! | **Total (estimated)** | **~580 000** |
//!
//! Under the 700K cap with ~17% safety margin. Complex circuits with
//! more columns or multiple lookups may approach the cap; Phase-3 work
//! will measure real fixtures and potentially tighten via Pippenger
//! MSM (issue [#37](https://github.com/wienerlabs/mosaic/issues/37)).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod canonical;
pub mod challenges;
pub mod verifier;

pub use canonical::{Halo2KzgProof, Halo2KzgVerifyingKey};
pub use challenges::{derive_challenges, Halo2Challenges};
pub use verifier::Halo2KzgBn254;
