//! # mosaic-nova
//!
//! Folding-scheme verifier over BN254 — **Phase-3 scaffold**.
//!
//! Folding schemes accumulate proofs of incremental computation. Given a
//! chain of N step instances `I_1, I_2, ..., I_N`, the prover folds them
//! pairwise into a single "accumulator" instance `A_N`. Verifying `A_N`
//! attests to the correctness of the entire chain — but verification
//! cost is **constant** in N, not linear.
//!
//! On Solana this matters because an entire zkVM execution (millions of
//! steps) can collapse to a single ~900 K CU on-chain check.
//!
//! ## Supported variants
//!
//! Three folding schemes share the same high-level verifier shape
//! (check a folded instance satisfies its constraint system at a random
//! point). The [`canonical::FoldingVariant`] tag byte disambiguates:
//!
//! | Tag | Scheme | Paper | Constraint system |
//! |---|---|---|---|
//! | 0 | **Nova** | [eprint 2021/370](https://eprint.iacr.org/2021/370) | Relaxed R1CS |
//! | 1 | **`HyperNova`** | [eprint 2023/573](https://eprint.iacr.org/2023/573) | Customizable CS |
//! | 2 | **`ProtoStar`** | [eprint 2023/620](https://eprint.iacr.org/2023/620) | Relaxed special-sound |
//!
//! All three operate over BN254 — originally Pasta curves (Nova paper),
//! but the PSE port ([`microsoft/Nova`](https://github.com/microsoft/Nova))
//! and the `sonobe` folding-compiler both emit BN254 proofs verifiable
//! on Solana's `alt_bn128` syscall surface.
//!
//! ## Phase-3 scope
//!
//! Phase 3 ships the full verifier. This Phase-2 freeze contains only
//! the scaffold:
//!
//! - [`canonical`] — placeholder proof + VK byte layout.
//! - [`verifier::NovaFolding`] implements [`mosaic_core::ProofSystem`],
//!   wire-format-validates inputs, then returns
//!   [`mosaic_core::OnChainError::UnimplementedProofSystem`].
//!
//! Shared BN254 primitives (Fr arithmetic, MSM, transcript, G1/G2
//! generator constants) come from `mosaic_plonk` — third consumer of
//! the `mosaic-plonk` primitive set, triggering the
//! `mosaic-zk-primitives` extraction as a follow-up refactor.
//!
//! Tracking issue: [#4](https://github.com/wienerlabs/mosaic/issues/4).
//!
//! ## CU target (ADR-0005)
//!
//! | Step | CU estimate |
//! |---|---|
//! | Decode + variant dispatch | 20 K |
//! | Transcript challenge derivation (3-round Fiat-Shamir) | 25 K |
//! | R1CS matrix MSM (A·z, B·z, C·z at folded point) | 300 K |
//! | Error term `E = A·z ∘ B·z − u · C·z` commitment check | 250 K |
//! | Cross-term `T` commitment consistency | 150 K |
//! | Final KZG opening pairing (if Spartan-wrapped) | 140 K |
//! | **Total (Nova)** | **~885 K** |
//!
//! Under the 900 K CU cap with tight margin. `HyperNova`'s higher-degree
//! gates may push toward the cap; `ProtoStar`'s special-sound protocols
//! typically come in lower. Real fixtures from `sonobe` will tighten
//! these numbers during Phase-3 implementation.
//!
//! ## Why folding schemes matter on Solana
//!
//! A 10M-step zkVM trace verified directly would require a 10M-step
//! STARK or recursive SNARK chain — both infeasible on-chain. Folding
//! schemes collapse the chain off-chain and send one constant-size
//! proof. This is the architectural unlock for:
//!
//! - **Rollup zkVMs** (RISC-V / x86 execution traces)
//! - **Verifiable computing** marketplaces (long-running jobs)
//! - **ZK coprocessors** (arbitrary-step computations)
//!
//! See [`sonobe`](https://github.com/privacy-scaling-explorations/sonobe)
//! for the reference folding-compiler toolchain.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod canonical;
pub mod challenges;
pub mod folding;
pub mod kzg;
pub mod verifier;

pub use canonical::{FoldingVariant, NovaFoldingProof, NovaFoldingVerifyingKey};
pub use challenges::{derive_challenges, NovaChallenges};
pub use folding::{
    folded_commitment_from_fold, folded_commitment_two_term, folded_error_commitment,
    hadamard_residual, verify_folding_consistency,
};
pub use kzg::verify_opening_scaffold;
pub use verifier::NovaFolding;
