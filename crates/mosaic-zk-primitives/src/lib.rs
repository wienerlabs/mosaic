//! # mosaic-zk-primitives
//!
//! Shared BN254 cryptographic primitives for the Mosaic verifier
//! family. This crate packages the primitive layer that every BN254-
//! based Phase-3 verifier body (`HyperPlonk`, Halo2-KZG, Nova) builds on
//! top of, and that the Phase-2 KZG-PLONK verifier also consumes.
//!
//! ## Why a separate crate
//!
//! Through Phase 2 the primitives lived inside `mosaic-plonk`, which
//! made sense when PLONK was the only consumer. With four BN254
//! verifiers (Phase-2 PLONK + Phase-3 `HyperPlonk`, Halo2, Nova) all
//! depending on the same five modules, extraction into a dedicated
//! crate:
//!
//! - removes the PLONK-specific dependency each consumer had to carry,
//! - lets the primitive layer evolve independently of any single
//!   verifier's compatibility concerns,
//! - reduces what a `cargo build -p mosaic-hyperplonk` pulls in —
//!   no more `mosaic-plonk::linearization`, `::challenges`, etc.
//!
//! ## What's here
//!
//! - [`fr`] — byte-level Fr range helpers (no arkworks dependency).
//! - [`field`] — arkworks-backed Fr arithmetic (multiplication,
//!   inversion, Lagrange basis, public-input polynomial evaluation).
//! - [`msm`] — G1 multi-scalar multiplication primitive driving the
//!   linearization commitments.
//! - [`transcript`] — Keccak-256 Fiat-Shamir transcript with reset/
//!   absorb/squeeze API.
//! - [`g1_consts`] — G1/G2 generator encoders + the canonical
//!   Mosaic wire-format bytes of the BN254 generators.
//!
//! ## What's NOT here
//!
//! Verifier-specific code: gate expressions, permutation arguments,
//! lookup arguments, canonical proof layouts. Those stay in the
//! per-verifier crates.
//!
//! ## History
//!
//! Before v0.5.0 these modules lived at
//! `mosaic_plonk::{fr,field,msm,transcript,g1_consts}`. For backward
//! compatibility that crate re-exports from here so downstream code
//! that still imports via `mosaic_plonk::*` continues to work.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod field;
pub mod fr;
pub mod g1_consts;
pub mod msm;
pub mod transcript;
