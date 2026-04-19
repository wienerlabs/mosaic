//! # mosaic-serde
//!
//! Format adapters that translate proofs and verifying keys from upstream
//! frameworks into Mosaic canonical bytes (see `mosaic_groth16::canonical`
//! for Groth16's canonical layout).
//!
//! ## Adapter status
//!
//! | Format | Module | Status |
//! |---|---|---|
//! | `Canonical` | none | identity codec, exists in [`mosaic_core::codec`] |
//! | `SnarkjsJson` | [`snarkjs`] | implemented (Groth16 only) |
//! | `Arkworks` | [`arkworks`] | implemented (Groth16 only) |
//! | `Gnark` | [`gnark`] | TODO(mosaic-010) — Phase 2 |
//! | `Halo2Kzg` | [`halo2`] | TODO(mosaic-011) — Phase 2 |
//! | `Plonky3` | [`plonky3`] | TODO(mosaic-012) — Phase 3 |
//! | `Risc0` | [`risc0`] | TODO(mosaic-013) — Phase 3 |

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
compile_error!("mosaic-serde requires the `std` feature");

pub mod arkworks;
pub mod gnark;
pub mod halo2;
pub mod plonky3;
pub mod risc0;
pub mod snarkjs;

pub use mosaic_core::codec::{DecodedArtifacts, FormatTag, ProofCodec};
