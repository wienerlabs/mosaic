//! `ProofCodec` trait for format-tagged serialization adapters.
//!
//! Each upstream proving framework — `snarkjs`, `arkworks`, `gnark`,
//! `halo2-kzg`, `plonky3`, `risc0` — emits proofs and verifying keys in its
//! own native format. The Mosaic on-chain verifier consumes a single
//! canonical byte layout per proof system, so the off-chain SDK runs the
//! adapter pipeline:
//!
//! ```text
//! framework_format  ─┐
//!                    ├──▶  ProofCodec::decode  ──▶  canonical bytes  ──▶  on-chain
//! framework_format  ─┘                                                ──▶  ProofSystem::verify
//! ```
//!
//! Concrete codecs live in the `mosaic-serde` crate; this trait + the
//! `FormatTag` enum are the contract.

use crate::error::OnChainError;
use alloc::vec::Vec;

extern crate alloc;

/// Stable identifier for upstream proof formats.
///
/// As with [`crate::proof_system::ProofSystemId`], the discriminant is wire-stable.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FormatTag {
    /// Mosaic canonical format (no adapter required).
    Canonical = 0x00,
    /// `snarkjs` JSON output (Circom pipeline).
    SnarkjsJson = 0x01,
    /// arkworks `CanonicalSerialize` output.
    Arkworks = 0x02,
    /// gnark binary proof format.
    Gnark = 0x03,
    /// Halo2-KZG transcript bytes (privacy-scaling-explorations layout).
    Halo2Kzg = 0x04,
    /// Plonky3 STARK proof bytes.
    Plonky3 = 0x05,
    /// Risc0 receipt journal+seal bytes.
    Risc0 = 0x06,
}

/// Codec that converts upstream `Source` byte streams (or structured input)
/// into Mosaic's canonical wire format for a given proof system.
pub trait ProofCodec {
    /// The format this codec handles.
    fn format(&self) -> FormatTag;

    /// Decode an upstream proof into canonical bytes.
    fn decode_proof(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError>;

    /// Decode an upstream verifying key into canonical bytes.
    fn decode_vk(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError>;

    /// Decode upstream public inputs into canonical bytes.
    fn decode_public_inputs(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError>;
}

/// Convenience bundle decoded by an adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedArtifacts {
    /// Canonical-format verifying key.
    pub vk: Vec<u8>,
    /// Canonical-format proof.
    pub proof: Vec<u8>,
    /// Canonical-format public inputs (concatenated big-endian field elements).
    pub public_inputs: Vec<u8>,
}
