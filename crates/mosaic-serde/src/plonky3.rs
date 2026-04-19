//! Plonky3 STARK proof bytes adapter.
//!
//! TODO(mosaic-012): Phase 3.

use mosaic_core::{
    codec::{FormatTag, ProofCodec},
    OnChainError,
};
use std::vec::Vec;

/// Plonky3 codec — currently a stub.
#[derive(Copy, Clone, Debug, Default)]
pub struct Plonky3Codec;

impl Plonky3Codec {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofCodec for Plonky3Codec {
    fn format(&self) -> FormatTag {
        FormatTag::Plonky3
    }
    fn decode_proof(&self, _src: &[u8]) -> Result<Vec<u8>, OnChainError> {
        Err(OnChainError::UnimplementedProofSystem)
    }
    fn decode_vk(&self, _src: &[u8]) -> Result<Vec<u8>, OnChainError> {
        Err(OnChainError::UnimplementedProofSystem)
    }
    fn decode_public_inputs(&self, _src: &[u8]) -> Result<Vec<u8>, OnChainError> {
        Err(OnChainError::UnimplementedProofSystem)
    }
}
