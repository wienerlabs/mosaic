//! Risc0 receipt journal+seal bytes adapter.
//!
//! TODO(mosaic-013): Phase 3.

use mosaic_core::{
    codec::{FormatTag, ProofCodec},
    OnChainError,
};
use std::vec::Vec;

/// Risc0 codec — currently a stub.
#[derive(Copy, Clone, Debug, Default)]
pub struct Risc0Codec;

impl Risc0Codec {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofCodec for Risc0Codec {
    fn format(&self) -> FormatTag {
        FormatTag::Risc0
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
