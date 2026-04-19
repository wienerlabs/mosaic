//! Halo2-KZG transcript bytes adapter.
//!
//! TODO(mosaic-011): Phase 2.

use mosaic_core::{
    codec::{FormatTag, ProofCodec},
    OnChainError,
};
use std::vec::Vec;

/// Halo2-KZG codec — currently a stub.
#[derive(Copy, Clone, Debug, Default)]
pub struct Halo2KzgCodec;

impl Halo2KzgCodec {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofCodec for Halo2KzgCodec {
    fn format(&self) -> FormatTag {
        FormatTag::Halo2Kzg
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
