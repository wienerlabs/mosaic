//! gnark binary proof format adapter.
//!
//! TODO(mosaic-010): Phase 2.
//!
//! gnark serializes points in a packed form distinct from snarkjs and
//! arkworks; precise byte layout is documented at
//! <https://docs.gnark.consensys.io/HowTo/serialize>.

use mosaic_core::{
    codec::{FormatTag, ProofCodec},
    OnChainError,
};
use std::vec::Vec;

/// gnark codec — currently a stub.
#[derive(Copy, Clone, Debug, Default)]
pub struct GnarkCodec;

impl GnarkCodec {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofCodec for GnarkCodec {
    fn format(&self) -> FormatTag {
        FormatTag::Gnark
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
