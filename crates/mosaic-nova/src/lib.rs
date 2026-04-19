//! # mosaic-nova
//!
//! Folding-scheme verifier (Nova / HyperNova / ProtoStar) — **Phase 3** target.
//! Folding schemes accumulate proofs of incremental computation; the on-chain
//! verifier checks the final folded instance.
//!
//! Tracking issue: TODO(mosaic-004).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    OnChainError,
};

/// Placeholder Nova verifier.
#[derive(Copy, Clone, Debug, Default)]
pub struct Nova;

impl Nova {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofSystem for Nova {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::NovaFolding
    }

    fn verify(&self, _vk: &[u8], _proof: &[u8], _pi: &[u8]) -> Result<(), OnChainError> {
        // TODO(mosaic-004): implement Nova folding verifier.
        Err(OnChainError::UnimplementedProofSystem)
    }

    fn estimated_compute_units(&self, _vk: &[u8], _proof: &[u8]) -> Option<u32> {
        Some(900_000)
    }
}
