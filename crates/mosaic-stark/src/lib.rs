//! # mosaic-stark
//!
//! FRI-STARK verifier — **Phase 3** target. Designed around the eprint
//! 2025/1741 Winterfell-on-Solana technique: `sol_sha256` (`hashv`) syscall
//! batching, `#[inline(never)]` on FRI inner loops, and a bump arena
//! synchronized with the requested heap frame.
//!
//! Tracking issue: TODO(mosaic-003).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    OnChainError,
};

/// Placeholder FRI-STARK verifier. Real impl deferred to Phase 3.
#[derive(Copy, Clone, Debug, Default)]
pub struct FriStark;

impl FriStark {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofSystem for FriStark {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::FriStark
    }

    fn verify(&self, _vk: &[u8], _proof: &[u8], _pi: &[u8]) -> Result<(), OnChainError> {
        // TODO(mosaic-003): implement FRI verifier with hashv batching.
        Err(OnChainError::UnimplementedProofSystem)
    }

    fn estimated_compute_units(&self, _vk: &[u8], _proof: &[u8]) -> Option<u32> {
        // STARKs are CU-heavy; dispatcher must request 14M heap_frame.
        // Returning `None` because the real bound depends on proof size.
        None
    }
}
