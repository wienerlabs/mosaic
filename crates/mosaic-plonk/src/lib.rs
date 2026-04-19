//! # mosaic-plonk
//!
//! BN254 KZG-PLONK verifier — **Phase 2** target. Crate exists today only to
//! keep the workspace resolver and CI matrix stable; all verification entry
//! points return [`OnChainError::UnimplementedProofSystem`].
//!
//! Tracking issue: TODO(mosaic-002) — wire halo2-kzg-style verifier with
//! BN254 syscall pairings.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    OnChainError,
};

/// Placeholder verifier. Returns [`OnChainError::UnimplementedProofSystem`] on every call.
#[derive(Copy, Clone, Debug, Default)]
pub struct PlonkKzgBn254;

impl PlonkKzgBn254 {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofSystem for PlonkKzgBn254 {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::PlonkKzgBn254
    }

    fn verify(&self, _vk: &[u8], _proof: &[u8], _pi: &[u8]) -> Result<(), OnChainError> {
        // TODO(mosaic-002): implement KZG-PLONK verifier.
        Err(OnChainError::UnimplementedProofSystem)
    }

    fn estimated_compute_units(&self, _vk: &[u8], _proof: &[u8]) -> Option<u32> {
        // Documented target: ≤600K CU. Returning the budget so the dispatcher
        // can early-exit if the host transaction CU limit is below this.
        Some(600_000)
    }
}
