//! FRI-STARK verifier scaffold.
//!
//! Phase-2 freeze ships wire-format validation + a `ProofSystem` impl
//! returning `UnimplementedProofSystem`. Phase 3 lands the hash-based
//! verification body: trace/constraint Merkle checks, FRI low-degree
//! test across layers, out-of-domain quotient consistency, and the PoW
//! grinding check.
//!
//! ## Phase-3 round plan (for the implementer)
//!
//! ```text
//! verify(vk_bytes, proof_bytes, public_inputs_bytes):
//!     vk    = FriStarkVerifyingKey::from_bytes(vk_bytes)?;    // done
//!     proof = FriStarkProof::from_bytes(proof_bytes)?;        // done
//!     assert_eq!(vk.field_id, proof.field_id);
//!     assert_eq!(vk.trace_width, proof.trace_width);
//!
//!     // ---- Phase 3 work starts here ----
//!
//!     // Seed transcript from VK + public inputs + trace commitment.
//!     let mut t = ShaTranscript::new(vk.air_hash);
//!     t.absorb(public_inputs_bytes);
//!     t.absorb(proof.trace_commitment);
//!
//!     // Constraint composition challenges.
//!     let alpha = t.squeeze();                        // linear combiner
//!     t.absorb(proof.constraint_commitment);
//!
//!     // FRI commit phase — absorb each layer root, squeeze beta.
//!     let betas: Vec<Fr> = proof.fri_layer_iter()
//!         .map(|root| { t.absorb(root); t.squeeze() })
//!         .collect();
//!
//!     // Out-of-domain evaluations consistency check:
//!     //   constraint(z) ?= sum_i alpha^i · quotient_i(z)
//!     // where z is squeezed out-of-domain after FRI commits.
//!     let z = t.squeeze();
//!     for eval in proof.ood_evals_iter() { t.absorb(eval); }
//!     verify_ood_quotient_consistency(&vk, &proof, alpha, z)?;
//!
//!     // Query phase — expand PoW nonce, then N_queries random indices.
//!     verify_pow(&t, proof.pow_bits, proof.pow_nonce)?;
//!     for _ in 0..proof.num_queries {
//!         let idx = t.squeeze_query_index(proof.trace_log_height + proof.log_blowup);
//!         verify_fri_query_path(&vk, &proof, idx, &betas)?;
//!         verify_trace_auth_path(&vk, &proof, idx)?;
//!         verify_constraint_auth_path(&vk, &proof, idx)?;
//!     }
//!
//!     // Final FRI layer — constant polynomial check.
//!     verify_fri_final_poly(&proof, &betas)?;
//!
//!     Ok(())
//! ```
//!
//! ## SBF-specific implementation notes
//!
//! - `#[inline(never)]` every FRI layer helper. The inner loops touch
//!   dozens of 32-byte digests; without outlining, stack frames easily
//!   exceed the 4 KB cap.
//! - Prefer `solana_keccak::hashv` (multi-input) over per-absorb hashes
//!   — one syscall dispatch amortizes across the whole absorb payload.
//! - Goldilocks Fr arithmetic can be implemented in pure Rust (no
//!   arkworks dependency) — single 64-bit modulus, no Montgomery form.
//! - Merkle auth path decoding should walk a packed byte buffer rather
//!   than `Vec<Vec<u8>>` to avoid per-node heap churn.
//!
//! ## Proof delivery
//!
//! Real proofs (30 KB+) exceed the 1232 B per-tx Solana limit. The
//! `mosaic-chunked` protocol is the expected delivery path:
//!
//! 1. Client `InitializeSession` with expected total size + proof hash.
//! 2. Multiple `AppendChunk` writes accumulate bytes + rolling SHA-256.
//! 3. `CommitAndVerify` reassembles the buffer and invokes
//!    `mosaic-program::dispatch_verify` with `ProofSystemId::FriStark`.

use crate::canonical::{FriStarkProof, FriStarkVerifyingKey};
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};

/// FRI-STARK verifier. Phase-3 scaffold.
///
/// Generic over the syscall backend so host-side oracle (arkworks / host
/// hashes) and on-chain (`solana_program::hash`) implementations share
/// the same algorithm body.
pub struct FriStark<'a, B: SyscallBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: SyscallBackend + ?Sized> FriStark<'a, B> {
    /// Construct against an existing backend.
    #[must_use]
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    /// Phase-2 scaffolding: parse byte layout, cross-check VK vs proof
    /// field-id + trace width, return `UnimplementedProofSystem`.
    /// Phase 3 wires the full hash-based verifier body per the
    /// module-level plan.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        _public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        let vk = FriStarkVerifyingKey::from_bytes(vk_bytes)?;
        let proof = FriStarkProof::from_bytes(proof_bytes)?;

        // Cross-consistency: VK must match proof's field + trace shape.
        // Catches VK/proof pair mismatches early — real verifier body
        // would produce garbage challenges and fail cryptographically,
        // but surfacing the configuration mismatch is a clearer error.
        if vk.field_id != proof.field_id
            || vk.trace_width != proof.trace_width
            || vk.trace_log_height != proof.trace_log_height
            || vk.log_blowup != proof.log_blowup
        {
            return Err(OnChainError::VerifyingKeyProofMismatch);
        }

        // Backend will be used in Phase 3 (SHA-256 absorbs for FRI +
        // Merkle verification). Drop reference to silence warnings.
        let _ = self.backend;
        Err(OnChainError::UnimplementedProofSystem)
    }
}

impl<B: SyscallBackend + ?Sized + Send + Sync + 'static> ProofSystem for FriStark<'_, B> {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::FriStark
    }

    fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        Self::verify(self, vk_bytes, proof_bytes, public_inputs_bytes)
    }

    fn estimated_compute_units(&self, _vk: &[u8], _proof: &[u8]) -> Option<u32> {
        // ADR-0005 budget: ≤14M CU (max-compute tier). Phase-3
        // implementation will return a tight per-proof estimate based
        // on num_queries × (fri_layers + 2 auth paths); for now return
        // the upper bound so callers can size compute_unit_limit safely.
        Some(14_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{sizes, StarkFieldId};
    use alloc::vec;

    struct MockBackend;
    impl SyscallBackend for MockBackend {
        fn alt_bn128_group_op(
            &self,
            _op: mosaic_core::syscall::AltBn128Op,
            _endianness: mosaic_core::syscall::InputEndianness,
            _input: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, OnChainError> {
            Err(OnChainError::UnsupportedOperation)
        }
        fn alt_bn128_compression(
            &self,
            _op: mosaic_core::syscall::AltBn128Compress,
            _input: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, OnChainError> {
            Err(OnChainError::UnsupportedOperation)
        }
        fn poseidon(
            &self,
            _params: mosaic_core::syscall::PoseidonParameters,
            _endianness: mosaic_core::syscall::InputEndianness,
            _inputs: &[&[u8]],
        ) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::UnimplementedProofSystem)
        }
        fn sha256(&self, _inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::Sha256SyscallFailed)
        }
        fn keccak256(&self, _inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::Keccak256SyscallFailed)
        }
    }

    fn proof_bytes(field: StarkFieldId, num_fri: u8, num_q: u16, log_h: u16, width: u32) -> Vec<u8> {
        let ood_bytes = 10 * field.field_elem_bytes();
        let final_bytes = 4 * field.field_elem_bytes();
        let query_bytes = (num_q as usize) * 64;
        let total = sizes::FIXED_HEADER_LEN
            + 2 * sizes::DIGEST_LEN
            + (num_fri as usize) * sizes::DIGEST_LEN
            + 4 + ood_bytes + 4 + final_bytes + 4 + query_bytes
            + sizes::POW_NONCE_LEN;
        let mut buf = vec![0u8; total];
        buf[0] = field as u8;
        buf[1] = 1; // log_blowup
        buf[2] = num_fri;
        buf[4..6].copy_from_slice(&num_q.to_le_bytes());
        buf[6..8].copy_from_slice(&log_h.to_le_bytes());
        buf[8..12].copy_from_slice(&width.to_le_bytes());
        let mut off = sizes::FIXED_HEADER_LEN
            + 2 * sizes::DIGEST_LEN
            + (num_fri as usize) * sizes::DIGEST_LEN;
        buf[off..off + 4].copy_from_slice(&(ood_bytes as u32).to_le_bytes());
        off += 4 + ood_bytes;
        buf[off..off + 4].copy_from_slice(&(final_bytes as u32).to_le_bytes());
        off += 4 + final_bytes;
        buf[off..off + 4].copy_from_slice(&(query_bytes as u32).to_le_bytes());
        buf
    }

    fn matching_vk(field: StarkFieldId, log_h: u16, width: u32) -> Vec<u8> {
        FriStarkVerifyingKey {
            field_id: field,
            trace_width: width,
            trace_log_height: log_h,
            log_blowup: 1,
            air_hash: [0; 32],
        }
        .to_bytes()
    }

    #[test]
    fn parses_wire_before_returning_unimplemented() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 16, 32);
        let proof = proof_bytes(StarkFieldId::Goldilocks, 16, 80, 16, 32);
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(matches!(r, Err(OnChainError::UnimplementedProofSystem)));
    }

    #[test]
    fn rejects_vk_proof_field_mismatch() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        // VK says Goldilocks, proof says BabyBear.
        let vk = matching_vk(StarkFieldId::Goldilocks, 10, 8);
        let proof = proof_bytes(StarkFieldId::BabyBear, 4, 10, 10, 8);
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyProofMismatch)));
    }

    #[test]
    fn rejects_vk_proof_trace_width_mismatch() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 16, 32);
        let proof = proof_bytes(StarkFieldId::Goldilocks, 8, 40, 16, 64); // width 64 ≠ 32
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyProofMismatch)));
    }

    #[test]
    fn rejects_wrong_vk_length() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        let bad_vk = vec![0u8; FriStarkVerifyingKey::SERIALIZED_LEN - 1];
        let proof = proof_bytes(StarkFieldId::Goldilocks, 4, 10, 10, 4);
        let r = FriStark::verify(&v, &bad_vk, &proof, &[]);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_proof_length() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 16, 32);
        let bad_proof = vec![0u8; 8]; // way too short
        let r = FriStark::verify(&v, &vk, &bad_proof, &[]);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn estimated_cu_returns_adr_cap() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        assert_eq!(
            ProofSystem::estimated_compute_units(&v, &[], &[]),
            Some(14_000_000),
        );
    }

    #[test]
    fn proof_system_id_is_fri_stark() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        assert_eq!(v.proof_system_id(), ProofSystemId::FriStark);
    }

    #[allow(dead_code)]
    fn boxed(v: FriStark<'static, MockBackend>) -> alloc::boxed::Box<dyn ProofSystem> {
        alloc::boxed::Box::new(v)
    }
}
