//! HyperPlonk verifier scaffold.
//!
//! Phase-2 freeze ships wire-format validation + a `ProofSystem` impl
//! returning `UnimplementedProofSystem`. Phase 3 lands the sumcheck +
//! linearization + pairing body.
//!
//! ## Phase-3 round plan (for the implementer)
//!
//! ```text
//! verify(vk_bytes, proof_bytes, public_inputs_bytes):
//!     vk    = HyperPlonkVerifyingKey::from_bytes(vk_bytes)?;     // done
//!     proof = HyperPlonkProof::from_bytes(proof_bytes)?;         // done
//!
//!     // ---- Phase 3 work starts here ----
//!
//!     // Round 1: absorb VK + public inputs + A/B/C/Z commitments.
//!     transcript.absorb_vk(&vk);
//!     transcript.absorb_public_inputs(pi);
//!     transcript.absorb_g1(proof.a);
//!     transcript.absorb_g1(proof.b);
//!     transcript.absorb_g1(proof.c);
//!     transcript.absorb_g1(proof.z);
//!     let alpha = transcript.squeeze();  // random linear combination
//!
//!     // Round 2 (sumcheck): verify the zero-check sumcheck over
//!     //   f(x) = alpha · gate_constraint(x) + permutation_term(x)
//!     // For each round r in 0..num_variables:
//!     //   absorb round polynomial p_r(X);
//!     //   squeeze challenge ξ_r;
//!     //   assert p_r(0) + p_r(1) == previous_claimed_value;
//!     //   update claimed_value = p_r(ξ_r);
//!     let final_claim = run_sumcheck(&transcript, proof.round_polys(), proof.sumcheck_rounds)?;
//!
//!     // Round 3: reduce MLE claims to a single univariate KZG opening.
//!     // At the sumcheck challenge point (ξ_0, ..., ξ_{n-1}):
//!     //   claim = alpha · gate(evals) + perm(evals, z_eval)
//!     // Verify via the final_evals bundle + proof.z_eval + proof.kzg_opening.
//!     verify_mle_evaluation_batched(
//!         &transcript, &vk, &proof.final_evals,
//!         &proof.kzg_opening, final_claim,
//!     )?;
//!
//!     Ok(())
//! ```
//!
//! Shared primitives consumed from `mosaic_plonk`:
//! - `mosaic_plonk::fr` — byte-level Fr range ops
//! - `mosaic_plonk::field` — arkworks Fr arithmetic
//! - `mosaic_plonk::msm` — G1 multi-scalar multiplication
//! - `mosaic_plonk::transcript` — Keccak-256 transcript (reuse the
//!   round-by-round absorb API)
//! - `mosaic_plonk::g1_consts` — G1/G2 generator bytes for KZG opening
//!   and final pairing check

use crate::canonical::{HyperPlonkProof, HyperPlonkVerifyingKey};
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};

/// HyperPlonk-KZG verifier over BN254. Phase-3 scaffold.
pub struct HyperPlonkKzgBn254<'a, B: SyscallBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: SyscallBackend + ?Sized> HyperPlonkKzgBn254<'a, B> {
    /// Construct against an existing backend.
    #[must_use]
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    /// Phase-2 scaffolding: parse byte layout, return
    /// `UnimplementedProofSystem`. Phase 3 wires the sumcheck + KZG
    /// reduction per the module-level plan.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        _public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        // Wire-format validation — catches byte-layout regressions in
        // Phase 2 before any verifier logic lands.
        let _vk = HyperPlonkVerifyingKey::from_bytes(vk_bytes)?;
        let _proof = HyperPlonkProof::from_bytes(proof_bytes)?;
        // The backend will be used in Phase 3 (transcript absorbs,
        // KZG opening verification). Drop reference to silence warnings.
        let _ = self.backend;
        Err(OnChainError::UnimplementedProofSystem)
    }
}

impl<B: SyscallBackend + ?Sized + Send + Sync + 'static> ProofSystem
    for HyperPlonkKzgBn254<'_, B>
{
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::HyperPlonkKzgBn254
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
        // ADR-0005 budget: ≤900 000 CU. Returning the upper bound so
        // callers sizing compute_unit_limit have a safe default until
        // the Phase 3 implementation provides a tight per-proof estimate.
        Some(900_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN, G1_LEN, SUMCHECK_POLY_LEN};

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

    fn dummy_vk_bytes() -> alloc::vec::Vec<u8> {
        HyperPlonkVerifyingKey {
            n_public: 1,
            num_variables: 10,
            x2_g2: [0; 128],
            gate_g1: [0; G1_LEN],
        }
        .to_bytes()
    }

    fn dummy_proof_bytes_10_rounds() -> alloc::vec::Vec<u8> {
        let polys_len = 10 * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        let mut buf = alloc::vec![0u8; total];
        buf[256..260].copy_from_slice(&10u32.to_le_bytes());
        buf
    }

    #[test]
    fn parses_wire_before_returning_unimplemented() {
        let backend = MockBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let proof = dummy_proof_bytes_10_rounds();
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::UnimplementedProofSystem)));
    }

    #[test]
    fn rejects_wrong_vk_length_before_unimplemented() {
        let backend = MockBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        let bad_vk = alloc::vec![0u8; HyperPlonkVerifyingKey::SERIALIZED_LEN - 1];
        let proof = dummy_proof_bytes_10_rounds();
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &bad_vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_proof_length_before_unimplemented() {
        let backend = MockBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let bad_proof = alloc::vec![0u8; 32]; // way too short
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &vk, &bad_proof, &pi);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn estimated_cu_returns_adr_target() {
        let backend = MockBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        assert_eq!(
            ProofSystem::estimated_compute_units(&v, &[], &[]),
            Some(900_000),
        );
    }

    #[test]
    fn proof_system_id_is_hyperplonk() {
        let backend = MockBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        assert_eq!(v.proof_system_id(), ProofSystemId::HyperPlonkKzgBn254);
    }

    /// Object-safety smoke test: this must compile.
    #[allow(dead_code)]
    fn boxed(v: HyperPlonkKzgBn254<'static, MockBackend>) -> alloc::boxed::Box<dyn ProofSystem> {
        alloc::boxed::Box::new(v)
    }
}
