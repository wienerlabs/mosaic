//! PLONK verifier.
//!
//! **Session 1 status**: wire-format validation + rounds 1-6 Fiat-Shamir
//! challenge derivation wired. Linearization polynomial reconstruction
//! and the KZG batched opening pairing check return
//! `UnimplementedProofSystem`. Session 2 lands those steps.
//!
//! ## Round-by-round plan
//!
//! ```text
//! verify(vk_bytes, proof_bytes, public_inputs_bytes):
//!     vk    = PlonkVerifyingKey::from_bytes(vk_bytes)?          // done
//!     proof = PlonkProof::from_bytes(proof_bytes)?              // done
//!     pi    = check_public_inputs(public_inputs_bytes)?         // done (range check)
//!
//!     c = RoundChallenges::derive(backend, &vk, &proof, &pi)?   // done (session 1)
//!
//!     // ---- session 2 work starts here ----
//!
//!     let xi_n         = pow_fr(&c.xi, 1u64 << vk.power);
//!     let l1_xi        = lagrange_basis_one(&c.xi, &xi_n, &vk.omega);
//!     let pi_xi        = evaluate_public_input_poly(&pi, &c.xi, &vk.omega, &xi_n);
//!
//!     let r_g1 = linearization_msm(&c, &vk, &proof, l1_xi, pi_xi)?;
//!
//!     // Batched KZG opening: one pairing with two (G1, G2) pairs.
//!     let pairing_result = backend.alt_bn128_group_op(Pairing, BE, &pair_input)?;
//!     if pairing_result[31] != 0x01 { return Err(PairingCheckFailed); }
//!     Ok(())
//! ```

use crate::{
    canonical::{PlonkProof, PlonkVerifyingKey},
    challenges::RoundChallenges,
};
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};

/// BN254 KZG-PLONK verifier. Holds a reference to the syscall backend
/// used for Fiat-Shamir challenge derivation and (in session 2) for the
/// linearization MSM + KZG pairing check.
///
/// Generic over `B` so the same type drives both host tests (via
/// `HostBackend`) and on-chain code (via `SolanaSyscallBackend`).
pub struct PlonkKzgBn254<'a, B: SyscallBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: SyscallBackend + ?Sized> PlonkKzgBn254<'a, B> {
    /// Construct against an existing backend.
    #[must_use]
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    /// Perform the full verifier pipeline.
    ///
    /// Session 1 wires steps 1-3 (parse + range check + challenge
    /// derivation); the linearization MSM and KZG pairing check return
    /// `UnimplementedProofSystem`. See the module doc for the plan.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        let vk = PlonkVerifyingKey::from_bytes(vk_bytes)?;
        let proof = PlonkProof::from_bytes(proof_bytes)?;

        // Fiat-Shamir challenge derivation. After this point, `_challenges`
        // holds β, γ, α, ξ, v, u — consumed by session-2 code.
        let _challenges =
            RoundChallenges::derive(self.backend, &vk, &proof, public_inputs_bytes)?;

        // TODO(mosaic-001): session 2 — linearization MSM + KZG pairing.
        Err(OnChainError::UnimplementedProofSystem)
    }
}

impl<B: SyscallBackend + ?Sized + Send + Sync + 'static> ProofSystem for PlonkKzgBn254<'_, B> {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::PlonkKzgBn254
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
        Some(600_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FR_LEN, G1_LEN, G2_LEN, PROOF_LEN, VK_HEADER_LEN};
    use mosaic_core::syscall::SyscallBackend;

    struct KeccakMockBackend;
    impl SyscallBackend for KeccakMockBackend {
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
        fn keccak256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            use tiny_keccak::{Hasher, Keccak};
            let mut h = Keccak::v256();
            for i in inputs {
                h.update(i);
            }
            let mut out = [0u8; 32];
            h.finalize(&mut out);
            Ok(out)
        }
    }

    fn dummy_vk_bytes(n_public: u32) -> alloc::vec::Vec<u8> {
        PlonkVerifyingKey {
            qm_g1: [0; G1_LEN], ql_g1: [0; G1_LEN],
            qr_g1: [0; G1_LEN], qo_g1: [0; G1_LEN],
            qc_g1: [0; G1_LEN],
            s1_g1: [0; G1_LEN], s2_g1: [0; G1_LEN],
            s3_g1: [0; G1_LEN],
            x2_g2: [0; G2_LEN], power: 10,
            k1: [0; FR_LEN], k2: [0; FR_LEN],
            omega: [0; FR_LEN], n_public,
        }
        .to_bytes()
    }

    #[test]
    fn verify_derives_challenges_then_returns_unimplemented() {
        let backend = KeccakMockBackend;
        let v = PlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes(1);
        let proof = alloc::vec![0u8; PROOF_LEN];
        let pi = alloc::vec![0u8; FR_LEN];
        let r = PlonkKzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::UnimplementedProofSystem)));
    }

    #[test]
    fn verify_rejects_wrong_vk_length_before_deriving() {
        let backend = KeccakMockBackend;
        let v = PlonkKzgBn254::new(&backend);
        let bad_vk = alloc::vec![0u8; VK_HEADER_LEN - 1];
        let proof = alloc::vec![0u8; PROOF_LEN];
        let pi = alloc::vec![0u8; FR_LEN];
        let r = PlonkKzgBn254::verify(&v, &bad_vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn verify_rejects_wrong_proof_length_before_deriving() {
        let backend = KeccakMockBackend;
        let v = PlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes(1);
        let bad_proof = alloc::vec![0u8; PROOF_LEN - 1];
        let pi = alloc::vec![0u8; FR_LEN];
        let r = PlonkKzgBn254::verify(&v, &vk, &bad_proof, &pi);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn verify_rejects_out_of_range_public_input() {
        let backend = KeccakMockBackend;
        let v = PlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes(1);
        let proof = alloc::vec![0u8; PROOF_LEN];
        let bad_pi: alloc::vec::Vec<u8> = crate::fr::BN254_FR_MODULUS_BE.to_vec();
        let r = PlonkKzgBn254::verify(&v, &vk, &proof, &bad_pi);
        assert!(matches!(r, Err(OnChainError::PublicInputOutOfRange)));
    }

    #[test]
    fn estimated_compute_units_returns_adr_target() {
        let backend = KeccakMockBackend;
        let v = PlonkKzgBn254::new(&backend);
        assert_eq!(
            ProofSystem::estimated_compute_units(&v, &[], &[]),
            Some(600_000),
        );
    }

    /// Object-safety smoke test: this must compile.
    #[allow(dead_code)]
    fn boxed(v: PlonkKzgBn254<'static, KeccakMockBackend>) -> alloc::boxed::Box<dyn ProofSystem> {
        alloc::boxed::Box::new(v)
    }
}
