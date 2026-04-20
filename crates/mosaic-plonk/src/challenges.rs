//! PLONK Fiat-Shamir challenge derivation — rounds 1-6.
//!
//! Produces the six challenges the verifier needs:
//!
//! | Round | Challenge | Absorbs (fresh transcript per round) |
//! |---|---|---|
//! | 2a    | β         | Qm, Ql, Qr, Qo, Qc, S1, S2, S3 selectors; public inputs; proof A, B, C |
//! | 2b    | γ         | β |
//! | 3     | α         | β, γ, proof.Z |
//! | 4     | ξ         | α, proof.T1, proof.T2, proof.T3 |
//! | 5     | v         | ξ, eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw |
//! | 6     | u         | v, proof.W_xi, proof.W_xiw |
//!
//! Absorb ordering matches the snarkjs 0.7.x PLONK verifier. gnark and
//! arkworks PLONK implementations use slightly different orderings; a
//! future adapter in `mosaic-serde::gnark` will route through a
//! configurable transcript rather than forking this module.

use crate::{
    canonical::{sizes::G1_LEN, PlonkProof, PlonkVerifyingKey},
    fr,
    transcript::{Kind, Transcript},
};
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// All six Fiat-Shamir challenges for a single PLONK proof, as 32-byte
/// big-endian Fr elements.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RoundChallenges {
    /// Permutation argument β.
    pub beta: [u8; 32],
    /// Permutation argument γ.
    pub gamma: [u8; 32],
    /// Quotient separation α.
    pub alpha: [u8; 32],
    /// Evaluation point ξ.
    pub xi: [u8; 32],
    /// Linearization batch v.
    pub v: [u8; 32],
    /// Opening batch u.
    pub u: [u8; 32],
}

impl RoundChallenges {
    /// Derive all six challenges from VK + proof + public inputs using
    /// the snarkjs-compatible absorb ordering.
    ///
    /// `public_inputs_bytes` must be `vk.n_public * 32` big-endian Fr
    /// elements concatenated. All inputs are treated as public — no
    /// constant-time guarantees here.
    pub fn derive<B: SyscallBackend + ?Sized>(
        backend: &B,
        vk: &PlonkVerifyingKey,
        proof: &PlonkProof<'_>,
        public_inputs_bytes: &[u8],
    ) -> Result<Self, OnChainError> {
        let expected_pi_len = (vk.n_public as usize).checked_mul(32)
            .ok_or(OnChainError::PublicInputCountMismatch)?;
        if public_inputs_bytes.len() != expected_pi_len {
            return Err(OnChainError::PublicInputCountMismatch);
        }
        // Every public-input byte-array must be in Fr range; this mirrors
        // the Groth16 verifier's guard and prevents small-subgroup-style
        // mischief. Each chunk is 32 bytes.
        for chunk in public_inputs_bytes.chunks_exact(32) {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(chunk);
            if !fr::lt_r(&buf) {
                return Err(OnChainError::PublicInputOutOfRange);
            }
        }

        let mut transcript = Transcript::new(Kind::Keccak256, backend);

        // ---------- Round 2a: β ----------
        transcript.absorb_g1(&vk.qm_g1)?;
        transcript.absorb_g1(&vk.ql_g1)?;
        transcript.absorb_g1(&vk.qr_g1)?;
        transcript.absorb_g1(&vk.qo_g1)?;
        transcript.absorb_g1(&vk.qc_g1)?;
        transcript.absorb_g1(&vk.s1_g1)?;
        transcript.absorb_g1(&vk.s2_g1)?;
        transcript.absorb_g1(&vk.s3_g1)?;
        transcript.absorb(public_inputs_bytes);
        transcript.absorb_g1(proof.a)?;
        transcript.absorb_g1(proof.b)?;
        transcript.absorb_g1(proof.c)?;
        let beta = transcript.get_challenge()?;

        // ---------- Round 2b: γ ----------
        transcript.reset();
        transcript.absorb_fr(&beta)?;
        let gamma = transcript.get_challenge()?;

        // ---------- Round 3: α ----------
        transcript.reset();
        transcript.absorb_fr(&beta)?;
        transcript.absorb_fr(&gamma)?;
        transcript.absorb_g1(proof.z)?;
        let alpha = transcript.get_challenge()?;

        // ---------- Round 4: ξ ----------
        transcript.reset();
        transcript.absorb_fr(&alpha)?;
        transcript.absorb_g1(proof.t1)?;
        transcript.absorb_g1(proof.t2)?;
        transcript.absorb_g1(proof.t3)?;
        let xi = transcript.get_challenge()?;

        // ---------- Round 5: v ----------
        transcript.reset();
        transcript.absorb_fr(&xi)?;
        transcript.absorb_fr(proof.eval_a)?;
        transcript.absorb_fr(proof.eval_b)?;
        transcript.absorb_fr(proof.eval_c)?;
        transcript.absorb_fr(proof.eval_s1)?;
        transcript.absorb_fr(proof.eval_s2)?;
        transcript.absorb_fr(proof.eval_zw)?;
        let v = transcript.get_challenge()?;

        // ---------- Round 6: u ----------
        transcript.reset();
        transcript.absorb_fr(&v)?;
        transcript.absorb_g1(proof.w_xi)?;
        transcript.absorb_g1(proof.w_xiw)?;
        let u = transcript.get_challenge()?;

        debug_assert_eq!(G1_LEN, 64); // sanity — absorb_g1 expects 64 B
        Ok(Self { beta, gamma, alpha, xi, v, u })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FR_LEN, G2_LEN, PROOF_LEN};
    use mosaic_core::syscall::SyscallBackend;

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

    fn zero_vk(n_public: u32) -> PlonkVerifyingKey {
        PlonkVerifyingKey {
            qm_g1: [0; G1_LEN], ql_g1: [0; G1_LEN],
            qr_g1: [0; G1_LEN], qo_g1: [0; G1_LEN],
            qc_g1: [0; G1_LEN],
            s1_g1: [0; G1_LEN], s2_g1: [0; G1_LEN],
            s3_g1: [0; G1_LEN],
            x2_g2: [0; G2_LEN], power: 10,
            k1: [0; FR_LEN], k2: [0; FR_LEN], omega: [0; FR_LEN],
            n_public,
        }
    }

    #[test]
    fn derive_is_deterministic() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
        let pi = [0u8; FR_LEN];

        let c1 = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
        let c2 = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn derive_changes_with_public_inputs() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();

        let mut pi1 = [0u8; FR_LEN];
        pi1[FR_LEN - 1] = 1;
        let mut pi2 = [0u8; FR_LEN];
        pi2[FR_LEN - 1] = 2;

        let c1 = RoundChallenges::derive(&backend, &vk, &proof, &pi1).unwrap();
        let c2 = RoundChallenges::derive(&backend, &vk, &proof, &pi2).unwrap();
        // β depends on public inputs (absorbed directly); changing PI must
        // change β and therefore every downstream challenge.
        assert_ne!(c1.beta, c2.beta);
        assert_ne!(c1.gamma, c2.gamma);
        assert_ne!(c1.alpha, c2.alpha);
        assert_ne!(c1.xi, c2.xi);
    }

    #[test]
    fn derive_rejects_wrong_public_input_count() {
        let backend = MockBackend;
        let vk = zero_vk(2); // expects 2 × 32 = 64 bytes
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
        let bad_pi = [0u8; FR_LEN]; // only 32 bytes

        assert!(matches!(
            RoundChallenges::derive(&backend, &vk, &proof, &bad_pi),
            Err(OnChainError::PublicInputCountMismatch),
        ));
    }

    #[test]
    fn derive_rejects_out_of_range_public_input() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
        let bad_pi = fr::BN254_FR_MODULUS_BE; // exactly r, out of range

        assert!(matches!(
            RoundChallenges::derive(&backend, &vk, &proof, &bad_pi),
            Err(OnChainError::PublicInputOutOfRange),
        ));
    }

    #[test]
    fn all_challenges_in_fr_range() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
        let pi = [0u8; FR_LEN];

        let c = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
        for challenge in [c.beta, c.gamma, c.alpha, c.xi, c.v, c.u] {
            assert!(fr::lt_r(&challenge));
        }
    }

    #[test]
    fn different_proofs_produce_different_challenges() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let pi = [0u8; FR_LEN];

        let proof_a_bytes = [0x11u8; PROOF_LEN];
        let proof_a = PlonkProof::from_bytes(&proof_a_bytes).unwrap();
        let c_a = RoundChallenges::derive(&backend, &vk, &proof_a, &pi).unwrap();

        let proof_b_bytes = [0x22u8; PROOF_LEN];
        let proof_b = PlonkProof::from_bytes(&proof_b_bytes).unwrap();
        let c_b = RoundChallenges::derive(&backend, &vk, &proof_b, &pi).unwrap();

        assert_ne!(c_a.beta, c_b.beta);
        assert_ne!(c_a.u, c_b.u);
    }
}
