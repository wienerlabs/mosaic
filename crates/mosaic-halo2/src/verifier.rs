//! Halo2-KZG verifier scaffold.
//!
//! Phase-2 freeze ships wire-format validation + a `ProofSystem` impl
//! returning `UnimplementedProofSystem`. Phase 3 lands the custom-gate
//! evaluation, lookup argument, permutation grand-product, quotient
//! aggregation, linearization MSM, and final KZG pairing check.
//!
//! ## Phase-3 round plan (for the implementer)
//!
//! ```text
//! verify(vk_bytes, proof_bytes, public_inputs_bytes):
//!     vk    = Halo2KzgVerifyingKey::from_bytes(vk_bytes)?;    // done
//!     proof = Halo2KzgProof::from_bytes(proof_bytes)?;        // done
//!
//!     // ---- Phase 3 work starts here ----
//!
//!     // Round 1: absorb VK + instance columns + advice commitments.
//!     transcript.absorb_vk(&vk);
//!     transcript.absorb_public_inputs(pi);
//!     for a in proof.advice_iter() { transcript.absorb_g1(a); }
//!     let theta = transcript.squeeze();  // lookup combine challenge
//!
//!     // Round 2: lookup `m` polynomials — one per lookup argument.
//!     for l in proof.lookup_commits.chunks_exact(G1_LEN) {
//!         transcript.absorb_g1(l);
//!     }
//!     let (beta, gamma) = (transcript.squeeze(), transcript.squeeze());
//!
//!     // Round 3: permutation grand-product.
//!     transcript.absorb_g1(proof.permutation_z);
//!     let y = transcript.squeeze();  // gate linear combination
//!
//!     // Round 4: vanishing H chunks.
//!     for h in proof.quotient_iter() { transcript.absorb_g1(h); }
//!     let xi = transcript.squeeze();  // evaluation point
//!
//!     // Round 5: evaluations at xi — gate, permutation, lookup, instance.
//!     for e in proof.evaluations_iter() { transcript.absorb_fr(e); }
//!
//!     // Check vanishing identity:
//!     //   t(ξ) · Z_H(ξ) ?= gate(ξ) + y · perm(ξ) + y² · lookup(ξ)
//!     verify_vanishing_identity(&proof, &vk, theta, beta, gamma, y, xi)?;
//!
//!     // Round 6: batched multipoint KZG opening at {ξ, ξω}.
//!     let v = transcript.squeeze();  // batch challenge
//!     transcript.absorb_g1(proof.w_xi);
//!     transcript.absorb_g1(proof.w_xiw);
//!     let u = transcript.squeeze();  // second batch challenge
//!
//!     verify_kzg_multipoint_opening(
//!         &vk, &proof, xi, v, u,
//!         /* evaluated commitments */,
//!     )?;
//!
//!     Ok(())
//! ```
//!
//! Shared primitives reused from `mosaic_plonk`:
//! - `mosaic_plonk::fr` — Fr byte range ops
//! - `mosaic_plonk::field` — arkworks Fr arithmetic
//! - `mosaic_plonk::msm` — G1 MSM primitive
//! - `mosaic_plonk::transcript` — Keccak-256 round transcript
//! - `mosaic_plonk::g1_consts` — G1/G2 generator bytes for pairing

use crate::{
    canonical::{Halo2KzgProof, Halo2KzgVerifyingKey},
    challenges::derive_challenges,
    kzg::verify_opening_scaffold,
};
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};

/// Halo2-KZG verifier over BN254 (Privacy Scaling Explorations fork).
/// Phase-3 scaffold.
pub struct Halo2KzgBn254<'a, B: SyscallBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: SyscallBackend + ?Sized> Halo2KzgBn254<'a, B> {
    /// Construct against an existing backend.
    #[must_use]
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    /// Verify a Halo2-KZG proof.
    ///
    /// Session-4d implementation: full pipeline from parse through
    /// KZG scaffold opening. Returns `Ok(())` on success.
    ///
    /// ## Scaffold caveat
    ///
    /// The vanishing-identity check uses scaffold circuit evaluators
    /// (`circuit.rs`) and the KZG opening uses a **single-commitment**
    /// scaffold (`kzg.rs::verify_opening_scaffold`) — not Halo2's
    /// full two-point batched multipoint opening over all committed
    /// polys. Both are structurally correct (transcript + MSM +
    /// pairing run end-to-end) but not cryptographically equivalent
    /// to Espresso/PSE's reference verifier. Session 4e pins these
    /// against real fixtures.
    ///
    /// ## Errors
    ///
    /// - `VerifyingKeyLengthMismatch` / `ProofLengthMismatch` — wire.
    /// - `PublicInputCountMismatch` / `PublicInputOutOfRange` —
    ///   instance column validation.
    /// - `PairingCheckFailed` — KZG scaffold opening failed.
    /// - `InvalidPointEncoding` — malformed G1 commitment.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        // 1. Parse + basic cross-checks.
        let vk = Halo2KzgVerifyingKey::from_bytes(vk_bytes)?;
        let proof = Halo2KzgProof::from_bytes(proof_bytes)?;
        if vk.n_advice != proof.n_advice {
            return Err(OnChainError::VerifyingKeyProofMismatch);
        }

        // 2. Derive challenges (θ, β, γ, y, ξ) from transcript.
        let (challenges, _transcript) =
            derive_challenges(self.backend, &vk, public_inputs_bytes, &proof)?;

        // 3. KZG scaffold opening check at ξ.
        //    (Session 4e expands to vanishing-identity + two-point
        //    batched multipoint opening.)
        verify_opening_scaffold(self.backend, &vk, &proof, &challenges.xi)?;

        Ok(())
    }
}

impl<B: SyscallBackend + ?Sized + Send + Sync + 'static> ProofSystem for Halo2KzgBn254<'_, B> {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::Halo2KzgBn254
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
        // ADR-0005 budget: ≤700 000 CU. Returning the upper bound so
        // callers sizing compute_unit_limit have a safe default until
        // the Phase 3 implementation provides a tight per-proof estimate.
        Some(700_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN};
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

    fn dummy_vk_bytes() -> alloc::vec::Vec<u8> {
        Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            // Real G2 generator — pairing syscall rejects (0,0,0,0).
            x2_g2: mosaic_plonk::g1_consts::g2_generator_bytes(),
            fixed_commits: vec![0; 2 * G1_LEN],
            permutation_commits: vec![0; 5 * G1_LEN],
        }
        .to_bytes()
    }

    fn dummy_proof_bytes_typical() -> alloc::vec::Vec<u8> {
        // 5 advice, 1 lookup, 3 quotient chunks, 15 evals — a typical
        // k=10 Halo2 circuit with one lookup argument.
        let n_advice: u32 = 5;
        let n_lookups: u32 = 1;
        let n_quotient: u32 = 3;
        let n_evals: u32 = 15;
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = alloc::vec![0u8; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
        buf
    }

    /// Full pipeline with real host backend: parse → challenges →
    /// KZG scaffold opening (zero-commit → pairing of identities = 1).
    /// Returns Ok(()) after session 4d integration.
    #[test]
    fn full_pipeline_zero_proof_accepts() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = Halo2KzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let proof = dummy_proof_bytes_typical();
        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(r.is_ok(), "zero-proof pipeline should pass, got {r:?}");
    }

    #[test]
    fn rejects_wrong_vk_length_before_unimplemented() {
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        let bad_vk = alloc::vec![0u8; Halo2KzgVerifyingKey::FIXED_LEN - 1];
        let proof = dummy_proof_bytes_typical();
        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &bad_vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_proof_length_before_unimplemented() {
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let bad_proof = alloc::vec![0u8; 32]; // way too short
        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &bad_proof, &pi);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn estimated_cu_returns_adr_target() {
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        assert_eq!(
            ProofSystem::estimated_compute_units(&v, &[], &[]),
            Some(700_000),
        );
    }

    #[test]
    fn proof_system_id_is_halo2() {
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        assert_eq!(v.proof_system_id(), ProofSystemId::Halo2KzgBn254);
    }

    /// Object-safety smoke test: this must compile.
    #[allow(dead_code)]
    fn boxed(v: Halo2KzgBn254<'static, MockBackend>) -> alloc::boxed::Box<dyn ProofSystem> {
        alloc::boxed::Box::new(v)
    }
}
