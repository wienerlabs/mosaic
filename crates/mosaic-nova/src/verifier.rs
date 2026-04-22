//! Nova / HyperNova / ProtoStar folding verifier scaffold.
//!
//! Phase-2 freeze ships wire-format validation + a `ProofSystem` impl
//! returning `UnimplementedProofSystem`. Phase 3 lands the actual
//! folded-instance verification body: R1CS/CCS constraint check at the
//! folded point, cross-term consistency, and (if Spartan-wrapped) the
//! final KZG opening pairing.
//!
//! ## Phase-3 round plan (for the implementer)
//!
//! ```text
//! verify(vk_bytes, proof_bytes, public_inputs_bytes):
//!     vk    = NovaFoldingVerifyingKey::from_bytes(vk_bytes)?;   // done
//!     proof = NovaFoldingProof::from_bytes(proof_bytes)?;       // done
//!     assert_eq!(vk.variant, proof.variant);
//!     assert_eq!(vk.n_public, proof.n_public);
//!
//!     // ---- Phase 3 work starts here ----
//!
//!     // Absorb commitments to derive the folding challenge.
//!     let mut t = Transcript::new(vk.cs_digest);
//!     t.absorb_public_inputs(proof.public_inputs);
//!     t.absorb_g1(proof.e_comm);
//!     t.absorb_g1(proof.w_comm);
//!     t.absorb_g1(proof.t_comm);
//!     let r = t.squeeze();   // folding scalar challenge
//!
//!     // Reconstruct the folded RR1CS relation:
//!     //   A·z ∘ B·z == u · C·z + E
//!     // where z = (w, u, x) and operations are Hadamard products on
//!     // committed vectors. On-chain this reduces to three MSMs + one
//!     // cross-term check.
//!     let az_comm = msm_g1(&backend, vk.a_comm, z_scalars)?;
//!     let bz_comm = msm_g1(&backend, vk.b_comm, z_scalars)?;
//!     let cz_comm = msm_g1(&backend, vk.c_comm, z_scalars)?;
//!     verify_hadamard_relation(&az_comm, &bz_comm, &cz_comm,
//!                              proof.u, proof.e_comm)?;
//!
//!     // For HyperNova: add CCS higher-degree term checks.
//!     if matches!(proof.variant, FoldingVariant::HyperNova) {
//!         for aux in proof.aux_iter() {
//!             verify_hypernova_aux_commit(aux, r)?;
//!         }
//!     }
//!
//!     // Spartan-wrapped KZG opening at evaluation point ξ.
//!     let xi = t.squeeze();
//!     verify_kzg_opening_at_xi(&vk, &proof, xi, r)?;
//!
//!     Ok(())
//! ```
//!
//! Shared primitives consumed from `mosaic_plonk`:
//! - `mosaic_plonk::fr` — Fr byte range ops
//! - `mosaic_plonk::field` — arkworks Fr arithmetic (for folding scalar
//!   reductions)
//! - `mosaic_plonk::msm` — G1 MSM primitive (the dominant CU cost in
//!   the Hadamard relation check)
//! - `mosaic_plonk::transcript` — Keccak-256 round transcript
//! - `mosaic_plonk::g1_consts` — G1/G2 generator bytes for the final
//!   pairing check
//!
//! ## Implementation notes
//!
//! - The Hadamard relation check is the bulk of CU spend; a zero/one
//!   scalar shortcut in `msm_g1` would benefit Nova disproportionately
//!   because `z = (w, u, x)` often has many 0/1 entries for boolean
//!   R1CS wires.
//! - HyperNova's higher-degree terms collapse to the same MSM shape,
//!   just with more aux commits; the variant-specific code path is
//!   ~10 extra lines over vanilla Nova.
//! - ProtoStar adds a protocol-generic special-sound reduction; the
//!   first Phase-3 milestone targets Nova only, with HyperNova and
//!   ProtoStar landing in follow-up commits (tracked on issue #4).

use crate::{
    canonical::{NovaFoldingProof, NovaFoldingVerifyingKey},
    challenges::derive_challenges,
    kzg::verify_opening_scaffold,
};
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};

/// Nova-family folding verifier. Phase-3 scaffold.
pub struct NovaFolding<'a, B: SyscallBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: SyscallBackend + ?Sized> NovaFolding<'a, B> {
    /// Construct against an existing backend.
    #[must_use]
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    /// Verify a Nova / HyperNova / ProtoStar folding proof.
    ///
    /// Session-5c implementation: full pipeline from parse through
    /// KZG scaffold opening. Returns `Ok(())` on success.
    ///
    /// ## Scaffold caveat
    ///
    /// The Hadamard-relation check + folded-commitment reconstruction
    /// primitives are implemented in `folding.rs` and unit-tested,
    /// but not yet composed into the pipeline — the pipeline
    /// currently runs transcript challenges + a single-commitment
    /// KZG opening. Session 6 pins the full folded-instance check
    /// against `sonobe` reference fixtures and wires Hadamard +
    /// commitment reconstruction into the main flow.
    ///
    /// ## Errors
    ///
    /// - `VerifyingKeyLengthMismatch` / `ProofLengthMismatch` — wire.
    /// - `VerifyingKeyProofMismatch` — variant or n_public disagree.
    /// - `PublicInputCountMismatch` / `PublicInputOutOfRange` — PI
    ///   validation in challenges.
    /// - `PairingCheckFailed` — KZG opening failed.
    /// - `InvalidPointEncoding` — malformed G1 commitment.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        let vk = NovaFoldingVerifyingKey::from_bytes(vk_bytes)?;
        let proof = NovaFoldingProof::from_bytes(proof_bytes)?;

        if vk.variant != proof.variant || vk.n_public != proof.n_public {
            return Err(OnChainError::VerifyingKeyProofMismatch);
        }

        // Derive challenges (r, ξ, ν) from VK + proof + PI.
        let (challenges, _transcript) =
            derive_challenges(self.backend, &vk, public_inputs_bytes, &proof)?;

        // KZG scaffold opening at ξ (single-commitment stand-in;
        // session 6 extends to the full Spartan-batched opening).
        verify_opening_scaffold(self.backend, &vk, &proof, &challenges.xi)?;

        Ok(())
    }
}

impl<B: SyscallBackend + ?Sized + Send + Sync + 'static> ProofSystem for NovaFolding<'_, B> {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::NovaFolding
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
        // the Phase-3 implementation provides a tight estimate.
        Some(900_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{sizes, FoldingVariant};
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

    fn proof_bytes(variant: FoldingVariant, num_aux: u8, n_public: u16) -> Vec<u8> {
        let aux_len = (num_aux as usize) * sizes::G1_LEN;
        let pi_len = (n_public as usize) * sizes::FR_LEN;
        let total = sizes::FIXED_HEADER_LEN
            + sizes::FIXED_COMMITS_LEN
            + sizes::SCALAR_LEN
            + aux_len
            + pi_len
            + sizes::OPENING_LEN;
        let mut buf = vec![0u8; total];
        buf[0] = variant as u8;
        buf[1] = num_aux;
        buf[2..4].copy_from_slice(&n_public.to_le_bytes());
        buf
    }

    fn matching_vk(variant: FoldingVariant, n_public: u16) -> Vec<u8> {
        NovaFoldingVerifyingKey {
            variant,
            n_public,
            n_constraints: 1024,
            // Real G2 generator — pairing syscall rejects (0,0,0,0).
            x2_g2: mosaic_plonk::g1_consts::g2_generator_bytes(),
            a_comm: [0; sizes::G1_LEN],
            b_comm: [0; sizes::G1_LEN],
            c_comm: [0; sizes::G1_LEN],
            cs_digest: [0; 32],
        }
        .to_bytes()
    }

    /// Build a PI buffer of n Fr zero elements (matching n_public).
    fn zero_pi(n: u16) -> Vec<u8> {
        vec![0u8; (n as usize) * sizes::FR_LEN]
    }

    /// Session-5c integration: full pipeline runs with HostBackend +
    /// zero-filled proof/PI; pairing of identities accepts.
    #[test]
    fn full_pipeline_zero_proof_accepts() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 4);
        let proof = proof_bytes(FoldingVariant::Nova, 0, 4);
        let pi = zero_pi(4);
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        assert!(r.is_ok(), "zero-proof pipeline should pass, got {r:?}");
    }

    #[test]
    fn full_pipeline_hypernova_with_aux_commits() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::HyperNova, 2);
        let proof = proof_bytes(FoldingVariant::HyperNova, 4, 2);
        let pi = zero_pi(2);
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        assert!(r.is_ok(), "HyperNova zero-proof pipeline should pass, got {r:?}");
    }

    #[test]
    fn rejects_vk_proof_variant_mismatch() {
        let backend = MockBackend;
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 2);
        let proof = proof_bytes(FoldingVariant::HyperNova, 0, 2);
        let pi = zero_pi(2);
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyProofMismatch)));
    }

    #[test]
    fn rejects_vk_proof_pi_count_mismatch() {
        let backend = MockBackend;
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 2);
        let proof = proof_bytes(FoldingVariant::Nova, 0, 4);
        let pi = zero_pi(2); // VK says 2 but proof has 4
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyProofMismatch)));
    }

    #[test]
    fn rejects_wrong_vk_length() {
        let backend = MockBackend;
        let v = NovaFolding::new(&backend);
        let bad_vk = vec![0u8; NovaFoldingVerifyingKey::SERIALIZED_LEN - 1];
        let proof = proof_bytes(FoldingVariant::Nova, 0, 1);
        let r = NovaFolding::verify(&v, &bad_vk, &proof, &[]);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_proof_length() {
        let backend = MockBackend;
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 4);
        let bad_proof = vec![0u8; 16];
        let r = NovaFolding::verify(&v, &vk, &bad_proof, &[]);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn estimated_cu_returns_adr_target() {
        let backend = MockBackend;
        let v = NovaFolding::new(&backend);
        assert_eq!(
            ProofSystem::estimated_compute_units(&v, &[], &[]),
            Some(900_000),
        );
    }

    #[test]
    fn proof_system_id_is_nova_folding() {
        let backend = MockBackend;
        let v = NovaFolding::new(&backend);
        assert_eq!(v.proof_system_id(), ProofSystemId::NovaFolding);
    }

    #[allow(dead_code)]
    fn boxed(v: NovaFolding<'static, MockBackend>) -> alloc::boxed::Box<dyn ProofSystem> {
        alloc::boxed::Box::new(v)
    }
}
