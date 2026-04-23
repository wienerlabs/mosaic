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
//! - `mosaic_zk_primitives::fr` — Fr byte range ops
//! - `mosaic_zk_primitives::field` — arkworks Fr arithmetic (for folding scalar
//!   reductions)
//! - `mosaic_zk_primitives::msm` — G1 MSM primitive (the dominant CU cost in
//!   the Hadamard relation check)
//! - `mosaic_zk_primitives::transcript` — Keccak-256 round transcript
//! - `mosaic_zk_primitives::g1_consts` — G1/G2 generator bytes for the final
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
    folding::{folded_commitment_from_fold, hadamard_residual},
    kzg::verify_spartan_batched_opening,
};
use ark_bn254::Fr;
use ark_ff::Zero;
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};
use mosaic_zk_primitives::field::{fr_from_canonical_bytes, fr_to_canonical_bytes};
use mosaic_zk_primitives::transcript::derive_fr_challenge;

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
    /// Session 6-partial implementation: parse → challenges → Hadamard
    /// residual check (new in this commit) → KZG scaffold opening →
    /// `Ok(())`.
    ///
    /// ## Hadamard relation check
    ///
    /// The folded instance satisfies the relaxed R1CS relation
    /// `A·z ∘ B·z = u · C·z + E`. At the Spartan evaluation point ξ
    /// this reduces to the scalar equation
    /// `A(ξ) · B(ξ) - u · C(ξ) - E(ξ) = 0`. The verifier reads the
    /// four evaluations from `proof.hadamard_evals`, reads `u` from
    /// the proof header, and checks the residual. A non-zero residual
    /// surfaces as `SumcheckFailed` (reused to match the claim-
    /// reduction error in HyperPlonk/Halo2).
    ///
    /// ## Scaffold caveat
    ///
    /// The Hadamard check closes the folded-instance side. The KZG
    /// opening is still single-commitment (session 7+ extends to
    /// Spartan multi-poly batched opening); the
    /// `folded_commitment_from_fold` primitive remains available for
    /// future integration once the proof layout also carries the two
    /// base commitments to fold against.
    ///
    /// ## Errors
    ///
    /// - `VerifyingKeyLengthMismatch` / `ProofLengthMismatch` — wire.
    /// - `VerifyingKeyProofMismatch` — variant or n_public disagree.
    /// - `PublicInputCountMismatch` / `PublicInputOutOfRange` — PI
    ///   validation in challenges.
    /// - `SumcheckFailed` — Hadamard residual is non-zero or `u` is
    ///   malformed.
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

        // Hadamard-relation residual check at the Spartan point.
        // Parses (a, b, c, e) evaluations from proof.hadamard_evals and
        // u from proof.u; computes `a·b - u·c - e` and rejects if non-zero.
        let (a_eval, b_eval, c_eval, e_eval) = proof.parse_hadamard_evals()?;
        let u = fr_from_canonical_bytes(proof.u)?;
        let residual = hadamard_residual(&a_eval, &b_eval, &c_eval, &e_eval, &u);
        if !residual.is_zero() {
            return Err(OnChainError::SumcheckFailed);
        }

        // Session-15-nova: folded-commitment reconstruction.
        // Recompute `E_folded` and `W_folded` from the two base
        // instances and the cross-term T using the transcript-
        // derived folding challenge `r`. Reject if the reconstruction
        // doesn't match the declared `e_comm` / `w_comm`.
        //
        //   E_folded ?= E_1 + r·E_2 + r²·T     (folding.rs primitive)
        //   W_folded ?= W_1 + r·W_2 + r²·T
        //
        // Catches a malicious prover who sends inconsistent base/fold
        // commitments — even with a valid Hadamard residual, the
        // fold reconstruction will disagree with the declared E/W.
        let r = challenges.r;
        let computed_e = folded_commitment_from_fold(
            self.backend,
            proof.base_e_1,
            proof.base_e_2,
            proof.t_comm,
            &r,
        )?;
        if &computed_e[..] != proof.e_comm {
            return Err(OnChainError::VerificationFailed);
        }
        let computed_w = folded_commitment_from_fold(
            self.backend,
            proof.base_w_1,
            proof.base_w_2,
            proof.t_comm,
            &r,
        )?;
        if &computed_w[..] != proof.w_comm {
            return Err(OnChainError::VerificationFailed);
        }

        // Session 19: Spartan-batched multi-poly opening. Previously
        // session-≤18 opened only `w_comm`; the batched reduction now
        // collapses (a_comm, b_comm, c_comm, e_comm, w_comm) via a `v`
        // challenge into a single pairing identity. The session-≤18
        // `verify_opening_scaffold` stays referenced so callers that
        // want the legacy single-commit check can still reach it.
        // `verify_opening_scaffold` stays exported for unit tests in
        // `kzg::tests`; it's the session-≤18 single-commit opening.
        let v = derive_fr_challenge(
            self.backend,
            b"mosaic-nova/v",
            &[
                &fr_to_canonical_bytes(&challenges.xi),
                proof.hadamard_evals,
                proof.w_comm,
                proof.e_comm,
            ],
        )?;
        verify_spartan_batched_opening(
            self.backend,
            &vk,
            &proof,
            &challenges.xi,
            &v,
        )?;

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
    use alloc::vec::Vec;

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
            + 4 * sizes::G1_LEN // session-15-nova base commits
            + sizes::HADAMARD_EVALS_LEN
            + sizes::W_EVAL_LEN
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
            x2_g2: mosaic_zk_primitives::g1_consts::g2_generator_bytes(),
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

    /// Session-15-nova: tamper with `base_e_1` (set to G1 generator,
    /// a non-zero point) while leaving `e_comm` zero → the folded
    /// commitment reconstruction yields `G1_generator + r·0 + r²·0
    /// = G1_generator ≠ 0 = e_comm` → `VerificationFailed`.
    /// Demonstrates the new fold-reconstruction soundness gate.
    #[test]
    fn rejects_tampered_base_e_commitment() {
        use mosaic_zk_primitives::g1_consts::g1_generator_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 2);
        let mut proof = proof_bytes(FoldingVariant::Nova, 0, 2);

        // Layout: FIXED_HEADER + E/W/T (3·G1) + u (32 B) → base_e_1.
        let base_e_1_off = sizes::FIXED_HEADER_LEN
            + sizes::FIXED_COMMITS_LEN
            + sizes::SCALAR_LEN;
        let g1_gen = g1_generator_bytes();
        proof[base_e_1_off..base_e_1_off + sizes::G1_LEN].copy_from_slice(&g1_gen);

        let pi = zero_pi(2);
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::VerificationFailed)),
            "tampered base_e_1 should fail fold reconstruction, got {r:?}",
        );
    }

    /// Session 6-partial soundness gate: set a=1, b=1, others zero →
    /// residual = 1·1 - 0·0 - 0 = 1 ≠ 0 → `SumcheckFailed`.
    #[test]
    fn rejects_tampered_hadamard_evals() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 2);
        let mut proof = proof_bytes(FoldingVariant::Nova, 0, 2);

        // Hadamard evals start at FIXED_HEADER + FIXED_COMMITS +
        // SCALAR + 4·G1 (session-15-nova base commits).
        let had_off = sizes::FIXED_HEADER_LEN
            + sizes::FIXED_COMMITS_LEN
            + sizes::SCALAR_LEN
            + 4 * sizes::G1_LEN;
        // Set a_eval = 1 and b_eval = 1 (last byte of BE Fr).
        proof[had_off + sizes::FR_LEN - 1] = 1;
        proof[had_off + 2 * sizes::FR_LEN - 1] = 1;

        let pi = zero_pi(2);
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::SumcheckFailed)),
            "tampered a·b ≠ u·c + e should fail Hadamard residual, got {r:?}",
        );
    }

    /// Set u = 2 and e_eval = a_eval·b_eval - 2·c_eval with wires = 1
    /// → residual = 1·1 - 2·1 - (1 - 2) = 1 - 2 + 1 = 0. Test the
    /// happy path where a custom non-zero bundle satisfies the
    /// relation.
    #[test]
    fn accepts_nonzero_hadamard_satisfying_bundle() {
        use mosaic_zk_primitives::field::fr_to_canonical_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 2);
        let mut proof = proof_bytes(FoldingVariant::Nova, 0, 2);

        // Set u = 2.
        let u_off = sizes::FIXED_HEADER_LEN + sizes::FIXED_COMMITS_LEN;
        let u_bytes = fr_to_canonical_bytes(&Fr::from(2u64));
        proof[u_off..u_off + sizes::FR_LEN].copy_from_slice(&u_bytes);

        // a = b = c = 1, e = 1·1 - 2·1 = -1.
        let hadamard_off = u_off + sizes::FR_LEN + 4 * sizes::G1_LEN;
        let one_bytes = fr_to_canonical_bytes(&Fr::from(1u64));
        let neg_one_bytes = fr_to_canonical_bytes(&(-Fr::from(1u64)));
        proof[hadamard_off..hadamard_off + sizes::FR_LEN].copy_from_slice(&one_bytes);
        proof[hadamard_off + sizes::FR_LEN..hadamard_off + 2 * sizes::FR_LEN]
            .copy_from_slice(&one_bytes);
        proof[hadamard_off + 2 * sizes::FR_LEN..hadamard_off + 3 * sizes::FR_LEN]
            .copy_from_slice(&one_bytes);
        proof[hadamard_off + 3 * sizes::FR_LEN..hadamard_off + 4 * sizes::FR_LEN]
            .copy_from_slice(&neg_one_bytes);

        let pi = zero_pi(2);
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        // Session 19 upgrade: Hadamard residual still passes
        // (1·1 - 2·1 = -1, which matches e_eval), but the new
        // Spartan-batched KZG opening folds in the Hadamard evals as
        // claimed values for a/b/c/e against VK-side (zero) commits.
        // With commits = 0 but evals ≠ 0, y_batched ≠ 0 while
        // C_batched = 0 → pairing fails on the opening side.
        //
        // This is the intended stricter behavior: any Hadamard-
        // satisfying bundle constructed without matching commit
        // openings now gets caught. Full acceptance requires a real
        // fixture with consistent (A·z, B·z, C·z, E, W) commits +
        // openings — tracked in the fixture-driven differential
        // testing roadmap item.
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "post-session-19, a Hadamard-only satisfying bundle is \
             rejected by the Spartan-batched opening; got {r:?}",
        );
    }

    /// Session 19: Spartan-batched opening now folds the VK-side
    /// (a_comm, b_comm, c_comm) into the MSM. Swapping any one of
    /// them from the zero baseline to the G1 generator produces a
    /// non-zero `C_batched` while the evaluations stay zero, breaking
    /// the batched pairing identity — `PairingCheckFailed`.
    #[test]
    fn spartan_rejects_tampered_vk_a_comm() {
        use mosaic_zk_primitives::g1_consts::g1_generator_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = NovaFolding::new(&backend);
        let mut vk_bytes = matching_vk(FoldingVariant::Nova, 0);

        // VK layout: variant (1) + n_public (2) + n_constraints (4) +
        // x2_g2 (128) + a_comm (64) + b_comm (64) + c_comm (64) +
        // cs_digest (32). a_comm sits at offset 1 + 2 + 4 + 128 = 135.
        let a_comm_off = 1 + 2 + 4 + 128;
        vk_bytes[a_comm_off..a_comm_off + sizes::G1_LEN]
            .copy_from_slice(&g1_generator_bytes());

        let proof = proof_bytes(FoldingVariant::Nova, 0, 0);
        let pi = zero_pi(0);
        let r = NovaFolding::verify(&v, &vk_bytes, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "tampered VK a_comm should fail Spartan-batched opening; \
             got {r:?}",
        );
    }

    /// Session 19 companion: tamper an individual Hadamard evaluation
    /// byte. The Hadamard residual check would catch this if it
    /// breaks the A·B - u·C - E = 0 relation, but sessions-≤18 only
    /// used the FIRST public input as the KZG eval — leaving
    /// advice/e/w evals unchecked by the opening. With session-19
    /// batching, they're all folded in → tampering propagates.
    #[test]
    fn spartan_rejects_tampered_hadamard_a_eval() {
        use mosaic_zk_primitives::field::fr_to_canonical_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 0);
        let mut proof = proof_bytes(FoldingVariant::Nova, 0, 0);

        // Set u = 1 so the Hadamard residual 1·1 - 1·1 - 0 = 0 with
        // a = b = c = 1 still holds, forcing the regression path to
        // the Spartan opening (if we also tampered a_eval alone, the
        // Hadamard residual would catch it first).
        let u_off = sizes::FIXED_HEADER_LEN + sizes::FIXED_COMMITS_LEN;
        let one_bytes = fr_to_canonical_bytes(&Fr::from(1u64));
        proof[u_off..u_off + sizes::FR_LEN].copy_from_slice(&one_bytes);

        // Set a_eval = 1; keep b = c = e = 0. Hadamard: 1·0 − 1·0 − 0 = 0 ✓.
        // Spartan: y_batched = v⁰·1 ≠ 0, but all commits zero →
        // C_batched = 0 → pairing fails.
        let hadamard_off = u_off + sizes::FR_LEN + 4 * sizes::G1_LEN;
        proof[hadamard_off..hadamard_off + sizes::FR_LEN].copy_from_slice(&one_bytes);

        let pi = zero_pi(0);
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "tampered a_eval should fail Spartan-batched opening; \
             got {r:?}",
        );
    }

    /// Session 23: `proof.w_eval` is now a dedicated 32-byte slot
    /// rather than derived from the first public input. The Spartan-
    /// batched opening folds `v⁴·w_eval` into `y_batched`, so a
    /// tampered non-zero `w_eval` with zero witness commit must
    /// fail the batched pairing. Exercises the new slot directly.
    #[test]
    fn spartan_rejects_tampered_w_eval_slot() {
        use mosaic_zk_primitives::field::fr_to_canonical_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = NovaFolding::new(&backend);
        let vk = matching_vk(FoldingVariant::Nova, 0);
        let mut proof = proof_bytes(FoldingVariant::Nova, 0, 0);

        // Set u = 1 so the Hadamard residual 0·0 − 1·0 − 0 = 0 holds
        // with a = b = c = e = 0. Then the verifier progresses to
        // the Spartan-batched opening, where a tampered w_eval
        // produces y_batched ≠ 0 with C_batched = 0 → pairing fails.
        let u_off = sizes::FIXED_HEADER_LEN + sizes::FIXED_COMMITS_LEN;
        let one_bytes = fr_to_canonical_bytes(&Fr::from(1u64));
        proof[u_off..u_off + sizes::FR_LEN].copy_from_slice(&one_bytes);

        // w_eval slot sits immediately after the hadamard_evals block.
        // Layout offset: FIXED_HEADER + FIXED_COMMITS + SCALAR +
        //   4·G1 (base commits) + HADAMARD_EVALS.
        let w_eval_off = u_off
            + sizes::FR_LEN
            + 4 * sizes::G1_LEN
            + sizes::HADAMARD_EVALS_LEN;
        proof[w_eval_off..w_eval_off + sizes::FR_LEN].copy_from_slice(&one_bytes);

        let pi = zero_pi(0);
        let r = NovaFolding::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "tampered w_eval slot should fail Spartan-batched opening; \
             got {r:?}",
        );
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
