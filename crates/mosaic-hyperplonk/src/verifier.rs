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

use crate::{
    canonical::{
        final_evals_index as idx,
        sizes::{FR_LEN, SUMCHECK_POLY_LEN},
        HyperPlonkProof, HyperPlonkVerifyingKey,
    },
    challenges::derive_challenges,
    gate::{gate_expr, SelectorEvals, WireEvals},
    sumcheck::verify_sumcheck,
};
use ark_bn254::Fr;
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};
use mosaic_plonk::field::fr_from_canonical_bytes;

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

    /// Verify a HyperPlonk-KZG proof.
    ///
    /// Session-3d implementation: wires through parse → challenge
    /// derivation → sumcheck verification → gate-expr claim reduction.
    /// Returns [`OnChainError::UnimplementedProofSystem`] at the final
    /// KZG batched-opening step, which lands in session 3e.
    ///
    /// ## Errors
    ///
    /// - `ProofLengthMismatch` / `VerifyingKeyLengthMismatch` — wire.
    /// - `VerifyingKeyProofMismatch` — VK/proof `num_variables` and
    ///   `sumcheck_rounds` disagree.
    /// - `PublicInputCountMismatch` / `PublicInputOutOfRange` — PI
    ///   validation inside challenge derivation.
    /// - `SumcheckFailed` — either a per-round identity fails, or the
    ///   final sumcheck claim doesn't match the expected gate-expr
    ///   evaluation at the challenge point.
    /// - `UnimplementedProofSystem` — reached the KZG batched-opening
    ///   step, which is not yet implemented.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        // 1. Parse + structural cross-check.
        let vk = HyperPlonkVerifyingKey::from_bytes(vk_bytes)?;
        let proof = HyperPlonkProof::from_bytes(proof_bytes)?;
        if vk.num_variables != proof.sumcheck_rounds {
            return Err(OnChainError::VerifyingKeyProofMismatch);
        }

        // 2. Pre-sumcheck challenge derivation (β, γ, α).
        //    Leaves the transcript seeded with α for sumcheck rounds.
        let (challenges, mut transcript) =
            derive_challenges(self.backend, &vk, public_inputs_bytes, &proof)?;

        // 3. Sumcheck verification.
        //    The zero-check sumcheck has initial claim 0 on the
        //    combined gate + permutation polynomial.
        let sumcheck_out = verify_sumcheck(
            &mut transcript,
            &Fr::from(0u64),
            proof.sumcheck_polys,
            proof.sumcheck_rounds,
        )?;

        // 4. Claim reduction: compute the expected value of the
        //    combined polynomial at the sumcheck challenge point from
        //    the proof's final_evals bundle, and compare to the
        //    sumcheck's final claim.
        let expected_claim = compute_expected_final_claim(
            proof.final_evals,
            &challenges.alpha,
        )?;
        if expected_claim != sumcheck_out.final_claim {
            return Err(OnChainError::SumcheckFailed);
        }

        // 5. KZG batched opening — session 3e.
        //    The opening must attest that final_evals are the correct
        //    evaluations of the committed MLEs at the sumcheck
        //    challenge point. Until that's wired, the verifier stops
        //    here with UnimplementedProofSystem so callers know the
        //    proof hasn't been fully validated.
        Err(OnChainError::UnimplementedProofSystem)
    }
}

/// Compute the expected value of the combined zero-check polynomial
/// at the sumcheck challenge point, from the proof's `final_evals`
/// bundle.
///
/// **Session-3d scope:** gate expression only. The permutation term
/// is a placeholder (returns zero) until session 3e lands the full
/// grand-product reduction. Valid proofs will therefore satisfy this
/// check only if their permutation contribution at the challenge
/// point happens to be zero — which is not generally true and is why
/// the verifier always stops at `UnimplementedProofSystem` before
/// this function can produce a false-accept in production.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if `final_evals` is shorter
///   than `12 × 32 = 384` bytes.
/// - [`OnChainError::PublicInputOutOfRange`] if any Fr in the bundle
///   is out of range.
fn compute_expected_final_claim(
    final_evals_bytes: &[u8],
    alpha: &Fr,
) -> Result<Fr, OnChainError> {
    // Parse the 12 Fr evaluations at fixed offsets.
    let eval_at = |i: usize| -> Result<Fr, OnChainError> {
        let start = i * FR_LEN;
        let end = start + FR_LEN;
        if final_evals_bytes.len() < end {
            return Err(OnChainError::ProofLengthMismatch);
        }
        fr_from_canonical_bytes(&final_evals_bytes[start..end])
    };

    let wires = WireEvals {
        a: eval_at(idx::A)?,
        b: eval_at(idx::B)?,
        c: eval_at(idx::C)?,
    };
    // z_eval is read but unused until session 3e adds permutation.
    let _z_eval = eval_at(idx::Z)?;
    let selectors = SelectorEvals {
        q_m: eval_at(idx::Q_M)?,
        q_l: eval_at(idx::Q_L)?,
        q_r: eval_at(idx::Q_R)?,
        q_o: eval_at(idx::Q_O)?,
        q_c: eval_at(idx::Q_C)?,
    };
    // σ_i_evals read but unused until session 3e adds permutation.
    let _sigma_1 = eval_at(idx::SIGMA_1)?;
    let _sigma_2 = eval_at(idx::SIGMA_2)?;
    let _sigma_3 = eval_at(idx::SIGMA_3)?;

    // α · gate_expr + permutation_placeholder.
    let gate_value = gate_expr(&wires, &selectors);
    let perm_value = Fr::from(0u64); // session-3e placeholder.

    Ok(*alpha * gate_value + perm_value)
}

/// Silence unused-helper warning when SUMCHECK_POLY_LEN is only used
/// in conditional test code. Inlined here to keep the constant
/// import alongside FR_LEN at the top of the file.
#[allow(dead_code)]
const _SUMCHECK_POLY_LEN: usize = SUMCHECK_POLY_LEN;

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
    use crate::canonical::sizes::{FINAL_EVALS, FIXED_HEADER_LEN, G1_LEN};
    use mosaic_core::syscall::host::HostBackend;

    /// Stub backend that fails on every syscall. Used in tests that
    /// check wire-format rejection paths that should short-circuit
    /// before any syscall runs.
    struct NeverBackend;
    impl SyscallBackend for NeverBackend {
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
            q_m_g1: [0; G1_LEN],
            q_l_g1: [0; G1_LEN],
            q_r_g1: [0; G1_LEN],
            q_o_g1: [0; G1_LEN],
            q_c_g1: [0; G1_LEN],
            sigma_1_g1: [0; G1_LEN],
            sigma_2_g1: [0; G1_LEN],
            sigma_3_g1: [0; G1_LEN],
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

    /// With a real host keccak + all-zero VK/proof/PI, the verifier
    /// progresses through parse → challenges → sumcheck (trivially
    /// valid: zero polys with zero initial claim) → claim reduction
    /// (trivial: α · 0 + 0 = 0) → KZG step, which returns
    /// `UnimplementedProofSystem`. This is the "happy path for
    /// session-3d integration" test.
    #[test]
    fn full_pipeline_zero_proof_hits_kzg_unimplemented() {
        let backend = HostBackend::new();
        let v = HyperPlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let proof = dummy_proof_bytes_10_rounds();
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::UnimplementedProofSystem)),
            "expected UnimplementedProofSystem at KZG step, got {r:?}",
        );
    }

    #[test]
    fn rejects_wrong_vk_length_before_unimplemented() {
        let backend = NeverBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        let bad_vk = alloc::vec![0u8; HyperPlonkVerifyingKey::SERIALIZED_LEN - 1];
        let proof = dummy_proof_bytes_10_rounds();
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &bad_vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_proof_length_before_unimplemented() {
        let backend = NeverBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let bad_proof = alloc::vec![0u8; 32]; // way too short
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &vk, &bad_proof, &pi);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    /// VK declares num_variables = 10 but proof claims sumcheck_rounds
    /// = 8. Verifier should catch this structural mismatch before any
    /// crypto runs.
    #[test]
    fn rejects_vk_proof_num_variables_mismatch() {
        let backend = NeverBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes(); // declares num_variables = 10
        // Build a proof claiming 8 rounds.
        let polys_len = 8 * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        let mut proof = alloc::vec![0u8; total];
        proof[256..260].copy_from_slice(&8u32.to_le_bytes());
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyProofMismatch)));
    }

    /// Tamper with the first sumcheck round polynomial → sumcheck
    /// identity fails at round 0.
    #[test]
    fn rejects_tampered_sumcheck_round() {
        let backend = HostBackend::new();
        let v = HyperPlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let mut proof = dummy_proof_bytes_10_rounds();
        // First round polynomial lives at offset 260 (after 4·G1 + u32).
        // Set its c_0 coefficient to 1 — now p(0) + p(1) = 2 ≠ 0 (claim).
        proof[260 + 31] = 1; // last byte of first Fr (BE), == 1.
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::SumcheckFailed)),
            "expected SumcheckFailed, got {r:?}",
        );
    }

    /// Inject a non-zero gate evaluation into final_evals → claim
    /// reduction detects `α · gate ≠ 0 = sumcheck_final_claim`.
    #[test]
    fn rejects_claim_reduction_mismatch() {
        let backend = HostBackend::new();
        let v = HyperPlonkKzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let mut proof = dummy_proof_bytes_10_rounds();
        // Set q_c final_eval to 1. All other final_evals are 0. With
        // a=b=c=0, q_m=q_l=q_r=q_o=0, gate = q_c = 1 ≠ 0.
        // Offset: FIXED_HEADER + 10·SUMCHECK_POLY_LEN + Q_C * FR_LEN.
        let q_c_offset =
            FIXED_HEADER_LEN + 10 * SUMCHECK_POLY_LEN + idx::Q_C * FR_LEN;
        proof[q_c_offset + 31] = 1; // last byte of BE Fr = 1 → Fr::one()
        let pi = [0u8; FR_LEN];
        let r = HyperPlonkKzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::SumcheckFailed)),
            "expected SumcheckFailed at claim reduction, got {r:?}",
        );
    }

    #[test]
    fn estimated_cu_returns_adr_target() {
        let backend = NeverBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        assert_eq!(
            ProofSystem::estimated_compute_units(&v, &[], &[]),
            Some(900_000),
        );
    }

    #[test]
    fn proof_system_id_is_hyperplonk() {
        let backend = NeverBackend;
        let v = HyperPlonkKzgBn254::new(&backend);
        assert_eq!(v.proof_system_id(), ProofSystemId::HyperPlonkKzgBn254);
    }

    /// Object-safety smoke test: this must compile.
    #[allow(dead_code)]
    fn boxed(v: HyperPlonkKzgBn254<'static, NeverBackend>) -> alloc::boxed::Box<dyn ProofSystem> {
        alloc::boxed::Box::new(v)
    }
}
