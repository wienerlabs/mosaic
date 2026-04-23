//! KZG batched multipoint opening verifier (scaffold).
//!
//! The outer `HyperPlonk` verifier needs to confirm that the 12
//! evaluations in the proof's `final_evals` bundle are the correct
//! values of the committed MLEs at the sumcheck challenge point. This
//! module implements that check as a single pairing call:
//!
//! ```text
//! e(C_batched - [y_batched]_1 + [ξ · opening]_1, [1]_2)
//!   · e(-opening, [x]_2) ?= 1
//! ```
//!
//! where:
//! - `C_batched = Σ_{i=0}^{11} ν^i · C_i` — MSM over all 12 committed
//!   polys (4 from proof: a, b, c, z; 8 from VK: `q_M`, `q_L`, `q_R`, `q_O`,
//!   `q_C`, `σ_1`, `σ_2`, `σ_3`).
//! - `y_batched = Σ_{i=0}^{11} ν^i · e_i` — random linear combination
//!   of the 12 claimed evaluations.
//! - `ν` — batching challenge, squeezed from the transcript after
//!   absorbing `final_evals`.
//! - `ξ` — evaluation point.
//! - `opening` — single G1 KZG opening proof.
//!
//! ## Scaffold caveat: univariate reduction
//!
//! Real `HyperPlonk` uses a **multi-point** opening scheme that reduces
//! the claim over `(ξ_0, ..., ξ_{n-1}) ∈ F^n` to a univariate claim
//! via a specific reduction (typically Zeromorph / Pst / Gemini). The
//! canonical proof layout we ship (a single G1 opening) is sized for
//! that post-reduction univariate proof.
//!
//! This scaffold takes the shortcut of using the **last sumcheck
//! challenge** as the univariate evaluation point. The pairing check
//! then becomes mathematically identical to a univariate KZG
//! verification and runs the full syscall chain, but it does **not**
//! enforce the full `HyperPlonk` soundness guarantee. Session 3f will
//! pin the actual multi-point reduction against Espresso's reference
//! implementation and revise this module accordingly.
//!
//! Consumers should treat a successful return from this function as
//! "structural validation passed" rather than "cryptographically
//! verified". See the top-level verifier rustdoc for the full caveat.

use crate::canonical::{
    sizes::{FR_LEN, G1_LEN},
    HyperPlonkProof, HyperPlonkVerifyingKey,
};
use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::One;
use mosaic_core::{
    syscall::{AltBn128Op, InputEndianness, SyscallBackend},
    OnChainError,
};
use mosaic_zk_primitives::{
    field::{fr_from_canonical_bytes, fr_to_canonical_bytes},
    g1_consts::g2_generator_bytes,
    msm::{add_g1, commitment_minus_scalar_g1, msm_g1, negate_g1, scalar_mul_g1},
    transcript::Transcript,
};

/// Verify the batched KZG opening via a single `alt_bn128_pairing`
/// syscall call (2 pairs).
///
/// `transcript` must be in the post-sumcheck state: seeded with α and
/// all sumcheck round polynomials absorbed. This function absorbs
/// `final_evals` and squeezes the batching challenge ν, then runs the
/// MSM + pairing.
///
/// `univ_eval_point` is the univariate evaluation point for the
/// opening. Session 28 wires this via a domain-separated keccak of
/// the full sumcheck challenge vector (see the caller in
/// `verifier.rs`); prior sessions used only the last challenge.
/// Real `HyperPlonk` would produce this via a Zeromorph / PST /
/// Gemini reduction with accompanying consistency commitments —
/// tracked as a scaffold caveat.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if `final_evals` is not
///   exactly `12 × 32` bytes.
/// - [`OnChainError::PublicInputOutOfRange`] if any Fr in `final_evals`
///   is out of range.
/// - [`OnChainError::InvalidPointEncoding`] if a commitment is
///   malformed.
/// - [`OnChainError::PairingCheckFailed`] on a false pairing result.
/// - Transcript / syscall errors from the backend.
#[allow(clippy::too_many_lines)]
pub fn verify_batched_opening<B: SyscallBackend + ?Sized>(
    backend: &B,
    transcript: &mut Transcript<'_, B>,
    vk: &HyperPlonkVerifyingKey,
    proof: &HyperPlonkProof<'_>,
    univ_eval_point: &Fr,
) -> Result<(), OnChainError> {
    let final_evals = proof.final_evals;
    if final_evals.len() != 12 * FR_LEN {
        return Err(OnChainError::ProofLengthMismatch);
    }
    if proof.kzg_opening.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }

    // 1. Absorb final_evals, squeeze batching challenge ν.
    transcript.absorb(final_evals);
    let nu_bytes = transcript.get_challenge()?;
    let nu = fr_from_canonical_bytes(&nu_bytes)?;

    // 2. Compute ν^i for i=0..12 — the MSM scalars.
    let mut nu_powers = [Fr::one(); 12];
    for i in 1..12 {
        nu_powers[i] = nu_powers[i - 1] * nu;
    }
    let nu_powers_bytes: [[u8; 32]; 12] = {
        let mut out = [[0u8; 32]; 12];
        for i in 0..12 {
            out[i] = fr_to_canonical_bytes(&nu_powers[i]);
        }
        out
    };

    // 3. MSM over 12 commitments. Order matches `final_evals_index`:
    //    (a, b, c, z, q_m, q_l, q_r, q_o, q_c, σ_1, σ_2, σ_3).
    let commits: [&[u8]; 12] = [
        proof.a,
        proof.b,
        proof.c,
        proof.z,
        &vk.q_m_g1,
        &vk.q_l_g1,
        &vk.q_r_g1,
        &vk.q_o_g1,
        &vk.q_c_g1,
        &vk.sigma_1_g1,
        &vk.sigma_2_g1,
        &vk.sigma_3_g1,
    ];
    let c_batched = msm_g1(backend, &commits, &nu_powers_bytes)?;

    // 4. Batched evaluation value: Σ ν^i · e_i.
    let mut y_batched = Fr::from(0u64);
    for i in 0..12 {
        let start = i * FR_LEN;
        let end = start + FR_LEN;
        let e_i = fr_from_canonical_bytes(&final_evals[start..end])?;
        y_batched += nu_powers[i] * e_i;
    }

    // 5. Compute the LHS G1 point of the pairing check:
    //    A1 = C_batched - y_batched · G1_generator + ξ · opening
    //
    //    Derivation: we want to pair-check
    //        e(C - y·G1, G2) == e(opening, x·G2 - ξ·G2)
    //    Since we can't do G2 scalar mul on-chain, rewrite via
    //    bilinearity:
    //        e(C - y·G1 + ξ·opening, G2) · e(-opening, x·G2) == 1
    //    The LHS G1 arg is (C - y·G1 + ξ·opening).
    let y_bytes = fr_to_canonical_bytes(&y_batched);
    let c_minus_y = commitment_minus_scalar_g1(backend, &c_batched, &y_bytes)?;

    let xi_bytes = fr_to_canonical_bytes(univ_eval_point);
    let mut opening_arr = [0u8; G1_LEN];
    opening_arr.copy_from_slice(proof.kzg_opening);
    let xi_opening = scalar_mul_g1(backend, &opening_arr, &xi_bytes)?;

    let a1 = add_g1(backend, &c_minus_y, &xi_opening)?;

    // 6. Pairing check with 2 pairs:
    //    Pair 1: (A1, [1]_G2)
    //    Pair 2: (-opening, [x]_G2)
    let neg_opening = negate_g1(&opening_arr);
    let g2_gen = g2_generator_bytes();

    let mut pairing_input: Vec<u8> = Vec::with_capacity(2 * (G1_LEN + 128));
    pairing_input.extend_from_slice(&a1);
    pairing_input.extend_from_slice(&g2_gen);
    pairing_input.extend_from_slice(&neg_opening);
    pairing_input.extend_from_slice(&vk.x2_g2);

    let result = backend.alt_bn128_group_op(
        AltBn128Op::Pairing,
        InputEndianness::BigEndian,
        &pairing_input,
    )?;
    if result.len() != 32 || result[31] != 0x01 {
        return Err(OnChainError::PairingCheckFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FIXED_HEADER_LEN, SUMCHECK_POLY_LEN};
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_zk_primitives::g1_consts::g1_generator_bytes;
    use mosaic_zk_primitives::transcript::Kind;

    /// VK with identity G1 commits (accepted as zero points) and the
    /// real G2 generator for `x2_g2` (required to be on-curve by the
    /// pairing syscall). This is the minimal VK shape that round-trips
    /// through on-chain primitives without triggering point-on-curve
    /// rejection for the G2 element.
    fn zero_vk() -> HyperPlonkVerifyingKey {
        HyperPlonkVerifyingKey {
            n_public: 0,
            num_variables: 2,
            x2_g2: g2_generator_bytes(),
            q_m_g1: [0; G1_LEN],
            q_l_g1: [0; G1_LEN],
            q_r_g1: [0; G1_LEN],
            q_o_g1: [0; G1_LEN],
            q_c_g1: [0; G1_LEN],
            sigma_1_g1: [0; G1_LEN],
            sigma_2_g1: [0; G1_LEN],
            sigma_3_g1: [0; G1_LEN],
            k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
            k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
            k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
        }
    }

    fn zero_proof_bytes(rounds: u32) -> alloc::vec::Vec<u8> {
        let polys_len = (rounds as usize) * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + 12 * FR_LEN + G1_LEN;
        let mut buf = alloc::vec![0u8; total];
        buf[256..260].copy_from_slice(&rounds.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_wrong_final_evals_length() {
        // Build a proof whose final_evals slot has the wrong length
        // by parsing a minimal proof and swapping the slice. Since
        // `HyperPlonkProof::from_bytes` enforces the length already,
        // this only tests the internal guard (belt-and-suspenders).
        let backend = HostBackend::new();
        let proof_buf = zero_proof_bytes(2);
        let proof_parsed = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        let vk = zero_vk();
        let mut t = Transcript::new(Kind::Keccak256, &backend);

        // Sanity: real proof has correctly-sized final_evals.
        assert_eq!(proof_parsed.final_evals.len(), 12 * FR_LEN);

        // Construct a proof struct with truncated final_evals — tests
        // the early length guard in verify_batched_opening.
        let bad = HyperPlonkProof {
            final_evals: &proof_parsed.final_evals[..11 * FR_LEN],
            ..proof_parsed
        };
        let r = verify_batched_opening(
            &backend,
            &mut t,
            &vk,
            &bad,
            &Fr::from(0u64),
        );
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_opening_length() {
        let backend = HostBackend::new();
        let proof_buf = zero_proof_bytes(2);
        let proof_parsed = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        let vk = zero_vk();
        let mut t = Transcript::new(Kind::Keccak256, &backend);

        let bad = HyperPlonkProof {
            kzg_opening: &proof_parsed.kzg_opening[..63],
            ..proof_parsed
        };
        let r = verify_batched_opening(
            &backend,
            &mut t,
            &vk,
            &bad,
            &Fr::from(0u64),
        );
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    /// All-zero commitments and openings: the MSM + pairing collapses
    /// to `e(0, G2) · e(0, x2_G2) = 1 · 1 = 1` (identity of Fq12).
    /// This is a trivial accept — real provers never emit zero
    /// commitments, so this is acceptable scaffold behavior.
    /// Session 3f (real fixtures) will replace this trivial pass with
    /// meaningful validation.
    #[test]
    fn all_zero_trivially_passes_pairing() {
        let backend = HostBackend::new();
        let proof_buf = zero_proof_bytes(2);
        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        let vk = zero_vk();
        let mut t = Transcript::new(Kind::Keccak256, &backend);

        let r = verify_batched_opening(
            &backend,
            &mut t,
            &vk,
            &proof,
            &Fr::from(0u64),
        );
        // Zero commitments → pairing of identity × identity = 1.
        assert!(r.is_ok(), "zero proof should trivially pass pairing, got {r:?}");
    }

    /// Non-trivial inputs with VK's `x2_g2 = G2_generator` (so the
    /// SRS trapdoor is `x = 1`). For this VK, the pairing equation
    /// becomes `e(A1 - opening, G2) == 1`, which equals 1 only when
    /// `A1 == opening`. We construct inputs where this relation
    /// doesn't hold to exercise the failure path.
    ///
    /// Setup:
    /// - `proof.a = G1_generator`, `a_eval = 1` → `C_batched - y_batched·G1 = 0`
    /// - `kzg_opening = G1_generator`, `ξ = 2` → `ξ·opening = 2·G1`
    /// - `A1 = 0 + 2·G1 = 2·G1`
    /// - Pairing 1: `e(2·G1, G2)`. Pairing 2: `e(-G1, G2)`.
    /// - Product: `e(G1, G2) ≠ 1` → fail.
    #[test]
    fn nonzero_commit_with_wrong_opening_fails_pairing() {
        let backend = HostBackend::new();
        let mut proof_buf = zero_proof_bytes(2);

        // Set a=G1_generator (non-zero commit at offset 0).
        let g1_gen = g1_generator_bytes();
        proof_buf[0..G1_LEN].copy_from_slice(&g1_gen);

        // Set a_eval = 1 (the evaluation we're opening against).
        // Offset: FIXED_HEADER + 2·SUMCHECK_POLY_LEN + A·FR_LEN.
        let a_eval_offset = FIXED_HEADER_LEN + 2 * SUMCHECK_POLY_LEN;
        proof_buf[a_eval_offset + 31] = 1; // Fr::one() in BE

        // Set kzg_opening = G1_generator (non-zero G1 at the tail).
        let opening_offset = proof_buf.len() - G1_LEN;
        proof_buf[opening_offset..opening_offset + G1_LEN].copy_from_slice(&g1_gen);

        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        let vk = zero_vk();
        let mut t = Transcript::new(Kind::Keccak256, &backend);

        // ξ = 2 — non-zero univariate evaluation point.
        let r = verify_batched_opening(
            &backend,
            &mut t,
            &vk,
            &proof,
            &Fr::from(2u64),
        );
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "expected PairingCheckFailed for non-trivial proof with wrong opening, got {r:?}",
        );
    }
}
