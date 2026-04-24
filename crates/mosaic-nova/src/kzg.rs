//! KZG opening verifier for Nova-family folding proofs (scaffold).
//!
//! A Spartan-wrapped Nova proof includes a KZG opening of the witness
//! commitment `W` at the Spartan evaluation point. This module
//! verifies that opening via a single `alt_bn128_pairing` call.
//!
//! ## Pairing check
//!
//! ```text
//! e(W - [w_eval]_G1 + ξ · W_ξ, [1]_G2) · e(-W_ξ, [x]_G2)  ?=  1
//! ```
//!
//! where `w_eval` is the claimed evaluation of the witness polynomial
//! at `ξ`. Structurally identical to the `HyperPlonk` and Halo2
//! scaffold openings — same bilinearity rewrite to avoid on-chain G2
//! scalar mul.
//!
//! ## Scaffold limitations
//!
//! - Uses `proof.w_comm` and the first Fr in the proof's public
//!   inputs as the claimed evaluation. Real Nova's Spartan wrapper
//!   batches many openings (A·z, B·z, C·z commitments + E + W); this
//!   single-commit check is the simplest correct-shape stand-in.
//! - `W_ξω` is ignored (second opening point for grand-product-style
//!   arguments, not applicable to vanilla Nova).
//! - Session 6 extends against `sonobe` reference fixtures.

use crate::canonical::{
    sizes::{FR_LEN, G1_LEN},
    NovaFoldingProof, NovaFoldingVerifyingKey,
};
use ark_bn254::Fr;
use mosaic_core::{
    syscall::SyscallBackend,
    OnChainError,
};
use mosaic_zk_primitives::{
    field::{fr_from_canonical_bytes, fr_to_canonical_bytes},
    g1_consts::g2_generator_bytes,
    msm::{
        compute_kzg_opening_lhs, msm_g1, negate_g1, verify_two_pair_pairing,
    },
};

/// Scaffold single-commitment KZG opening check for a folded Nova
/// instance.
///
/// Uses `proof.w_comm` as the opened commitment and the first public
/// input (if any) as the claimed evaluation; falls back to zero
/// evaluation for the empty public-input case.
///
/// ## Errors
///
/// - [`OnChainError::InvalidPointEncoding`] if `w_comm` or `w_xi` is
///   malformed.
/// - [`OnChainError::PublicInputOutOfRange`] if the claimed evaluation
///   Fr is out of range.
/// - [`OnChainError::PairingCheckFailed`] on a false pairing result.
pub fn verify_opening_scaffold<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &NovaFoldingVerifyingKey,
    proof: &NovaFoldingProof<'_>,
    xi: &Fr,
) -> Result<(), OnChainError> {
    if proof.w_comm.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    if proof.w_xi.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }

    // Claimed evaluation: first Fr in public_inputs, or zero if empty.
    let y = if proof.public_inputs.len() >= FR_LEN {
        fr_from_canonical_bytes(&proof.public_inputs[..FR_LEN])?
    } else {
        Fr::from(0u64)
    };

    // Session-35: consolidated LHS construction.
    //   A1 = W_comm - y·G1 + ξ·W_ξ
    let y_bytes = fr_to_canonical_bytes(&y);
    let mut w_arr = [0u8; G1_LEN];
    w_arr.copy_from_slice(proof.w_comm);
    let mut wxi_arr = [0u8; G1_LEN];
    wxi_arr.copy_from_slice(proof.w_xi);

    let a1 = compute_kzg_opening_lhs(
        backend,
        &w_arr,
        &y_bytes,
        &fr_to_canonical_bytes(xi),
        &wxi_arr,
    )?;

    // Pair: (A1, G2) · (-W_ξ, x2_G2).
    let neg_wxi = negate_g1(&wxi_arr);
    verify_two_pair_pairing(backend, &a1, &g2_generator_bytes(), &neg_wxi, &vk.x2_g2)
}

/// Session-19: Spartan-batched multi-poly opening for Nova.
///
/// Real Nova (with a Spartan wrapper) opens five commitments at the
/// Spartan evaluation point ξ — the R1CS matrix polys `(A·z, B·z, C·z)`
/// from the VK, plus the error `E` and witness `W` from the folded
/// proof. This function collapses all five into one batched KZG
/// opening via a `v` challenge:
///
/// ```text
/// v-powers:   [1, v, v², v³, v⁴]
/// C_batched = v⁰·a_comm + v¹·b_comm + v²·c_comm + v³·e_comm + v⁴·w_comm
/// y_batched = v⁰·a_eval + v¹·b_eval + v²·c_eval + v³·e_eval + v⁴·w_eval
///
/// e(C_batched - y_batched·G1 + ξ·W_ξ, [1]_2) · e(-W_ξ, [x]_2) ?= 1
/// ```
///
/// Tampering *any* of the five commits or evals now propagates into
/// the batched pairing identity — the session-≤18 scaffold exercised
/// only `w_comm` + first-public-input, which silently absorbed
/// tampering of `a_comm / b_comm / c_comm / e_comm` and the Hadamard
/// evaluations.
///
/// ## Evaluation sources
///
/// - `a_eval`, `b_eval`, `c_eval`, `e_eval`: parsed from
///   `proof.hadamard_evals` (4 × 32 B).
/// - `w_eval`: session-23 dedicated 32-byte slot `proof.w_eval`
///   carrying `W̃(ξ)` — the prover's claimed evaluation of the
///   witness polynomial at the Spartan point. Sessions ≤22 used
///   the first public input as a scaffold stand-in.
///
/// ## Errors
///
/// - [`OnChainError::InvalidPointEncoding`] — any commit or opening is
///   not 64 bytes.
/// - [`OnChainError::PublicInputOutOfRange`] — any Fr out of range.
/// - [`OnChainError::ProofLengthMismatch`] — `hadamard_evals` shorter
///   than `4 × 32`.
/// - [`OnChainError::PairingCheckFailed`] — batched pairing fails.
pub fn verify_spartan_batched_opening<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &NovaFoldingVerifyingKey,
    proof: &NovaFoldingProof<'_>,
    xi: &Fr,
    v: &Fr,
) -> Result<(), OnChainError> {
    use crate::canonical::sizes::HADAMARD_EVALS_LEN;
    if proof.w_comm.len() != G1_LEN
        || proof.e_comm.len() != G1_LEN
        || proof.w_xi.len() != G1_LEN
    {
        return Err(OnChainError::InvalidPointEncoding);
    }
    if proof.hadamard_evals.len() < HADAMARD_EVALS_LEN {
        return Err(OnChainError::ProofLengthMismatch);
    }

    let a_eval = fr_from_canonical_bytes(&proof.hadamard_evals[0..FR_LEN])?;
    let b_eval =
        fr_from_canonical_bytes(&proof.hadamard_evals[FR_LEN..2 * FR_LEN])?;
    let c_eval =
        fr_from_canonical_bytes(&proof.hadamard_evals[2 * FR_LEN..3 * FR_LEN])?;
    let e_eval =
        fr_from_canonical_bytes(&proof.hadamard_evals[3 * FR_LEN..4 * FR_LEN])?;
    // Session 23: w_eval now comes from a dedicated 32-byte slot
    // rather than the first public input.
    if proof.w_eval.len() != FR_LEN {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let w_eval = fr_from_canonical_bytes(proof.w_eval)?;

    // v-powers: [1, v, v², v³, v⁴].
    let one = Fr::from(1u64);
    let v1 = *v;
    let v2 = v1 * v1;
    let v3 = v2 * v1;
    let v4 = v3 * v1;
    let v_powers: [Fr; 5] = [one, v1, v2, v3, v4];
    let scalars: [[u8; FR_LEN]; 5] = [
        fr_to_canonical_bytes(&v_powers[0]),
        fr_to_canonical_bytes(&v_powers[1]),
        fr_to_canonical_bytes(&v_powers[2]),
        fr_to_canonical_bytes(&v_powers[3]),
        fr_to_canonical_bytes(&v_powers[4]),
    ];
    let commits: [&[u8]; 5] = [
        &vk.a_comm,
        &vk.b_comm,
        &vk.c_comm,
        proof.e_comm,
        proof.w_comm,
    ];
    let c_batched = msm_g1(backend, &commits, &scalars)?;

    let y_batched = v_powers[0] * a_eval
        + v_powers[1] * b_eval
        + v_powers[2] * c_eval
        + v_powers[3] * e_eval
        + v_powers[4] * w_eval;

    // Session-35: consolidated LHS construction.
    //   A1 = C_batched - y_batched·G1 + ξ·W_ξ
    let mut wxi_arr = [0u8; G1_LEN];
    wxi_arr.copy_from_slice(proof.w_xi);
    let a1 = compute_kzg_opening_lhs(
        backend,
        &c_batched,
        &fr_to_canonical_bytes(&y_batched),
        &fr_to_canonical_bytes(xi),
        &wxi_arr,
    )?;
    let neg_wxi = negate_g1(&wxi_arr);
    verify_two_pair_pairing(backend, &a1, &g2_generator_bytes(), &neg_wxi, &vk.x2_g2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{sizes, FoldingVariant};
    use alloc::vec;
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_zk_primitives::g1_consts::g1_generator_bytes;

    fn valid_g2_vk() -> NovaFoldingVerifyingKey {
        NovaFoldingVerifyingKey {
            variant: FoldingVariant::Nova,
            n_public: 0,
            n_constraints: 100,
            x2_g2: g2_generator_bytes(),
            a_comm: [0; sizes::G1_LEN],
            b_comm: [0; sizes::G1_LEN],
            c_comm: [0; sizes::G1_LEN],
            cs_digest: [0; 32],
        }
    }

    fn minimal_proof_bytes() -> alloc::vec::Vec<u8> {
        let total = sizes::FIXED_HEADER_LEN
            + sizes::FIXED_COMMITS_LEN
            + sizes::SCALAR_LEN
            + 4 * sizes::G1_LEN // session-15-nova base commits
            + sizes::HADAMARD_EVALS_LEN
            + sizes::W_EVAL_LEN
            + sizes::OPENING_LEN;
        let mut buf = vec![0u8; total];
        buf[0] = FoldingVariant::Nova as u8;
        buf
    }

    #[test]
    fn all_zero_trivially_passes_pairing() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let proof = NovaFoldingProof::from_bytes(&proof_buf).unwrap();

        let r = verify_opening_scaffold(&backend, &vk, &proof, &Fr::from(0u64));
        assert!(r.is_ok(), "zero-proof pairing should pass, got {r:?}");
    }

    #[test]
    fn rejects_short_w_comm() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let parsed = NovaFoldingProof::from_bytes(&proof_buf).unwrap();
        let bad = NovaFoldingProof {
            w_comm: &parsed.w_comm[..63],
            ..parsed
        };
        let r = verify_opening_scaffold(&backend, &vk, &bad, &Fr::from(0u64));
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    #[test]
    fn rejects_short_w_xi() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let parsed = NovaFoldingProof::from_bytes(&proof_buf).unwrap();
        let bad = NovaFoldingProof {
            w_xi: &parsed.w_xi[..63],
            ..parsed
        };
        let r = verify_opening_scaffold(&backend, &vk, &bad, &Fr::from(0u64));
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    #[test]
    fn nonzero_commit_with_wrong_opening_fails() {
        // Same pattern as Halo2's KZG scaffold test: construct inputs
        // where the pairing shouldn't hold.
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let mut proof_buf = minimal_proof_bytes();

        let g1_gen = g1_generator_bytes();
        // W commit offset: FIXED + G1 (E comes first) → 16 + 64 = 80.
        let w_off = sizes::FIXED_HEADER_LEN + sizes::G1_LEN;
        proof_buf[w_off..w_off + sizes::G1_LEN].copy_from_slice(&g1_gen);
        // W_xi at proof.len() - 2·G1.
        let w_xi_off = proof_buf.len() - 2 * sizes::G1_LEN;
        proof_buf[w_xi_off..w_xi_off + sizes::G1_LEN].copy_from_slice(&g1_gen);
        // No public_inputs → y = 0; W = G1; ξ·W_ξ = 2·G1.
        // A1 = G1 - 0 + 2·G1 = 3·G1. Pair1 = e(3G1, G2). Pair2 = e(-G1, G2).
        // Product = e(2G1, G2) ≠ 1 → fails.
        let proof = NovaFoldingProof::from_bytes(&proof_buf).unwrap();
        let r = verify_opening_scaffold(&backend, &vk, &proof, &Fr::from(2u64));
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "expected PairingCheckFailed, got {r:?}",
        );
    }
}
