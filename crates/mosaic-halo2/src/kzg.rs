//! KZG opening verifier (scaffold).
//!
//! Halo2 ships a **two-point batched** opening `(W_ξ, W_ξω)` — one
//! per evaluation site in the grand-product-style argument. This
//! module's scaffold only exercises the single-point W_ξ path to keep
//! the wiring minimal while structurally correct; session 4e pins the
//! full two-point batching against Espresso/PSE reference fixtures.
//!
//! ## Pairing check
//!
//! ```text
//! e(C - [y]_G1 + ξ · W_ξ, [1]_G2) · e(-W_ξ, [x]_G2) ?= 1
//! ```
//!
//! where:
//! - `C` = batched commitment (scaffold: single `permutation_z` commit
//!   from the proof).
//! - `y` = claimed evaluation (scaffold: `evaluations[0]`).
//! - `ξ` = evaluation point (challenge from transcript).
//!
//! Same bilinearity rewrite as `mosaic-hyperplonk::kzg` — avoids
//! on-chain G2 scalar mul.
//!
//! ## Scaffold limitations
//!
//! - **Single-commitment opening** vs real Halo2's multi-poly batched
//!   opening. Session 4e extends to the full MSM over advice +
//!   permutation + quotient + VK preprocessing commits.
//! - **No ξω second opening** — the canonical W_ξω field is parsed but
//!   unused until session 4e.
//! - No on-chain ω computation (needs domain generator from `k`).

use crate::canonical::{
    sizes::{FR_LEN, G1_LEN},
    Halo2KzgProof, Halo2KzgVerifyingKey,
};
use alloc::vec::Vec;
use ark_bn254::Fr;
use mosaic_core::{
    syscall::{AltBn128Op, InputEndianness, SyscallBackend},
    OnChainError,
};
use mosaic_zk_primitives::{
    field::{fr_from_canonical_bytes, fr_to_canonical_bytes},
    g1_consts::{g1_generator_bytes, g2_generator_bytes},
    msm::{add_g1, negate_g1, scalar_mul_g1},
};

/// Scaffold single-point KZG opening check.
///
/// Verifies `e(C - y·G1 + ξ·W_ξ, G2) · e(-W_ξ, x2_G2) == 1` where
/// `C = proof.permutation_z` and `y = proof.evaluations[0]`.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if proof evaluations are
///   empty (need at least one Fr for the opening value).
/// - [`OnChainError::InvalidPointEncoding`] if permutation_z or w_xi
///   is malformed.
/// - [`OnChainError::PublicInputOutOfRange`] if the evaluation Fr is
///   out of range.
/// - [`OnChainError::PairingCheckFailed`] on a false pairing result.
pub fn verify_opening_scaffold<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &Halo2KzgVerifyingKey,
    proof: &Halo2KzgProof<'_>,
    xi: &Fr,
) -> Result<(), OnChainError> {
    if proof.evaluations.len() < FR_LEN {
        return Err(OnChainError::ProofLengthMismatch);
    }
    if proof.permutation_z.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    if proof.w_xi.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }

    // Claimed evaluation: first Fr in the evaluations bundle.
    let y = fr_from_canonical_bytes(&proof.evaluations[..FR_LEN])?;
    let y_bytes = fr_to_canonical_bytes(&y);

    // C - y·G1.
    let g1_gen = g1_generator_bytes();
    let y_g1 = scalar_mul_g1(backend, &g1_gen, &y_bytes)?;
    let neg_y_g1 = negate_g1(&y_g1);

    let mut c_arr = [0u8; G1_LEN];
    c_arr.copy_from_slice(proof.permutation_z);
    let c_minus_y = add_g1(backend, &c_arr, &neg_y_g1)?;

    // ξ·W_ξ.
    let xi_bytes = fr_to_canonical_bytes(xi);
    let mut wxi_arr = [0u8; G1_LEN];
    wxi_arr.copy_from_slice(proof.w_xi);
    let xi_wxi = scalar_mul_g1(backend, &wxi_arr, &xi_bytes)?;

    // A1 = C - y·G1 + ξ·W_ξ.
    let a1 = add_g1(backend, &c_minus_y, &xi_wxi)?;

    // -W_ξ for the second pair.
    let neg_wxi = negate_g1(&wxi_arr);

    // Pairing inputs:
    //   Pair 1: (A1, [1]_G2)
    //   Pair 2: (-W_ξ, [x]_G2)
    let g2_gen = g2_generator_bytes();
    let mut pairing_input: Vec<u8> = Vec::with_capacity(2 * (G1_LEN + 128));
    pairing_input.extend_from_slice(&a1);
    pairing_input.extend_from_slice(&g2_gen);
    pairing_input.extend_from_slice(&neg_wxi);
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
    use crate::canonical::sizes::FIXED_HEADER_LEN;
    use alloc::vec;
    use mosaic_core::syscall::host::HostBackend;

    fn valid_g2_vk() -> Halo2KzgVerifyingKey {
        Halo2KzgVerifyingKey {
            k: 4,
            n_instances: 0,
            n_advice: 1,
            n_fixed: 0,
            x2_g2: g2_generator_bytes(),
            fixed_commits: vec![],
            permutation_commits: vec![],
        }
    }

    fn minimal_proof_bytes() -> alloc::vec::Vec<u8> {
        // 1 advice, 0 lookups, 1 quotient, 1 eval.
        let n_advice: u32 = 1;
        let n_lookups: u32 = 0;
        let n_quotient: u32 = 1;
        let n_evals: u32 = 1;
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
        buf
    }

    #[test]
    fn all_zero_trivially_passes_pairing() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();

        let r = verify_opening_scaffold(&backend, &vk, &proof, &Fr::from(0u64));
        // Zero permutation_z + zero eval + zero W_xi → pairing of
        // identities = 1 trivially.
        assert!(r.is_ok(), "zero-proof pairing should pass, got {r:?}");
    }

    #[test]
    fn rejects_short_evaluations() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let proof_parsed = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let bad_proof = Halo2KzgProof {
            evaluations: &[],
            ..proof_parsed
        };
        let r = verify_opening_scaffold(&backend, &vk, &bad_proof, &Fr::from(0u64));
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn rejects_short_w_xi() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let proof_parsed = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let bad_proof = Halo2KzgProof {
            w_xi: &proof_parsed.w_xi[..63],
            ..proof_parsed
        };
        let r = verify_opening_scaffold(&backend, &vk, &bad_proof, &Fr::from(0u64));
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    #[test]
    fn nonzero_commit_with_wrong_opening_fails() {
        // Set permutation_z = G1_generator, eval = 1, W_xi = G1_generator,
        // ξ = 2. Then A1 = G1 - G1 + 2·G1 = 2·G1, Pair1 = e(2G1, G2),
        // Pair2 = e(-G1, G2) (since x = 1 in scaffold SRS). Product =
        // e(G1, G2) ≠ 1 → fails.
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let mut proof_buf = minimal_proof_bytes();

        let g1_gen = g1_generator_bytes();
        // permutation_z offset: FIXED + n_advice·G1 + n_lookups·G1
        // = 16 + 64 + 0 = 80.
        let z_off = FIXED_HEADER_LEN + G1_LEN;
        proof_buf[z_off..z_off + G1_LEN].copy_from_slice(&g1_gen);
        // First evaluation (Fr = 1): offset = z_off + G1_LEN (perm_z) +
        // n_quotient·G1 = 80 + 64 + 64 = 208; last byte of Fr = 1.
        let eval_off = z_off + G1_LEN + G1_LEN;
        proof_buf[eval_off + FR_LEN - 1] = 1;
        // W_xi at the end, second-to-last G1.
        let w_xi_off = proof_buf.len() - 2 * G1_LEN;
        proof_buf[w_xi_off..w_xi_off + G1_LEN].copy_from_slice(&g1_gen);

        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let r = verify_opening_scaffold(&backend, &vk, &proof, &Fr::from(2u64));
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "expected PairingCheckFailed, got {r:?}",
        );
    }
}
