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
//! at `ξ`. Structurally identical to the HyperPlonk and Halo2
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
use alloc::vec::Vec;
use ark_bn254::Fr;
use mosaic_core::{
    syscall::{AltBn128Op, InputEndianness, SyscallBackend},
    OnChainError,
};
use mosaic_plonk::{
    field::{fr_from_canonical_bytes, fr_to_canonical_bytes},
    g1_consts::{g1_generator_bytes, g2_generator_bytes},
    msm::{add_g1, negate_g1, scalar_mul_g1},
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
/// - [`OnChainError::InvalidPointEncoding`] if w_comm or w_xi is
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

    // Build LHS G1 arg: W - y·G1 + ξ·W_ξ.
    let g1_gen = g1_generator_bytes();
    let y_bytes = fr_to_canonical_bytes(&y);
    let y_g1 = scalar_mul_g1(backend, &g1_gen, &y_bytes)?;
    let neg_y_g1 = negate_g1(&y_g1);

    let mut w_arr = [0u8; G1_LEN];
    w_arr.copy_from_slice(proof.w_comm);
    let w_minus_y = add_g1(backend, &w_arr, &neg_y_g1)?;

    let xi_bytes = fr_to_canonical_bytes(xi);
    let mut wxi_arr = [0u8; G1_LEN];
    wxi_arr.copy_from_slice(proof.w_xi);
    let xi_wxi = scalar_mul_g1(backend, &wxi_arr, &xi_bytes)?;

    let a1 = add_g1(backend, &w_minus_y, &xi_wxi)?;

    // Pair: (A1, G2) · (-W_ξ, x2_G2).
    let neg_wxi = negate_g1(&wxi_arr);
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
    use crate::canonical::{sizes, FoldingVariant};
    use alloc::vec;
    use mosaic_core::syscall::host::HostBackend;

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
