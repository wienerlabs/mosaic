//! Fuzz harness — HyperPlonk `verify_sumcheck_claim_reduction` audit gate.
//!
//! Session 95 — fuzzes the audit-gate primitive directly with a
//! random `(final_evals, α, β, γ, vk_kₙ, sumcheck_final_claim)`
//! tuple.
//!
//! Input layout:
//!
//! ```text
//! [final_evals:   12 × 32 = 384 B (the Fr eval bundle)]
//! [alpha, beta, gamma:    3 × 32 = 96 B]
//! [k_1, k_2, k_3:         3 × 32 = 96 B (VK coset constants)]
//! [sumcheck_final_claim:  32 B Fr]
//! ```
//!
//! Total = 384 + 96 + 96 + 32 = 608 bytes minimum.
//!
//! The remainder of the VK is filled with deterministic placeholder
//! bytes — only the coset constants influence the gate's
//! permutation_term computation.
//!
//! The gate's documented rejection paths:
//! - `ProofLengthMismatch` (final_evals too short — not exercised
//!   here since we always pass exactly 384 bytes)
//! - `PublicInputOutOfRange` (any Fr in the bundle out of range)
//! - `SumcheckFailed` (recomputed expected claim ≠ alleged)
//!
//! ADR-0006 reference: see
//! [`mosaic_hyperplonk::verify_sumcheck_claim_reduction`].

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_hyperplonk::{
    verify_sumcheck_claim_reduction, HyperPlonkVerifyingKey, PreSumcheckChallenges,
};
use mosaic_zk_primitives::field::fr_from_canonical_bytes;

const FR_LEN: usize = 32;
const G1_LEN: usize = 64;
const G2_LEN: usize = 128;
const FINAL_EVALS_LEN: usize = 12 * FR_LEN; // 384

// 384 (final_evals) + 96 (α/β/γ) + 96 (k_1/k_2/k_3) + 32 (claim) = 608.
const MIN_INPUT_LEN: usize = FINAL_EVALS_LEN + 7 * FR_LEN;

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN_INPUT_LEN {
        return;
    }
    let mut off = 0;
    let final_evals = &data[off..off + FINAL_EVALS_LEN];
    off += FINAL_EVALS_LEN;

    let Ok(alpha) = fr_from_canonical_bytes(&data[off..off + FR_LEN]) else {
        return;
    };
    off += FR_LEN;
    let Ok(beta) = fr_from_canonical_bytes(&data[off..off + FR_LEN]) else {
        return;
    };
    off += FR_LEN;
    let Ok(gamma) = fr_from_canonical_bytes(&data[off..off + FR_LEN]) else {
        return;
    };
    off += FR_LEN;

    let mut k_1 = [0u8; FR_LEN];
    k_1.copy_from_slice(&data[off..off + FR_LEN]);
    off += FR_LEN;
    let mut k_2 = [0u8; FR_LEN];
    k_2.copy_from_slice(&data[off..off + FR_LEN]);
    off += FR_LEN;
    let mut k_3 = [0u8; FR_LEN];
    k_3.copy_from_slice(&data[off..off + FR_LEN]);
    off += FR_LEN;

    let Ok(sumcheck_final_claim) = fr_from_canonical_bytes(&data[off..off + FR_LEN]) else {
        return;
    };

    let challenges = PreSumcheckChallenges { alpha, beta, gamma };
    let vk = HyperPlonkVerifyingKey {
        n_public: 1,
        num_variables: 10,
        x2_g2: [0; G2_LEN],
        q_m_g1: [0; G1_LEN],
        q_l_g1: [0; G1_LEN],
        q_r_g1: [0; G1_LEN],
        q_o_g1: [0; G1_LEN],
        q_c_g1: [0; G1_LEN],
        sigma_1_g1: [0; G1_LEN],
        sigma_2_g1: [0; G1_LEN],
        sigma_3_g1: [0; G1_LEN],
        k_1,
        k_2,
        k_3,
    };

    // Either Ok(()) or any documented Err variant is acceptable.
    let _ = verify_sumcheck_claim_reduction(
        final_evals,
        &challenges,
        &vk,
        &sumcheck_final_claim,
    );
});
