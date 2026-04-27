//! Vanishing argument evaluation for Halo2-KZG.
//!
//! After challenges `(θ, β, γ, y, ξ)` are sampled, Halo2's verifier
//! checks that the vanishing identity holds at `ξ`:
//!
//! ```text
//! t(ξ) · Z_H(ξ)  ?=  gate_expr(ξ)
//!                  + y · permutation_expr(ξ, β, γ, z(ξ))
//!                  + y² · lookup_expr(ξ, θ, m(ξ))
//! ```
//!
//! where:
//! - `Z_H(ξ) = ξ^(2^k) - 1` — vanishing polynomial of the domain.
//! - `t(ξ) = Σ_i ξ^(i·2^k) · h_i(ξ)` — quotient poly from chunks.
//! - gate / perm / lookup expressions depend on the specific circuit
//!   and its evaluations at `ξ`.
//!
//! ## Module scope (session 4b)
//!
//! This module provides the **domain-level** primitives:
//!
//! - [`compute_z_h`] — closed-form evaluation of `Z_H(ξ)`.
//! - [`compute_t_from_chunks`] — reconstructs `t(ξ)` from `h_i(ξ)`
//!   chunk evaluations and the domain parameter `k`.
//!
//! Gate / permutation / lookup expression evaluation requires a
//! concrete circuit representation that Halo2's flexibility makes
//! hard to standardize. Session 4c will define a **single-gate
//! scaffold** (PLONK-style + one lookup, no custom gates) for an
//! initial end-to-end wiring; richer circuit families land when
//! real fixtures arrive in session 4e.
//!
//! ## Why these are standalone
//!
//! `compute_z_h` and `compute_t_from_chunks` are pure Fr arithmetic,
//! independent of circuit topology, and testable against closed-form
//! arkworks references. Isolating them lets us validate the math
//! before layering the circuit-specific evaluators on top.

use ark_bn254::Fr;
use ark_ff::One;
use mosaic_core::OnChainError;
use mosaic_zk_primitives::field::fr_pow_u64;

/// Evaluate the vanishing polynomial `Z_H(ξ) = ξ^(2^k) - 1`.
///
/// The domain `H` for a Halo2 circuit of parameter `k` has size `2^k`
/// and is the set of `2^k`-th roots of unity. `Z_H` vanishes on `H`,
/// so at any `ξ ∈ H` this returns zero — which happens with negligible
/// probability for random Fiat-Shamir ξ.
///
/// ## Errors
///
/// Returns [`OnChainError::ProofLengthMismatch`] if `k > 28` — no
/// realistic Halo2 circuit exceeds 2^28 rows, and larger values risk
/// u64 overflow in `fr_pow_u64`.
pub fn compute_z_h(xi: &Fr, k: u32) -> Result<Fr, OnChainError> {
    if k > 28 {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let domain_size: u64 = 1u64 << k;
    let xi_n = fr_pow_u64(xi, domain_size);
    Ok(xi_n - Fr::one())
}

/// Reconstruct `t(ξ)` from the quotient polynomial chunks
/// `h_0(ξ), h_1(ξ), ..., h_{m-1}(ξ)`.
///
/// Halo2 splits the quotient polynomial `t(X)` into `m` chunks to fit
/// within the trusted-setup SRS size: `t(X) = Σ_i X^(i·2^k) · h_i(X)`.
/// At evaluation point ξ this becomes:
///
/// ```text
/// t(ξ) = Σ_i ξ^(i·2^k) · h_i(ξ) = h_0(ξ) + ξ^(2^k)·h_1(ξ) + ξ^(2·2^k)·h_2(ξ) + ...
/// ```
///
/// The evaluations `h_i(ξ)` are sent by the prover as part of the
/// proof's evaluation bundle.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if `k > 28` or
///   `chunk_evals.is_empty()`.
pub fn compute_t_from_chunks(chunk_evals: &[Fr], xi: &Fr, k: u32) -> Result<Fr, OnChainError> {
    if k > 28 {
        return Err(OnChainError::ProofLengthMismatch);
    }
    if chunk_evals.is_empty() {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let domain_size: u64 = 1u64 << k;
    let xi_n = fr_pow_u64(xi, domain_size);

    // Polynomial reconstruction: t(ξ) = Σ h_i · (ξ^n)^i.
    //
    // The "evaluation point" for this Horner reduction is ξ^n
    // rather than ξ — each chunk is the i-th coefficient of the
    // polynomial that takes ξ^n as its variable. Session 64
    // migrated this site from an inline Horner loop to the shared
    // `mosaic_zk_primitives::field::fr_horner_eval` primitive
    // (added in session 63), giving the same audit-grade soundness
    // pin every other Phase-3 polynomial-eval site will get as it
    // migrates.
    Ok(mosaic_zk_primitives::field::fr_horner_eval(
        chunk_evals,
        &xi_n,
    ))
}

/// Combined vanishing-identity check:
///
/// ```text
/// t(ξ) · Z_H(ξ)  ?=  gate_value + y · perm_value + y² · lookup_value
/// ```
///
/// `gate_value`, `perm_value`, `lookup_value` are computed by the
/// circuit-specific evaluators (session 4c). This function just does
/// the linear combination + the LHS multiplication + comparison.
#[must_use]
pub fn vanishing_identity_holds(
    t_xi: &Fr,
    z_h_xi: &Fr,
    y: &Fr,
    gate_value: &Fr,
    perm_value: &Fr,
    lookup_value: &Fr,
) -> bool {
    let lhs = *t_xi * z_h_xi;
    let y_sq = *y * y;
    let rhs = *gate_value + *y * perm_value + y_sq * lookup_value;
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    // ---- compute_z_h ----

    #[test]
    fn z_h_matches_direct_formula() {
        let mut r = rng(1);
        for k in [0, 1, 4, 10, 20] {
            let xi = Fr::rand(&mut r);
            let got = compute_z_h(&xi, k).unwrap();
            let expected = fr_pow_u64(&xi, 1u64 << k) - Fr::one();
            assert_eq!(got, expected, "k={k}");
        }
    }

    #[test]
    fn z_h_vanishes_at_unity() {
        // 1^n - 1 = 0 for any n → Z_H vanishes when ξ is a 1-st root
        // of unity. More generally Z_H vanishes on the n-th roots of
        // unity; we test the most trivial point.
        for k in [0, 5, 10, 20] {
            let got = compute_z_h(&Fr::one(), k).unwrap();
            assert_eq!(got, Fr::zero(), "Z_H(1) should be 0 for k={k}");
        }
    }

    #[test]
    fn z_h_k_zero_is_xi_minus_one() {
        // k=0 → domain size 1 → Z_H(ξ) = ξ^1 - 1 = ξ - 1.
        let mut r = rng(2);
        for _ in 0..5 {
            let xi = Fr::rand(&mut r);
            let got = compute_z_h(&xi, 0).unwrap();
            assert_eq!(got, xi - Fr::one());
        }
    }

    #[test]
    fn z_h_rejects_k_over_28() {
        let xi = Fr::from(2u64);
        assert!(matches!(
            compute_z_h(&xi, 29),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    // ---- compute_t_from_chunks ----

    #[test]
    fn t_single_chunk_is_just_that_chunk() {
        // m=1: t(ξ) = h_0(ξ).
        let mut r = rng(10);
        for k in [0, 4, 10] {
            let xi = Fr::rand(&mut r);
            let h0 = Fr::rand(&mut r);
            let got = compute_t_from_chunks(&[h0], &xi, k).unwrap();
            assert_eq!(got, h0, "k={k}");
        }
    }

    #[test]
    fn t_two_chunks_matches_closed_form() {
        // m=2: t(ξ) = h_0(ξ) + ξ^(2^k) · h_1(ξ).
        let mut r = rng(11);
        for k in [0, 1, 4, 10] {
            let xi = Fr::rand(&mut r);
            let h0 = Fr::rand(&mut r);
            let h1 = Fr::rand(&mut r);
            let got = compute_t_from_chunks(&[h0, h1], &xi, k).unwrap();
            let n = 1u64 << k;
            let expected = h0 + fr_pow_u64(&xi, n) * h1;
            assert_eq!(got, expected, "k={k}");
        }
    }

    #[test]
    fn t_many_chunks_matches_explicit_summation() {
        let mut r = rng(12);
        let k = 4u32;
        let n = 1u64 << k;
        for m in [1, 2, 3, 5, 10] {
            let xi = Fr::rand(&mut r);
            let chunks: alloc::vec::Vec<Fr> = (0..m).map(|_| Fr::rand(&mut r)).collect();
            let got = compute_t_from_chunks(&chunks, &xi, k).unwrap();

            // Reference: explicit summation Σ ξ^(i·n) · h_i.
            let mut expected = Fr::zero();
            for (i, h) in chunks.iter().enumerate() {
                let power = fr_pow_u64(&xi, (i as u64) * n);
                expected += power * h;
            }
            assert_eq!(got, expected, "m={m}");
        }
    }

    #[test]
    fn t_rejects_empty_chunks() {
        let xi = Fr::from(5u64);
        let empty: [Fr; 0] = [];
        assert!(matches!(
            compute_t_from_chunks(&empty, &xi, 4),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn t_rejects_k_over_28() {
        let xi = Fr::from(2u64);
        let h = [Fr::from(1u64)];
        assert!(matches!(
            compute_t_from_chunks(&h, &xi, 29),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    // ---- vanishing_identity_holds ----

    #[test]
    fn vanishing_identity_accepts_matching_lhs_rhs() {
        // Construct gate/perm/lookup such that the identity holds for
        // a random (t, z_h, y).
        let mut r = rng(20);
        let t_xi = Fr::rand(&mut r);
        let z_h_xi = Fr::rand(&mut r);
        let y = Fr::rand(&mut r);
        let gate = Fr::rand(&mut r);
        let perm = Fr::rand(&mut r);
        // Pick lookup such that lhs == rhs:
        //   lhs = t·Z_H
        //   rhs = gate + y·perm + y²·lookup
        //   lookup = (lhs - gate - y·perm) / y²
        use ark_ff::Field;
        let lhs = t_xi * z_h_xi;
        let y_sq = y * y;
        let y_sq_inv = y_sq.inverse().unwrap();
        let lookup = (lhs - gate - y * perm) * y_sq_inv;

        assert!(vanishing_identity_holds(
            &t_xi, &z_h_xi, &y, &gate, &perm, &lookup,
        ));
    }

    #[test]
    fn vanishing_identity_rejects_tampered_gate() {
        let mut r = rng(21);
        let t_xi = Fr::rand(&mut r);
        let z_h_xi = Fr::rand(&mut r);
        let y = Fr::rand(&mut r);
        let gate = Fr::rand(&mut r);
        let perm = Fr::rand(&mut r);
        use ark_ff::Field;
        let lhs = t_xi * z_h_xi;
        let y_sq = y * y;
        let lookup = (lhs - gate - y * perm) * y_sq.inverse().unwrap();

        // Bump gate by 1 → identity fails.
        let bad_gate = gate + Fr::one();
        assert!(!vanishing_identity_holds(
            &t_xi, &z_h_xi, &y, &bad_gate, &perm, &lookup,
        ));
    }

    #[test]
    fn vanishing_identity_all_zero_holds_trivially() {
        // 0 · 0 == 0 + 0·0 + 0·0 = 0 — trivial accept.
        assert!(vanishing_identity_holds(
            &Fr::zero(),
            &Fr::zero(),
            &Fr::zero(),
            &Fr::zero(),
            &Fr::zero(),
            &Fr::zero(),
        ));
    }
}
