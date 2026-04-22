//! FRI (Fast Reed-Solomon IOP of Proximity) fold-consistency primitives.
//!
//! FRI verification proceeds layer by layer. At each layer `i`, the
//! verifier has committed evaluations of a polynomial `f_i` over a
//! domain of size `n_i`, and needs to check that the prover's claimed
//! next-layer polynomial `f_{i+1}` is indeed the correct fold of `f_i`
//! at a random challenge `β_i`.
//!
//! ## Fold relation
//!
//! The standard radix-2 FRI fold at a point `x ∈ L_i`:
//!
//! ```text
//! f_{i+1}(x²) = (f_i(x) + f_i(-x)) / 2  +  β_i · (f_i(x) − f_i(-x)) / (2x)
//! ```
//!
//! The two summands split `f_i` into its **even** (`f_e`) and **odd**
//! (`f_o`) parts:
//!
//! - `f_e(x²) = (f_i(x) + f_i(-x)) / 2`
//! - `f_o(x²) = (f_i(x) − f_i(-x)) / (2x)`
//! - `f_i(x) = f_e(x²) + x · f_o(x²)`
//!
//! The fold then computes `f_{i+1}(x²) = f_e(x²) + β_i · f_o(x²)` — a
//! random linear combination that the next layer's prover commits to.
//!
//! ## What this module provides
//!
//! - [`fold_relation_holds`] — the structural check: given prover-sent
//!   `(f_x, f_neg_x, f_next, β, x)`, returns true iff the relation
//!   above is satisfied. No transcript parsing, no proof decode — just
//!   arithmetic.
//! - [`compute_next_layer_value`] — explicit constructor that returns
//!   the fold result `f_{i+1}(x²)` given the five inputs. Useful for
//!   test fixtures and for the host-side prover oracle.
//!
//! Session 12 wires these into the verifier pipeline alongside
//! structured per-FRI-layer openings in the canonical layout.

use crate::goldilocks::Goldilocks;
use mosaic_core::OnChainError;

/// Compute the FRI fold: `f_{i+1}(x²) = f_e(x²) + β · f_o(x²)` where
///
/// - `f_e(x²) = (f_x + f_neg_x) · 2^(-1)` — even part.
/// - `f_o(x²) = (f_x − f_neg_x) · (2x)^(-1)` — odd part.
///
/// ## Errors
///
/// Returns [`OnChainError::InternalInvariantViolation`] if `x == 0`
/// (the odd-part denominator would be zero). In production FRI
/// transcripts the challenge point is non-zero with overwhelming
/// probability; explicit guard prevents silent bad arithmetic.
pub fn compute_next_layer_value(
    f_x: Goldilocks,
    f_neg_x: Goldilocks,
    beta: Goldilocks,
    x: Goldilocks,
) -> Result<Goldilocks, OnChainError> {
    if x.as_u64() == 0 {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let two_inv = Goldilocks::new(2)
        .inverse()
        .ok_or(OnChainError::InternalInvariantViolation)?;
    let two_x_inv = Goldilocks::new(2)
        .mul(x)
        .inverse()
        .ok_or(OnChainError::InternalInvariantViolation)?;

    // Even part: (f_x + f_neg_x) / 2.
    let f_even = f_x.add(f_neg_x).mul(two_inv);
    // Odd part: (f_x − f_neg_x) / (2x).
    let f_odd = f_x.sub(f_neg_x).mul(two_x_inv);
    // Fold: f_even + β · f_odd.
    Ok(f_even.add(beta.mul(f_odd)))
}

/// Check the FRI fold relation: does `f_next` equal the computed fold
/// of `(f_x, f_neg_x, β, x)`?
///
/// Returns `Ok(true)` on a valid fold, `Ok(false)` otherwise. Returns
/// an error only if the arithmetic itself can't be performed (zero
/// `x`, zero `2`, etc. — never happens with canonical Goldilocks).
pub fn fold_relation_holds(
    f_x: Goldilocks,
    f_neg_x: Goldilocks,
    f_next: Goldilocks,
    beta: Goldilocks,
    x: Goldilocks,
) -> Result<bool, OnChainError> {
    let expected = compute_next_layer_value(f_x, f_neg_x, beta, x)?;
    Ok(f_next == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: directly evaluate a polynomial `p(t) = Σ c_i · t^i` at
    /// a point in Goldilocks. Small-polynomial helper for constructing
    /// test fixtures from known coefficient vectors.
    fn eval_poly(coeffs: &[Goldilocks], t: Goldilocks) -> Goldilocks {
        let mut acc = Goldilocks::zero();
        let mut t_pow = Goldilocks::one();
        for &c in coeffs {
            acc = acc.add(c.mul(t_pow));
            t_pow = t_pow.mul(t);
        }
        acc
    }

    // ---- compute_next_layer_value ----

    #[test]
    fn fold_with_linear_polynomial() {
        // p(t) = 3 + 5·t. Even part = 3, odd part = 5.
        // At x = 7: p(7) = 3 + 35 = 38. p(-7) = 3 - 35 = -32 ≡ p - 32.
        // Fold at β = 11: even(x²) + β·odd(x²) = 3 + 11·5 = 58.
        let coeffs = [Goldilocks::new(3), Goldilocks::new(5)];
        let x = Goldilocks::new(7);
        let beta = Goldilocks::new(11);
        let f_x = eval_poly(&coeffs, x);
        let f_neg_x = eval_poly(&coeffs, x.neg());
        let got = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();
        assert_eq!(got.as_u64(), 58);
    }

    #[test]
    fn fold_with_quadratic_polynomial() {
        // p(t) = 2 + 3·t + 4·t². Split into even (2 + 4·t²) and odd (3·t).
        // f_even(x²) = 2 + 4·x². f_odd(x²) = 3 (constant).
        // Fold at β: (2 + 4·x²) + β·3.
        let coeffs = [
            Goldilocks::new(2),
            Goldilocks::new(3),
            Goldilocks::new(4),
        ];
        for x_val in [5u64, 13, 100, 999] {
            for beta_val in [2u64, 17, 42] {
                let x = Goldilocks::new(x_val);
                let beta = Goldilocks::new(beta_val);
                let f_x = eval_poly(&coeffs, x);
                let f_neg_x = eval_poly(&coeffs, x.neg());
                let got = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();

                // Expected: (2 + 4x²) + 3β.
                let x_sq = x.mul(x);
                let expected = Goldilocks::new(2)
                    .add(Goldilocks::new(4).mul(x_sq))
                    .add(Goldilocks::new(3).mul(beta));
                assert_eq!(got, expected, "x={x_val}, β={beta_val}");
            }
        }
    }

    #[test]
    fn fold_matches_direct_even_odd_decomposition() {
        // For arbitrary p(t), the fold is f_e(x²) + β·f_o(x²) where
        // f_e(X²) = Σ c_{2i} · X^(2i), f_o(X²) = Σ c_{2i+1} · X^(2i).
        // This should equal our primitive's output for random p.
        let coeffs: [Goldilocks; 6] = [
            Goldilocks::new(1),
            Goldilocks::new(9),
            Goldilocks::new(4),
            Goldilocks::new(7),
            Goldilocks::new(2),
            Goldilocks::new(6),
        ];
        let x = Goldilocks::new(12345);
        let beta = Goldilocks::new(999);

        // f_e(X²) = c_0 + c_2·X² + c_4·X⁴, evaluated at x² gives
        // c_0 + c_2·x² + c_4·x⁴.
        // f_o(X²) = c_1 + c_3·X² + c_5·X⁴, at x² gives
        // c_1 + c_3·x² + c_5·x⁴.
        let x_sq = x.mul(x);
        let x_4 = x_sq.mul(x_sq);
        let f_e_x_sq = coeffs[0]
            .add(coeffs[2].mul(x_sq))
            .add(coeffs[4].mul(x_4));
        let f_o_x_sq = coeffs[1]
            .add(coeffs[3].mul(x_sq))
            .add(coeffs[5].mul(x_4));
        let expected = f_e_x_sq.add(beta.mul(f_o_x_sq));

        let f_x = eval_poly(&coeffs, x);
        let f_neg_x = eval_poly(&coeffs, x.neg());
        let got = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn fold_rejects_zero_x() {
        let r = compute_next_layer_value(
            Goldilocks::zero(),
            Goldilocks::zero(),
            Goldilocks::one(),
            Goldilocks::zero(),
        );
        assert!(matches!(r, Err(OnChainError::InternalInvariantViolation)));
    }

    #[test]
    fn fold_constant_polynomial_is_invariant() {
        // p(t) = c (constant). f_x = f_neg_x = c.
        // Even part: (c + c)/2 = c. Odd part: 0/(2x) = 0.
        // Fold = c + β·0 = c.
        for c_val in [1u64, 42, 1_000_000] {
            for beta_val in [2u64, 99] {
                for x_val in [3u64, 77] {
                    let c = Goldilocks::new(c_val);
                    let got = compute_next_layer_value(
                        c,
                        c,
                        Goldilocks::new(beta_val),
                        Goldilocks::new(x_val),
                    )
                    .unwrap();
                    assert_eq!(got, c, "c={c_val}, β={beta_val}, x={x_val}");
                }
            }
        }
    }

    // ---- fold_relation_holds ----

    #[test]
    fn relation_holds_on_valid_fold() {
        // Construct valid (f_x, f_neg_x, β, x), compute fold, send as f_next.
        let x = Goldilocks::new(13);
        let beta = Goldilocks::new(7);
        let coeffs = [
            Goldilocks::new(100),
            Goldilocks::new(200),
            Goldilocks::new(300),
            Goldilocks::new(400),
        ];
        let f_x = eval_poly(&coeffs, x);
        let f_neg_x = eval_poly(&coeffs, x.neg());
        let f_next = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();

        assert_eq!(
            fold_relation_holds(f_x, f_neg_x, f_next, beta, x).unwrap(),
            true,
        );
    }

    #[test]
    fn relation_fails_on_tampered_f_next() {
        let x = Goldilocks::new(13);
        let beta = Goldilocks::new(7);
        let f_x = Goldilocks::new(100);
        let f_neg_x = Goldilocks::new(50);
        let real_next = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();
        let tampered = real_next.add(Goldilocks::one());

        assert_eq!(
            fold_relation_holds(f_x, f_neg_x, tampered, beta, x).unwrap(),
            false,
        );
    }

    #[test]
    fn relation_fails_on_wrong_beta() {
        let x = Goldilocks::new(13);
        let beta = Goldilocks::new(7);
        let wrong_beta = Goldilocks::new(8);
        let f_x = Goldilocks::new(100);
        let f_neg_x = Goldilocks::new(50);
        let f_next = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();

        assert_eq!(
            fold_relation_holds(f_x, f_neg_x, f_next, wrong_beta, x).unwrap(),
            false,
        );
    }

    #[test]
    fn relation_fails_on_swapped_f_x_f_neg_x() {
        // Swapping f(x) and f(-x) changes the odd-part sign: fold
        // becomes f_e − β·f_o instead of f_e + β·f_o, so the
        // relation fails unless f_o happens to be zero.
        let x = Goldilocks::new(13);
        let beta = Goldilocks::new(7);
        let coeffs = [
            Goldilocks::new(100),
            Goldilocks::new(200), // non-zero odd coefficient
        ];
        let f_x = eval_poly(&coeffs, x);
        let f_neg_x = eval_poly(&coeffs, x.neg());
        let f_next = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();

        // Swapped:
        let swap_check = fold_relation_holds(f_neg_x, f_x, f_next, beta, x).unwrap();
        assert_eq!(swap_check, false, "swapping f(x)/f(-x) should fail the relation");
    }

    #[test]
    fn relation_holds_across_many_random_inputs() {
        // Spot-check on a variety of polynomial shapes + challenge
        // points — all should produce consistent folds.
        let cases: &[(&[Goldilocks], u64, u64)] = &[
            (&[Goldilocks::new(1), Goldilocks::new(2)], 5, 3),
            (
                &[
                    Goldilocks::new(10),
                    Goldilocks::new(20),
                    Goldilocks::new(30),
                ],
                17,
                41,
            ),
            (
                &[
                    Goldilocks::new(1),
                    Goldilocks::new(0),
                    Goldilocks::new(1),
                    Goldilocks::new(0),
                    Goldilocks::new(1),
                ],
                100,
                200,
            ),
        ];
        for (coeffs, x_val, beta_val) in cases {
            let x = Goldilocks::new(*x_val);
            let beta = Goldilocks::new(*beta_val);
            let f_x = eval_poly(coeffs, x);
            let f_neg_x = eval_poly(coeffs, x.neg());
            let f_next = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();
            assert!(
                fold_relation_holds(f_x, f_neg_x, f_next, beta, x).unwrap(),
                "fold should hold for x={x_val}, β={beta_val}",
            );
        }
    }
}
