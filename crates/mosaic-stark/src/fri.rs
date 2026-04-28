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
//! - [`verify_fold_chain`] — multi-layer fold-chain walk; returns
//!   the final-layer `(x, claimed value)` pair without doing the
//!   final-poly cross-check.
//! - [`verify_fri_query`] — **session 90** high-level audit gate
//!   that runs the fold chain AND the final-poly cross-check + the
//!   `VerificationFailed` rejection in one named call. Mirrors the
//!   session-86 [`mosaic_nova::verify_folding_consistency`] pattern.
//!
//! Session 12 wires `verify_fold_chain` into the verifier pipeline.
//! Session 90 collapses the verifier's per-query inline pattern into
//! the new `verify_fri_query` gate.

use crate::goldilocks::{eval_poly_le_bytes, Goldilocks};
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

/// Walk an entire per-query FRI fold chain, applying the fold relation
/// layer by layer.
///
/// The verifier uses this primitive per query: starting from the
/// query's evaluations at layer 0, it validates that every
/// intermediate fold matches the claimed next-layer opening, and
/// returns the final layer's claimed scalar.
///
/// ## Parameters
///
/// - `layer_evals[i]` = `(f_i(x_i), f_i(−x_i))` — the query's two
///   openings at FRI layer `i`. The sibling opening `f_i(−x_i)` comes
///   from the "folded sibling" Merkle leaf in the same layer.
/// - `betas[i]` — fold challenge squeezed from the transcript after
///   absorbing layer `i`'s Merkle root.
/// - `initial_x` — the query's x-value at layer 0 (domain-generator
///   power indexed by the query). Each subsequent layer uses `x²`
///   from the prior layer.
///
/// `layer_evals.len()` must equal `betas.len()`; both equal
/// `num_fri_layers`. A chain with zero layers returns immediately —
/// no fold is expected — which is why the return type is `Option`:
/// the caller discriminates "no fold done" from "chain is one
/// element long".
///
/// Returns the final-layer scalar `f_{n}(initial_x^(2^n))` alongside
/// the `x` value at that depth. The outer verifier compares the
/// scalar to the claim carried by `fri_final_poly` (or recomputes
/// from the committed final polynomial — Phase-3 scaffold just
/// checks structural consistency).
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if `layer_evals.len() !=
///   betas.len()`.
/// - [`OnChainError::InternalInvariantViolation`] for any arithmetic
///   failure inside a layer (e.g., `x` doubles to zero — which can't
///   happen in Goldilocks for a starting `x` in a valid subgroup but
///   is guarded explicitly).
pub fn verify_fold_chain(
    layer_evals: &[(Goldilocks, Goldilocks)],
    betas: &[Goldilocks],
    initial_x: Goldilocks,
) -> Result<(Goldilocks, Goldilocks), OnChainError> {
    if layer_evals.len() != betas.len() {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let mut x = initial_x;
    // `prev_value` holds the layer's own `f_x` reading; after folding,
    // it becomes the claimed next-layer `f_next`. For the first layer
    // we don't yet have "prev" — we seed the loop with the opening
    // from layer 0 directly.
    let mut prev_value = if let Some((f_x, _)) = layer_evals.first() {
        *f_x
    } else {
        // Zero-layer chain: no fold done, the "final" is whatever
        // the caller provides as x and value — in practice this is
        // a no-op path. Return the initial x and zero.
        return Ok((x, Goldilocks::zero()));
    };

    for (i, (&(f_x, f_neg_x), &beta)) in layer_evals.iter().zip(betas.iter()).enumerate() {
        // Sanity: f_x at layer i must match prev_value from layer i-1's
        // fold (for i > 0) or the seed (for i == 0). This cross-check
        // catches mis-assembly of the proof — the prover must commit
        // consistent `f_x` values across layers.
        if i > 0 && prev_value != f_x {
            return Err(OnChainError::VerificationFailed);
        }
        // Compute the fold: this becomes the claimed next-layer f_x.
        prev_value = compute_next_layer_value(f_x, f_neg_x, beta, x)?;
        // Next layer operates at x². The domain halves each step.
        x = x.mul(x);
    }
    Ok((x, prev_value))
}

/// **Session 90 — high-level FRI per-query soundness gate.**
///
/// Combines [`verify_fold_chain`] with the final-polynomial cross-
/// check that closes the per-query soundness story:
///
/// 1. Walk the fold chain `layer_evals → (final_x, computed_final)`.
/// 2. Evaluate the proof's `fri_final_poly` at `final_x` to get the
///    expected final-layer value.
/// 3. Reject as [`OnChainError::VerificationFailed`] if the chain's
///    `computed_final` disagrees with the expected value.
///
/// This is the audit-grade "is this query consistent end-to-end?"
/// check. Sessions ≤89 inlined the three-step pattern at every
/// per-query loop iteration; session 90 collapses it into a single
/// named primitive so an external auditor reading the verifier sees
/// `verify_fri_query(...)` instead of three lines of fold + eval +
/// compare. Mirrors the session-86 Nova pattern with
/// [`mosaic_nova::verify_folding_consistency`].
///
/// ## Inputs
///
/// - `layer_evals` and `betas` — same shape as
///   [`verify_fold_chain`]; one layer-evaluation tuple and one fold
///   challenge per FRI layer.
/// - `initial_x` — the query's domain element at layer 0 (i.e.
///   `ω^global_idx` where ω is the trace-domain generator).
/// - `fri_final_poly_le_bytes` — flat little-endian-bytes coefficient
///   vector of the proof's claimed final polynomial.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] — `layer_evals.len() !=
///   betas.len()`, or the final-poly bytes are not a multiple of 8.
/// - [`OnChainError::InternalInvariantViolation`] — fold arithmetic
///   degeneracy (e.g. `x = 0`).
/// - [`OnChainError::VerificationFailed`] — the chain's computed
///   final value disagrees with the final-poly evaluation, OR a
///   layer-to-layer `f_x` consistency check failed inside the chain
///   walk.
pub fn verify_fri_query(
    layer_evals: &[(Goldilocks, Goldilocks)],
    betas: &[Goldilocks],
    initial_x: Goldilocks,
    fri_final_poly_le_bytes: &[u8],
) -> Result<(), OnChainError> {
    let (final_x, computed_final) = verify_fold_chain(layer_evals, betas, initial_x)?;
    let expected_final = eval_poly_le_bytes(fri_final_poly_le_bytes, final_x)?;
    if computed_final != expected_final {
        return Err(OnChainError::VerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goldilocks::eval_poly_le_bytes;

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

    // ---- verify_fold_chain ----

    #[test]
    fn chain_zero_layers_returns_initial_x() {
        let x = Goldilocks::new(42);
        let (final_x, final_v) = verify_fold_chain(&[], &[], x).unwrap();
        assert_eq!(final_x, x);
        assert_eq!(final_v, Goldilocks::zero());
    }

    #[test]
    fn chain_one_layer_matches_single_fold() {
        // 1-layer chain reduces to compute_next_layer_value.
        let x = Goldilocks::new(13);
        let beta = Goldilocks::new(7);
        let f_x = Goldilocks::new(100);
        let f_neg_x = Goldilocks::new(50);

        let (final_x, final_v) =
            verify_fold_chain(&[(f_x, f_neg_x)], &[beta], x).unwrap();
        let expected_v = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();
        assert_eq!(final_v, expected_v);
        // final_x = x² after one fold step.
        assert_eq!(final_x, x.mul(x));
    }

    #[test]
    fn chain_two_layers_honest_walk() {
        // Construct a quadratic polynomial, compute its layer-0 and
        // layer-1 evaluations, then walk the chain.
        //
        // p(t) = 7 + 2t + 5t² + 3t³.
        // Layer 0 domain contains x and -x.
        // Layer 1 domain contains x².
        // f_1(t) = p_e(t) + β_0 · p_o(t) where p_e, p_o split p.
        //   p_e(X²) = 7 + 5·X², p_o(X²) = 2 + 3·X².
        //   f_1(t) = (7 + 5t) + β_0·(2 + 3t)  (substitute X²→t).
        // Fold again at (x², -x²) via β_1 gives f_2.
        let coeffs = [
            Goldilocks::new(7),
            Goldilocks::new(2),
            Goldilocks::new(5),
            Goldilocks::new(3),
        ];
        let beta_0 = Goldilocks::new(11);
        let beta_1 = Goldilocks::new(17);
        let x = Goldilocks::new(6);

        // Layer-0 openings from direct evaluation of p at x and -x.
        let f0_x = eval_poly(&coeffs, x);
        let f0_neg_x = eval_poly(&coeffs, x.neg());

        // Layer-1 values computed from the fold relation.
        let f1_x = compute_next_layer_value(f0_x, f0_neg_x, beta_0, x).unwrap();
        // For the second fold we need f_1(x²) at both +(x²) and -(x²).
        // Use symbolic f_1(t) = (7 + 5t) + β_0·(2 + 3t) = (7 + 2β_0) + (5 + 3β_0)t.
        let f1_c0 = Goldilocks::new(7).add(beta_0.mul(Goldilocks::new(2)));
        let f1_c1 = Goldilocks::new(5).add(beta_0.mul(Goldilocks::new(3)));
        let x_sq = x.mul(x);
        let f1_at_x_sq = f1_c0.add(f1_c1.mul(x_sq));
        assert_eq!(f1_x, f1_at_x_sq, "layer-1 fold should match symbolic f_1(x²)");
        let f1_neg_x_sq = f1_c0.add(f1_c1.mul(x_sq.neg()));

        let layer_evals = [(f0_x, f0_neg_x), (f1_x, f1_neg_x_sq)];
        let betas = [beta_0, beta_1];
        let (final_x, final_v) =
            verify_fold_chain(&layer_evals, &betas, x).unwrap();

        // Expected final value: f_2(x⁴) = f_1_e(x⁴) + β_1 · f_1_o(x⁴).
        // f_1_e(X²) = 7 + 2β_0 (constant),  f_1_o(X²) = 5 + 3β_0 (constant).
        let expected_final = f1_c0.add(beta_1.mul(f1_c1));
        assert_eq!(final_v, expected_final);
        // final_x doubles twice: x → x² → x⁴.
        assert_eq!(final_x, x_sq.mul(x_sq));
    }

    #[test]
    fn chain_rejects_mismatched_betas_length() {
        let x = Goldilocks::new(13);
        let layer_evals = [(Goldilocks::one(), Goldilocks::one())];
        let betas = []; // 0 vs 1 layer.
        assert!(matches!(
            verify_fold_chain(&layer_evals, &betas, x),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn chain_rejects_inconsistent_f_x_between_layers() {
        // Layer-1's f_x should equal the computed fold from layer 0.
        // Tamper by sending a different value for layer-1 f_x.
        let x = Goldilocks::new(13);
        let beta_0 = Goldilocks::new(7);
        let beta_1 = Goldilocks::new(11);

        let f0_x = Goldilocks::new(100);
        let f0_neg_x = Goldilocks::new(50);
        let real_f1_x = compute_next_layer_value(f0_x, f0_neg_x, beta_0, x).unwrap();
        let tampered_f1_x = real_f1_x.add(Goldilocks::one());

        let layer_evals = [
            (f0_x, f0_neg_x),
            (tampered_f1_x, Goldilocks::new(99)),
        ];
        let betas = [beta_0, beta_1];
        let r = verify_fold_chain(&layer_evals, &betas, x);
        assert!(
            matches!(r, Err(OnChainError::VerificationFailed)),
            "inconsistent layer-1 f_x should fail, got {r:?}",
        );
    }

    #[test]
    fn chain_constant_polynomial_fold_is_invariant() {
        // p(t) = c constant → all f_i(x) = c. Chain returns c with
        // every layer's f_x agreeing.
        let c = Goldilocks::new(42);
        let x = Goldilocks::new(5);
        let betas = [
            Goldilocks::new(1),
            Goldilocks::new(2),
            Goldilocks::new(3),
            Goldilocks::new(4),
        ];
        let layer_evals: alloc::vec::Vec<(Goldilocks, Goldilocks)> =
            core::iter::repeat((c, c)).take(betas.len()).collect();
        let (_, final_v) = verify_fold_chain(&layer_evals, &betas, x).unwrap();
        assert_eq!(final_v, c, "constant poly should fold to itself through any β chain");
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

    // ---- Property-based tests (session 36) ----
    //
    // FRI fold arithmetic pivots on the even/odd decomposition of a
    // polynomial evaluated at a pair of opposite points `(x, −x)`.
    // The invariants below verify that:
    //
    //   1. The fold is self-consistent — applying compute_next_layer_value
    //      and then checking with fold_relation_holds always agrees.
    //   2. A tampered f_next always fails (anti-property: verify that
    //      changes are detected, not swallowed).
    //   3. β = 0 collapses the fold to the even part; β = 1 to
    //      (f_even + f_odd).
    //   4. Well-formed chains validate; chain-length mismatches error
    //      cleanly.

    use proptest::prelude::*;

    fn any_goldilocks() -> impl Strategy<Value = Goldilocks> {
        (0u64..crate::goldilocks::P).prop_map(Goldilocks::new)
    }

    /// Strategy: a non-zero Goldilocks value (for x in the fold
    /// relation which needs 2x invertible).
    fn any_nonzero_goldilocks() -> impl Strategy<Value = Goldilocks> {
        any_goldilocks().prop_filter("non-zero", |x| x.as_u64() != 0)
    }

    proptest! {
        /// `compute_next_layer_value` output always passes
        /// `fold_relation_holds` — the two primitives agree on every
        /// valid input.
        #[test]
        fn prop_fold_is_self_consistent(
            f_x in any_goldilocks(),
            f_neg_x in any_goldilocks(),
            beta in any_goldilocks(),
            x in any_nonzero_goldilocks(),
        ) {
            let f_next = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();
            let ok = fold_relation_holds(f_x, f_neg_x, f_next, beta, x).unwrap();
            prop_assert!(ok);
        }

        /// Tampering f_next by adding any non-zero delta must break
        /// the fold. Guards against "fold check always returns true"
        /// bugs.
        #[test]
        fn prop_tampered_f_next_fails_fold(
            f_x in any_goldilocks(),
            f_neg_x in any_goldilocks(),
            beta in any_goldilocks(),
            x in any_nonzero_goldilocks(),
            delta in any_nonzero_goldilocks(),
        ) {
            let f_next = compute_next_layer_value(f_x, f_neg_x, beta, x).unwrap();
            let tampered = f_next.add(delta);
            let ok = fold_relation_holds(f_x, f_neg_x, tampered, beta, x).unwrap();
            prop_assert!(!ok, "tampered f_next (+{}) should break fold", delta.as_u64());
        }

        /// With β = 0, the fold is just the even part:
        ///   f_next = (f_x + f_neg_x) / 2
        /// Exercises the scaffold-useful case where the odd part
        /// vanishes.
        #[test]
        fn prop_beta_zero_yields_even_part(
            f_x in any_goldilocks(),
            f_neg_x in any_goldilocks(),
            x in any_nonzero_goldilocks(),
        ) {
            let beta_zero = Goldilocks::zero();
            let two_inv = Goldilocks::new(2).inverse().unwrap();
            let expected_even = f_x.add(f_neg_x).mul(two_inv);
            let got = compute_next_layer_value(f_x, f_neg_x, beta_zero, x).unwrap();
            prop_assert_eq!(got, expected_even);
        }

        /// x = 0 must produce an error (denominator vanishes).
        /// Guards against silent division-by-zero.
        #[test]
        fn prop_x_zero_is_rejected(
            f_x in any_goldilocks(),
            f_neg_x in any_goldilocks(),
            beta in any_goldilocks(),
        ) {
            let r = compute_next_layer_value(f_x, f_neg_x, beta, Goldilocks::zero());
            prop_assert!(r.is_err());
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 90 — verify_fri_query audit-gate coverage.
    // ───────────────────────────────────────────────────────────────────

    /// Helper: encode a Goldilocks coefficient vector to the
    /// little-endian bytes layout `eval_poly_le_bytes` expects.
    fn coeffs_to_le_bytes(coeffs: &[Goldilocks]) -> alloc::vec::Vec<u8> {
        let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(coeffs.len() * 8);
        for c in coeffs {
            out.extend_from_slice(&c.to_bytes_le());
        }
        out
    }

    /// Honest tuple → audit gate accepts.
    ///
    /// Build a 2-layer fold chain from a degree-3 polynomial, then
    /// construct the matching final-poly bytes by encoding `f_2`'s
    /// constant coefficient (which IS the final value because the
    /// quadratic input collapses to a single Goldilocks scalar after
    /// the second fold). Audit gate must accept.
    #[test]
    fn verify_fri_query_accepts_honest_tuple() {
        let coeffs = [
            Goldilocks::new(7),
            Goldilocks::new(2),
            Goldilocks::new(5),
            Goldilocks::new(3),
        ];
        let beta_0 = Goldilocks::new(11);
        let beta_1 = Goldilocks::new(17);
        let x = Goldilocks::new(6);

        let f0_x = eval_poly(&coeffs, x);
        let f0_neg_x = eval_poly(&coeffs, x.neg());
        let f1_x = compute_next_layer_value(f0_x, f0_neg_x, beta_0, x).unwrap();
        let f1_c0 = Goldilocks::new(7).add(beta_0.mul(Goldilocks::new(2)));
        let f1_c1 = Goldilocks::new(5).add(beta_0.mul(Goldilocks::new(3)));
        let x_sq = x.mul(x);
        let f1_neg_x_sq = f1_c0.add(f1_c1.mul(x_sq.neg()));

        // Final polynomial f_2(t) = f_1_e + β_1 · f_1_o = f1_c0 + β_1·f1_c1.
        // After fold #2, f_2 is constant in the symbolic sense — encode
        // the single constant scalar.
        let f2_const = f1_c0.add(beta_1.mul(f1_c1));
        let final_poly_bytes = coeffs_to_le_bytes(&[f2_const]);

        let layer_evals = [(f0_x, f0_neg_x), (f1_x, f1_neg_x_sq)];
        let betas = [beta_0, beta_1];
        verify_fri_query(&layer_evals, &betas, x, &final_poly_bytes)
            .expect("honest tuple must accept");
    }

    /// Tampered final-poly constant → audit gate rejects with
    /// `VerificationFailed`. The fold chain itself is consistent;
    /// only the final polynomial is wrong.
    #[test]
    fn verify_fri_query_rejects_tampered_final_poly() {
        let coeffs = [
            Goldilocks::new(7),
            Goldilocks::new(2),
            Goldilocks::new(5),
            Goldilocks::new(3),
        ];
        let beta_0 = Goldilocks::new(11);
        let beta_1 = Goldilocks::new(17);
        let x = Goldilocks::new(6);

        let f0_x = eval_poly(&coeffs, x);
        let f0_neg_x = eval_poly(&coeffs, x.neg());
        let f1_x = compute_next_layer_value(f0_x, f0_neg_x, beta_0, x).unwrap();
        let f1_c0 = Goldilocks::new(7).add(beta_0.mul(Goldilocks::new(2)));
        let f1_c1 = Goldilocks::new(5).add(beta_0.mul(Goldilocks::new(3)));
        let x_sq = x.mul(x);
        let f1_neg_x_sq = f1_c0.add(f1_c1.mul(x_sq.neg()));
        let f2_const = f1_c0.add(beta_1.mul(f1_c1));

        // Tamper: bump the final-poly constant by 1.
        let bad_final = f2_const.add(Goldilocks::one());
        let bad_bytes = coeffs_to_le_bytes(&[bad_final]);

        let layer_evals = [(f0_x, f0_neg_x), (f1_x, f1_neg_x_sq)];
        let betas = [beta_0, beta_1];
        let res = verify_fri_query(&layer_evals, &betas, x, &bad_bytes);
        assert!(
            matches!(res, Err(OnChainError::VerificationFailed)),
            "tampered final poly must reject as VerificationFailed; got {res:?}",
        );
    }

    /// Tampered layer evaluation → cascades into wrong computed final
    /// → mismatch with honest final-poly → `VerificationFailed`.
    /// Demonstrates the gate's "any inconsistency is fatal" contract.
    #[test]
    fn verify_fri_query_rejects_tampered_layer_eval() {
        let coeffs = [
            Goldilocks::new(7),
            Goldilocks::new(2),
            Goldilocks::new(5),
            Goldilocks::new(3),
        ];
        let beta_0 = Goldilocks::new(11);
        let beta_1 = Goldilocks::new(17);
        let x = Goldilocks::new(6);

        let f0_x = eval_poly(&coeffs, x);
        let f0_neg_x = eval_poly(&coeffs, x.neg());
        let f1_x = compute_next_layer_value(f0_x, f0_neg_x, beta_0, x).unwrap();
        let f1_c0 = Goldilocks::new(7).add(beta_0.mul(Goldilocks::new(2)));
        let f1_c1 = Goldilocks::new(5).add(beta_0.mul(Goldilocks::new(3)));
        let x_sq = x.mul(x);
        let f1_neg_x_sq = f1_c0.add(f1_c1.mul(x_sq.neg()));
        let f2_const = f1_c0.add(beta_1.mul(f1_c1));
        let final_poly_bytes = coeffs_to_le_bytes(&[f2_const]);

        // Tamper the layer-1 sibling opening — `f1_neg_x_sq` becomes
        // `f1_neg_x_sq + 1`, breaking the layer-2 fold consistency.
        let bad_layer_evals = [
            (f0_x, f0_neg_x),
            (f1_x, f1_neg_x_sq.add(Goldilocks::one())),
        ];
        let betas = [beta_0, beta_1];
        let res = verify_fri_query(&bad_layer_evals, &betas, x, &final_poly_bytes);
        assert!(
            matches!(res, Err(OnChainError::VerificationFailed)),
            "tampered layer eval must reject as VerificationFailed; got {res:?}",
        );
    }

    /// Length mismatch propagates from `verify_fold_chain` →
    /// `ProofLengthMismatch` (NOT `VerificationFailed`). The gate
    /// uses `?` propagation so the underlying error type surfaces
    /// correctly.
    #[test]
    fn verify_fri_query_propagates_length_mismatch() {
        let layer_evals = [(Goldilocks::one(), Goldilocks::one())];
        let betas: [Goldilocks; 0] = [];
        let final_poly_bytes = coeffs_to_le_bytes(&[Goldilocks::zero()]);
        let res =
            verify_fri_query(&layer_evals, &betas, Goldilocks::new(13), &final_poly_bytes);
        assert!(
            matches!(res, Err(OnChainError::ProofLengthMismatch)),
            "len mismatch must propagate, not collapse to VerificationFailed; got {res:?}",
        );
    }

    /// Zero-layer chain returns `Ok(())` iff the final-poly evaluates
    /// to the chain's seed final value (Goldilocks zero by the
    /// `verify_fold_chain` zero-layer convention). Pin this corner
    /// explicitly so a future change to the zero-layer semantics
    /// surfaces as a test failure.
    #[test]
    fn verify_fri_query_zero_layer_chain_corner() {
        let layer_evals: [(Goldilocks, Goldilocks); 0] = [];
        let betas: [Goldilocks; 0] = [];
        let final_poly_bytes = coeffs_to_le_bytes(&[Goldilocks::zero()]);
        verify_fri_query(&layer_evals, &betas, Goldilocks::new(7), &final_poly_bytes)
            .expect("zero-layer + zero final poly must accept");

        // A non-zero final poly value mismatches the chain's zero seed
        // → reject.
        let bad_final = coeffs_to_le_bytes(&[Goldilocks::one()]);
        let res =
            verify_fri_query(&layer_evals, &betas, Goldilocks::new(7), &bad_final);
        assert!(
            matches!(res, Err(OnChainError::VerificationFailed)),
            "zero-layer + non-zero final poly must reject; got {res:?}",
        );
    }

    proptest! {
        /// Audit-gate equivalence pin: for every honest 1-layer fold
        /// over random (x, β, polynomial coefficients), the gate
        /// accepts. The final polynomial encoding is derived from
        /// the symbolic post-fold polynomial.
        ///
        /// Constructs `p(t) = c_0 + c_1·t`, computes the layer-0
        /// evals `(f_x, f_neg_x)`, folds at β to get `f_1(x²) = c_0 +
        /// β·c_1`, encodes the symbolic constant as the final poly,
        /// and asserts the gate accepts.
        #[test]
        fn prop_verify_fri_query_accepts_honest_1_layer_fold(
            c0_seed in any::<u32>(),
            c1_seed in any::<u32>(),
            beta_seed in 1u32..=u32::MAX,
            x_seed in 2u32..=u32::MAX, // skip x=0 boundary
        ) {
            let c0 = Goldilocks::new(c0_seed as u64);
            let c1 = Goldilocks::new(c1_seed as u64);
            let beta = Goldilocks::new(beta_seed as u64);
            let x = Goldilocks::new(x_seed as u64);
            let f_x = c0.add(c1.mul(x));
            let f_neg_x = c0.add(c1.mul(x.neg()));

            // f_1(t) = c_0 + β·c_1 (constant after one fold).
            let f1_const = c0.add(beta.mul(c1));
            let final_poly_bytes = coeffs_to_le_bytes(&[f1_const]);

            let res = verify_fri_query(
                &[(f_x, f_neg_x)],
                &[beta],
                x,
                &final_poly_bytes,
            );
            prop_assert!(
                res.is_ok(),
                "honest 1-layer fold must accept at (c0={:?}, c1={:?}, β={:?}, x={:?}); got {:?}",
                c0_seed, c1_seed, beta_seed, x_seed, res
            );
        }
    }
}
