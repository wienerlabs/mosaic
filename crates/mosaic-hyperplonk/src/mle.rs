//! Multilinear extension (MLE) helpers.
//!
//! A multilinear polynomial `f : F^n → F` over `n` variables has `2^n`
//! boolean-cube evaluations — one per point in `{0,1}^n` — and is the
//! unique multilinear interpolation of those evaluations. `HyperPlonk`
//! represents *all* committed polynomials (witness wires, selectors,
//! permutation grand-product) as MLEs over the boolean hypercube.
//!
//! ## What we need on-chain
//!
//! The outer verifier's per-proof work touches MLEs in two ways:
//!
//! 1. **`eq_poly_eval`** — for two point vectors `a, b ∈ F^n`,
//!    compute `eq(a, b) = Π_i ((1 - a_i)(1 - b_i) + a_i·b_i)`. This is
//!    the boolean-hypercube analog of a Lagrange basis evaluation and
//!    the only MLE op that runs in the on-chain hot path.
//! 2. The committed-poly evaluations at the sumcheck challenge point
//!    are sent as part of the proof (`final_evals` in the canonical
//!    layout), so the verifier never reconstructs them from `2^n`
//!    cube values.
//!
//! ## What we need off-chain
//!
//! Host-side tests and differential oracles benefit from
//! **`mle_eval_from_cube`** — given `2^n` boolean-cube evaluations,
//! compute `f(point)` by iterated folding. This is the standard way
//! to validate prover-sent evaluations in fixture construction.
//!
//! Both live here; `eq_poly_eval` is stack-only and `#[inline(never)]`-
//! ready for SBF, while `mle_eval_from_cube` heap-allocates and is
//! flagged as a host helper in its rustdoc.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::One;
use mosaic_core::OnChainError;

/// Evaluate the equality polynomial `eq(a, b)` for two point vectors
/// of the same length `n`:
///
/// ```text
/// eq(a, b) = Π_{i=0}^{n-1} ((1 - a_i)(1 - b_i) + a_i · b_i)
/// ```
///
/// Properties:
/// - `eq(x, y) = 1` if `x == y` on the boolean cube `{0, 1}^n`.
/// - `eq(x, y) = 0` if `x ≠ y` on the boolean cube.
/// - On general `F^n × F^n` it interpolates linearly between cube
///   corners — the unique multilinear function matching the above.
///
/// On-chain cost: `n` Fr multiplications + `n` Fr subtractions — no
/// allocations, works entirely on the stack.
///
/// ## Errors
///
/// Returns [`OnChainError::InternalInvariantViolation`] if the two
/// vectors have different lengths.
pub fn eq_poly_eval(a: &[Fr], b: &[Fr]) -> Result<Fr, OnChainError> {
    if a.len() != b.len() {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut acc = Fr::one();
    for (ai, bi) in a.iter().zip(b.iter()) {
        // (1 - a)(1 - b) + a·b. Expand to reduce multiplications:
        // = 1 - a - b + a·b + a·b = 1 - a - b + 2·a·b
        let ab = *ai * bi;
        let term = Fr::one() - ai - bi + ab + ab;
        acc *= term;
    }
    Ok(acc)
}

/// **Host-side helper.** Evaluate a multilinear polynomial at a point
/// given its `2^n` boolean-cube values.
///
/// The `values` slice must have length exactly `2^point.len()`, indexed
/// in little-endian order of the boolean-cube coordinates (index `i`
/// represents the point whose coordinate `k` is bit `k` of `i`).
///
/// Algorithm: iterated halving. At step `k`, pair consecutive values
/// `(v[2i], v[2i+1])` — these represent `f(0, x_1, ...)` and
/// `f(1, x_1, ...)` with variable 0 fixed — and collapse via linear
/// interpolation to `v[i] := v[2i]·(1 - y_0) + v[2i+1]·y_0`. After
/// `n` rounds, one value remains.
///
/// This function allocates `2^n` Fr values on the heap — **not**
/// suitable for SBF. Use only in host tests / oracles / fixture
/// generation.
///
/// ## Errors
///
/// - [`OnChainError::InternalInvariantViolation`] if the input
///   lengths do not satisfy `values.len() == 2^point.len()`.
pub fn mle_eval_from_cube(values: &[Fr], point: &[Fr]) -> Result<Fr, OnChainError> {
    let n = point.len();
    let expected = 1_usize
        .checked_shl(n as u32)
        .ok_or(OnChainError::InternalInvariantViolation)?;
    if values.len() != expected {
        return Err(OnChainError::InternalInvariantViolation);
    }

    if n == 0 {
        // Zero-variable MLE is just the constant.
        return Ok(values[0]);
    }

    let mut buf: Vec<Fr> = values.to_vec();
    for y_k in point {
        let one_minus_y = Fr::one() - y_k;
        let half = buf.len() / 2;
        for i in 0..half {
            let v0 = buf[2 * i];
            let v1 = buf[2 * i + 1];
            buf[i] = v0 * one_minus_y + v1 * y_k;
        }
        buf.truncate(half);
    }
    debug_assert_eq!(buf.len(), 1);
    Ok(buf[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    // ---- eq_poly_eval tests ----

    #[test]
    fn eq_poly_eval_on_boolean_cube_matches_kronecker_delta() {
        // For any n, eq(x, y) = 1 iff x == y on {0,1}^n, else 0.
        for n in 1..=4 {
            for i in 0..(1u64 << n) {
                for j in 0..(1u64 << n) {
                    let x: Vec<Fr> = (0..n)
                        .map(|k| {
                            if (i >> k) & 1 == 1 {
                                Fr::one()
                            } else {
                                Fr::zero()
                            }
                        })
                        .collect();
                    let y: Vec<Fr> = (0..n)
                        .map(|k| {
                            if (j >> k) & 1 == 1 {
                                Fr::one()
                            } else {
                                Fr::zero()
                            }
                        })
                        .collect();
                    let got = eq_poly_eval(&x, &y).unwrap();
                    if i == j {
                        assert_eq!(got, Fr::one(), "eq({x:?},{y:?}) should be 1");
                    } else {
                        assert_eq!(got, Fr::zero(), "eq({x:?},{y:?}) should be 0");
                    }
                }
            }
        }
    }

    #[test]
    fn eq_poly_eval_is_symmetric() {
        let mut r = rng(1);
        for _ in 0..10 {
            let a: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut r)).collect();
            let b: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut r)).collect();
            assert_eq!(eq_poly_eval(&a, &b).unwrap(), eq_poly_eval(&b, &a).unwrap());
        }
    }

    #[test]
    fn eq_poly_eval_matches_manual_product_formula() {
        let mut r = rng(2);
        for n in [1, 3, 6, 10] {
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut r)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut r)).collect();
            // Reference: Π (1-a_i)(1-b_i) + a_i·b_i
            let mut expected = Fr::one();
            for (ai, bi) in a.iter().zip(b.iter()) {
                expected *= (Fr::one() - ai) * (Fr::one() - bi) + *ai * *bi;
            }
            assert_eq!(eq_poly_eval(&a, &b).unwrap(), expected);
        }
    }

    #[test]
    fn eq_poly_eval_rejects_length_mismatch() {
        let a = [Fr::one(); 3];
        let b = [Fr::one(); 4];
        assert!(matches!(
            eq_poly_eval(&a, &b),
            Err(OnChainError::InternalInvariantViolation),
        ));
    }

    #[test]
    fn eq_poly_eval_empty_is_one() {
        // The empty product is 1 — the zero-variable MLE over `{0,1}^0 = {()}`.
        assert_eq!(eq_poly_eval(&[], &[]).unwrap(), Fr::one());
    }

    // ---- mle_eval_from_cube tests ----

    #[test]
    fn mle_eval_on_cube_recovers_cube_value() {
        // An MLE evaluated at a boolean cube point must return that
        // cube's value directly.
        let mut r = rng(10);
        for n in 1..=4 {
            let size = 1usize << n;
            let values: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut r)).collect();
            for i in 0..size {
                let point: Vec<Fr> = (0..n)
                    .map(|k| {
                        if (i >> k) & 1 == 1 {
                            Fr::one()
                        } else {
                            Fr::zero()
                        }
                    })
                    .collect();
                let got = mle_eval_from_cube(&values, &point).unwrap();
                assert_eq!(got, values[i], "cube point {i} should recover values[{i}]");
            }
        }
    }

    #[test]
    fn mle_eval_matches_kronecker_expansion() {
        // MLE(y) = Σ_{x ∈ cube} f(x) · eq(x, y).
        // Check this identity for random y off the cube.
        let mut r = rng(11);
        for n in 1..=4 {
            let size = 1usize << n;
            let values: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut r)).collect();
            let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut r)).collect();

            let got = mle_eval_from_cube(&values, &y).unwrap();

            // Reference: summation form.
            let mut expected = Fr::zero();
            for (i, fx) in values.iter().enumerate() {
                let x_point: Vec<Fr> = (0..n)
                    .map(|k| {
                        if (i >> k) & 1 == 1 {
                            Fr::one()
                        } else {
                            Fr::zero()
                        }
                    })
                    .collect();
                expected += *fx * eq_poly_eval(&x_point, &y).unwrap();
            }

            assert_eq!(got, expected, "n={n}");
        }
    }

    #[test]
    fn mle_eval_zero_variables_returns_constant() {
        let values = [Fr::from(42u64)];
        let point: [Fr; 0] = [];
        assert_eq!(
            mle_eval_from_cube(&values, &point).unwrap(),
            Fr::from(42u64)
        );
    }

    #[test]
    fn mle_eval_rejects_length_mismatch() {
        // 3 values, 2-variable point — expected 4 values.
        let values = [Fr::one(); 3];
        let point = [Fr::one(); 2];
        assert!(matches!(
            mle_eval_from_cube(&values, &point),
            Err(OnChainError::InternalInvariantViolation),
        ));
    }

    /// Small hand-computed MLE: for n=2 with cube values
    /// `[f(0,0), f(1,0), f(0,1), f(1,1)] = [1, 2, 3, 4]`, the MLE is
    ///
    /// ```text
    /// f(y_0, y_1) = 1·(1-y_0)(1-y_1) + 2·y_0·(1-y_1) + 3·(1-y_0)·y_1 + 4·y_0·y_1
    /// ```
    ///
    /// At `(y_0, y_1) = (1/2, 1/2)` the result is `(1+2+3+4)/4 = 10/4 = 5/2`.
    #[test]
    fn mle_eval_hand_computed_n2() {
        use ark_ff::Field;
        let values = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let half = Fr::from(2u64).inverse().unwrap();
        let point = [half, half];
        let got = mle_eval_from_cube(&values, &point).unwrap();
        let expected = Fr::from(10u64) * Fr::from(4u64).inverse().unwrap();
        assert_eq!(got, expected);
    }
}
