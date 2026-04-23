//! Gate constraint expression evaluation.
//!
//! `HyperPlonk` represents the circuit's gate as a multilinear polynomial
//! over the boolean hypercube. At a sumcheck challenge point
//! `ξ = (ξ_0, ..., ξ_{n-1})`, the verifier needs to evaluate the gate
//! expression using the MLE evaluations of:
//!
//! - **Witness wires** `a, b, c` — prover-sent via `final_evals` in the
//!   canonical proof layout.
//! - **Selector polynomials** `q_M, q_L, q_R, q_O, q_C` — committed in
//!   the VK as MLEs, their evaluations at `ξ` travel alongside the
//!   witness evals and are opened via KZG.
//!
//! The gate expression we target is the **PLONK-style arithmetic gate**:
//!
//! ```text
//! g(ξ) = q_M(ξ)·a(ξ)·b(ξ)
//!      + q_L(ξ)·a(ξ)
//!      + q_R(ξ)·b(ξ)
//!      + q_O(ξ)·c(ξ)
//!      + q_C(ξ)
//! ```
//!
//! This is the same gate family Espresso's `HyperPlonk` reference impl
//! uses. Custom gates beyond this shape (e.g. for RISC-V instruction
//! encoding) would extend the evaluator with additional selector
//! terms, without changing the basic structure.
//!
//! ## Role in the outer verifier
//!
//! After `verify_sumcheck` returns `(final_claim, challenges)`, the
//! outer verifier checks:
//!
//! ```text
//! final_claim  ?=  α · gate_expr(ξ) + permutation_expr(ξ, β, γ)
//! ```
//!
//! where `α, β, γ` are Fiat-Shamir challenges combining the gate and
//! permutation terms into a single sumcheck. This module ships
//! `gate_expr`; the permutation side is a separate helper
//! (session 3c).

use ark_bn254::Fr;
use mosaic_core::OnChainError;

/// Wire values at a sumcheck challenge point.
///
/// These are the MLE evaluations `a(ξ), b(ξ), c(ξ)` that the prover
/// sends via the proof's `final_evals` bundle. The verifier subsequently
/// opens these against the committed witness polys via KZG to ensure
/// they match.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WireEvals {
    /// `a(ξ)` — left-wire witness evaluation.
    pub a: Fr,
    /// `b(ξ)` — right-wire witness evaluation.
    pub b: Fr,
    /// `c(ξ)` — output-wire witness evaluation.
    pub c: Fr,
}

/// Selector polynomial values at a sumcheck challenge point.
///
/// These evaluations come from two sources:
/// - The VK commits to each selector MLE (`Q_M, Q_L, Q_R, Q_O, Q_C`).
/// - The prover sends the claimed evaluations at `ξ`, which the
///   verifier opens against the committed polys via KZG.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SelectorEvals {
    /// `q_M(ξ)` — multiplication selector.
    pub q_m: Fr,
    /// `q_L(ξ)` — left-wire linear selector.
    pub q_l: Fr,
    /// `q_R(ξ)` — right-wire linear selector.
    pub q_r: Fr,
    /// `q_O(ξ)` — output-wire linear selector.
    pub q_o: Fr,
    /// `q_C(ξ)` — constant selector.
    pub q_c: Fr,
}

/// Evaluate the PLONK-style gate expression at the sumcheck point.
///
/// ```text
/// g(ξ) = q_M·a·b + q_L·a + q_R·b + q_O·c + q_C
/// ```
///
/// Zero-allocation; 2 Fr multiplications for the product term + 3 for
/// the linear terms + 4 additions. A well-behaved prover produces a
/// proof where this value equals zero on every point of the boolean
/// cube where the circuit's gate is active.
#[must_use]
pub fn gate_expr(wires: &WireEvals, selectors: &SelectorEvals) -> Fr {
    let prod = selectors.q_m * wires.a * wires.b;
    let lin_a = selectors.q_l * wires.a;
    let lin_b = selectors.q_r * wires.b;
    let lin_c = selectors.q_o * wires.c;
    prod + lin_a + lin_b + lin_c + selectors.q_c
}

/// Decode wire evaluations from the prover's `final_evals` bundle.
///
/// The bundle layout we target (pinning in session 3c's canonical
/// revision): `a_eval ‖ b_eval ‖ c_eval ‖ z_eval` as 4 × 32-byte BE Fr.
///
/// This helper reads the first three Fr values (a, b, c).
///
/// ## Errors
///
/// Returns [`OnChainError::ProofLengthMismatch`] if `bytes.len()` is
/// below `3 × 32 = 96`, or [`OnChainError::PublicInputOutOfRange`] if
/// any Fr value is not reduced modulo the BN254 scalar order.
pub fn decode_wire_evals(bytes: &[u8]) -> Result<WireEvals, OnChainError> {
    use mosaic_zk_primitives::field::fr_from_canonical_bytes;
    if bytes.len() < 3 * 32 {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let a = fr_from_canonical_bytes(&bytes[0..32])?;
    let b = fr_from_canonical_bytes(&bytes[32..64])?;
    let c = fr_from_canonical_bytes(&bytes[64..96])?;
    Ok(WireEvals { a, b, c })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    #[test]
    fn gate_expr_matches_manual_formula() {
        let mut r = rng(1);
        for _ in 0..10 {
            let wires = WireEvals {
                a: Fr::rand(&mut r),
                b: Fr::rand(&mut r),
                c: Fr::rand(&mut r),
            };
            let selectors = SelectorEvals {
                q_m: Fr::rand(&mut r),
                q_l: Fr::rand(&mut r),
                q_r: Fr::rand(&mut r),
                q_o: Fr::rand(&mut r),
                q_c: Fr::rand(&mut r),
            };
            let got = gate_expr(&wires, &selectors);
            let expected = selectors.q_m * wires.a * wires.b
                + selectors.q_l * wires.a
                + selectors.q_r * wires.b
                + selectors.q_o * wires.c
                + selectors.q_c;
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn gate_expr_all_zero_selectors_is_zero() {
        let wires = WireEvals {
            a: Fr::from(42u64),
            b: Fr::from(100u64),
            c: Fr::from(7u64),
        };
        let selectors = SelectorEvals {
            q_m: Fr::zero(),
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_o: Fr::zero(),
            q_c: Fr::zero(),
        };
        assert_eq!(gate_expr(&wires, &selectors), Fr::zero());
    }

    /// Multiplication-gate satisfaction: `q_M·a·b + q_O·c = 0`.
    ///
    /// With `q_M = 1, q_O = -1, q_L = q_R = q_C = 0` this encodes
    /// "c = a·b", i.e., a multiplication gate. At any satisfying
    /// assignment `(a, b, c = a·b)` the gate expression is zero.
    #[test]
    fn gate_expr_multiplication_gate_zero_on_valid_assignment() {
        use ark_ff::One;
        let a = Fr::from(7u64);
        let b = Fr::from(9u64);
        let c = a * b; // 63
        let wires = WireEvals { a, b, c };
        let selectors = SelectorEvals {
            q_m: Fr::one(),
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
        };
        // q_M·a·b + q_O·c = 1·a·b + (-1)·c = a·b - c = 0 (since c = a·b).
        assert_eq!(gate_expr(&wires, &selectors), Fr::zero());
    }

    /// Addition gate: `q_L = 1, q_R = 1, q_O = -1, q_M = q_C = 0`
    /// encodes "c = a + b". Valid assignment gives zero.
    #[test]
    fn gate_expr_addition_gate_zero_on_valid_assignment() {
        use ark_ff::One;
        let a = Fr::from(3u64);
        let b = Fr::from(5u64);
        let c = a + b; // 8
        let wires = WireEvals { a, b, c };
        let selectors = SelectorEvals {
            q_m: Fr::zero(),
            q_l: Fr::one(),
            q_r: Fr::one(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
        };
        assert_eq!(gate_expr(&wires, &selectors), Fr::zero());
    }

    /// Constant gate: `q_C = -k`, force `c = k`. Then
    /// `q_O = 1, q_L = q_R = q_M = 0, q_C = -k` gives
    /// `c - k = 0` when c = k.
    #[test]
    fn gate_expr_constant_gate_zero_on_valid_assignment() {
        use ark_ff::One;
        let k = Fr::from(42u64);
        let wires = WireEvals {
            a: Fr::zero(),
            b: Fr::zero(),
            c: k,
        };
        let selectors = SelectorEvals {
            q_m: Fr::zero(),
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_o: Fr::one(),
            q_c: -k,
        };
        assert_eq!(gate_expr(&wires, &selectors), Fr::zero());
    }

    /// Unsatisfied multiplication gate: wrong `c`. Result must be
    /// non-zero — this is what a sumcheck identity failure looks
    /// like cryptographically (prover lied about a wire value).
    #[test]
    fn gate_expr_multiplication_nonzero_on_invalid_c() {
        use ark_ff::One;
        let a = Fr::from(7u64);
        let b = Fr::from(9u64);
        let wrong_c = Fr::from(100u64); // actual product is 63
        let wires = WireEvals { a, b, c: wrong_c };
        let selectors = SelectorEvals {
            q_m: Fr::one(),
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
        };
        // 7·9 - 100 = -37 ≠ 0
        assert_ne!(gate_expr(&wires, &selectors), Fr::zero());
    }

    // ---- decode_wire_evals tests ----

    #[test]
    fn decode_wire_evals_roundtrip() {
        use mosaic_zk_primitives::field::fr_to_canonical_bytes;
        let a = Fr::from(111u64);
        let b = Fr::from(222u64);
        let c = Fr::from(333u64);
        let mut buf = alloc::vec::Vec::with_capacity(96);
        buf.extend_from_slice(&fr_to_canonical_bytes(&a));
        buf.extend_from_slice(&fr_to_canonical_bytes(&b));
        buf.extend_from_slice(&fr_to_canonical_bytes(&c));
        let decoded = decode_wire_evals(&buf).unwrap();
        assert_eq!(decoded, WireEvals { a, b, c });
    }

    #[test]
    fn decode_wire_evals_rejects_short_buffer() {
        let short = [0u8; 95];
        assert!(matches!(
            decode_wire_evals(&short),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn decode_wire_evals_accepts_longer_buffer() {
        // Extra bytes allowed — real buffer has z_eval + selector evals
        // trailing. This decoder just reads the first 96 bytes.
        let buf = [0u8; 128];
        let got = decode_wire_evals(&buf).unwrap();
        assert_eq!(got.a, Fr::zero());
        assert_eq!(got.b, Fr::zero());
        assert_eq!(got.c, Fr::zero());
    }
}
