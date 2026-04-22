//! Folding-scheme algebraic primitives.
//!
//! Nova's relaxed R1CS relation at a satisfying assignment is:
//!
//! ```text
//! A·z ∘ B·z  =  u · C·z + E
//! ```
//!
//! where:
//! - `z = (w, u, x)` — concatenated witness ‖ folding scalar ‖ inputs.
//! - `∘` — Hadamard (element-wise) product.
//! - `E` — folded error vector.
//! - `u` — folding scalar (= 1 for a fresh instance, accumulates over folds).
//!
//! At a random evaluation point `ξ` (Spartan wrapping), the vector
//! identity reduces to a scalar equation over the polynomial
//! evaluations:
//!
//! ```text
//! A(ξ) · B(ξ) - u · C(ξ) - E(ξ)  =  0
//! ```
//!
//! This module provides [`hadamard_residual`] which computes the LHS
//! and [`folded_commitment_from_fold`] which reconstructs a folded
//! commitment from base commitments and the cross-term via
//! `C_folded = C_1 + r · C_2 + r² · T`.

use ark_bn254::Fr;
use mosaic_core::{
    syscall::SyscallBackend,
    OnChainError,
};
use mosaic_plonk::{
    field::fr_to_canonical_bytes,
    msm::{add_g1, scalar_mul_g1},
};

/// Compute the Hadamard-residual value at the evaluation point:
///
/// ```text
/// residual(ξ)  =  A(ξ) · B(ξ)  -  u · C(ξ)  -  E(ξ)
/// ```
///
/// A valid folded instance has `residual(ξ) = 0` for a random ξ. The
/// outer verifier closes the soundness check by cross-verifying this
/// residual against a Spartan opening at ξ.
#[must_use]
pub fn hadamard_residual(
    a_eval: &Fr,
    b_eval: &Fr,
    c_eval: &Fr,
    e_eval: &Fr,
    u: &Fr,
) -> Fr {
    *a_eval * b_eval - *u * c_eval - e_eval
}

/// Reconstruct a folded G1 commitment from two base commitments and a
/// cross-term via the standard Nova accumulator update:
///
/// ```text
/// C_folded  =  C_1  +  r · C_2  +  r² · T
/// ```
///
/// `r` is the folding challenge. When the outer verifier derives `r`
/// from the transcript and receives `C_folded`, it can recompute the
/// RHS locally and check commitment equality — closing the folding
/// soundness against the committed cross-term `T`.
///
/// ## Errors
///
/// - [`OnChainError::InvalidPointEncoding`] if any input G1 slice is
///   not exactly 64 bytes.
/// - Syscall errors from MSM.
pub fn folded_commitment_from_fold<B: SyscallBackend + ?Sized>(
    backend: &B,
    c1: &[u8],
    c2: &[u8],
    t: &[u8],
    r: &Fr,
) -> Result<[u8; 64], OnChainError> {
    if c1.len() != 64 || c2.len() != 64 || t.len() != 64 {
        return Err(OnChainError::InvalidPointEncoding);
    }

    // r · C_2.
    let r_bytes = fr_to_canonical_bytes(r);
    let mut c2_arr = [0u8; 64];
    c2_arr.copy_from_slice(c2);
    let r_c2 = scalar_mul_g1(backend, &c2_arr, &r_bytes)?;

    // r² · T.
    let r_sq = *r * r;
    let r_sq_bytes = fr_to_canonical_bytes(&r_sq);
    let mut t_arr = [0u8; 64];
    t_arr.copy_from_slice(t);
    let r_sq_t = scalar_mul_g1(backend, &t_arr, &r_sq_bytes)?;

    // C_1 + r·C_2 + r²·T.
    let mut c1_arr = [0u8; 64];
    c1_arr.copy_from_slice(c1);
    let tmp = add_g1(backend, &c1_arr, &r_c2)?;
    add_g1(backend, &tmp, &r_sq_t)
}

/// Compute the folded error commitment update:
///
/// ```text
/// E_folded  =  E_1  +  r · T
/// ```
///
/// Simpler than the two-term `folded_commitment_from_fold` because
/// Nova's E vector only combines linearly with the cross-term (E has
/// no squared contribution).
///
/// ## Errors
///
/// - [`OnChainError::InvalidPointEncoding`] if any input G1 slice is
///   not exactly 64 bytes.
/// - Syscall errors from MSM.
pub fn folded_error_commitment<B: SyscallBackend + ?Sized>(
    backend: &B,
    e1: &[u8],
    t: &[u8],
    r: &Fr,
) -> Result<[u8; 64], OnChainError> {
    if e1.len() != 64 || t.len() != 64 {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let r_bytes = fr_to_canonical_bytes(r);
    let mut t_arr = [0u8; 64];
    t_arr.copy_from_slice(t);
    let r_t = scalar_mul_g1(backend, &t_arr, &r_bytes)?;
    let mut e1_arr = [0u8; 64];
    e1_arr.copy_from_slice(e1);
    add_g1(backend, &e1_arr, &r_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_plonk::g1_consts::g1_generator_bytes;

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    // ---- hadamard_residual ----

    #[test]
    fn hadamard_residual_zero_on_valid_relation() {
        // Construct (a, b, c, E) such that a·b - u·c - E = 0.
        let mut r = rng(1);
        for _ in 0..5 {
            let a = Fr::rand(&mut r);
            let b = Fr::rand(&mut r);
            let c = Fr::rand(&mut r);
            let u = Fr::rand(&mut r);
            // E = a·b - u·c.
            let e = a * b - u * c;
            assert_eq!(hadamard_residual(&a, &b, &c, &e, &u), Fr::zero());
        }
    }

    #[test]
    fn hadamard_residual_nonzero_on_tampered_eval() {
        let mut r = rng(2);
        let a = Fr::rand(&mut r);
        let b = Fr::rand(&mut r);
        let c = Fr::rand(&mut r);
        let u = Fr::rand(&mut r);
        let e = a * b - u * c;
        // Bump a by 1 → relation fails.
        let bad_a = a + Fr::from(1u64);
        assert_ne!(hadamard_residual(&bad_a, &b, &c, &e, &u), Fr::zero());
    }

    #[test]
    fn hadamard_residual_fresh_instance_u_equals_one() {
        // u = 1 encodes a "fresh" instance: A·B - C - E = 0.
        let mut r = rng(3);
        let a = Fr::rand(&mut r);
        let b = Fr::rand(&mut r);
        let c = Fr::rand(&mut r);
        let e = a * b - c; // E = a·b - c when u = 1.
        assert_eq!(
            hadamard_residual(&a, &b, &c, &e, &Fr::from(1u64)),
            Fr::zero(),
        );
    }

    // ---- folded_commitment_from_fold ----

    #[test]
    fn folded_commitment_zero_r_is_just_c1() {
        // r = 0 → C_folded = C_1 + 0·C_2 + 0·T = C_1.
        let backend = HostBackend::new();
        let g1 = g1_generator_bytes();
        let zero_commit = [0u8; 64];
        let got = folded_commitment_from_fold(
            &backend,
            &g1, &zero_commit, &zero_commit, &Fr::zero(),
        )
        .unwrap();
        assert_eq!(got, g1);
    }

    #[test]
    fn folded_commitment_identity_inputs_is_identity() {
        let backend = HostBackend::new();
        let zero = [0u8; 64];
        let got = folded_commitment_from_fold(
            &backend, &zero, &zero, &zero, &Fr::from(5u64),
        )
        .unwrap();
        // 0 + 5·0 + 25·0 = 0.
        assert_eq!(got, zero);
    }

    #[test]
    fn folded_commitment_rejects_wrong_length() {
        let backend = HostBackend::new();
        let short = [0u8; 63];
        let g1 = g1_generator_bytes();
        let r = folded_commitment_from_fold(
            &backend, &short, &g1, &g1, &Fr::from(1u64),
        );
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    // ---- folded_error_commitment ----

    #[test]
    fn folded_error_zero_r_is_just_e1() {
        let backend = HostBackend::new();
        let g1 = g1_generator_bytes();
        let zero = [0u8; 64];
        let got =
            folded_error_commitment(&backend, &g1, &zero, &Fr::zero()).unwrap();
        assert_eq!(got, g1);
    }

    #[test]
    fn folded_error_identity_inputs_is_identity() {
        let backend = HostBackend::new();
        let zero = [0u8; 64];
        let got = folded_error_commitment(&backend, &zero, &zero, &Fr::from(7u64)).unwrap();
        assert_eq!(got, zero);
    }

    #[test]
    fn folded_error_rejects_wrong_length() {
        let backend = HostBackend::new();
        let short = [0u8; 63];
        let g1 = g1_generator_bytes();
        let r = folded_error_commitment(&backend, &short, &g1, &Fr::from(1u64));
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }
}
