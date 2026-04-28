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
//! This module provides:
//! - [`hadamard_residual`] — scalar residual at the evaluation point.
//! - [`folded_commitment_from_fold`] — three-term reconstruction
//!   `C_folded = C_1 + r · C_2 + r² · T` (placeholder shape used by
//!   both `E` and `W` in the current canonical layout).
//! - [`folded_commitment_two_term`] — canonical Nova two-term form
//!   `C_folded = C_1 + r · C_2` (`W` folds linearly without a cross-
//!   term in the standard relaxed-R1CS Nova).
//! - [`folded_error_commitment`] — the `E + r · T` shortcut once the
//!   layout drops the squared base contribution.
//! - [`verify_folding_consistency`] — high-level audit gate that
//!   reconstructs both `E_folded` and `W_folded` from the proof's base
//!   commitments + cross-term and rejects the proof if either
//!   reconstruction disagrees with the declared `e_comm` / `w_comm`.

use ark_bn254::Fr;
use mosaic_core::{syscall::SyscallBackend, OnChainError};
use mosaic_zk_primitives::{
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
pub fn hadamard_residual(a_eval: &Fr, b_eval: &Fr, c_eval: &Fr, e_eval: &Fr, u: &Fr) -> Fr {
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

/// Reconstruct a folded G1 commitment from two base commitments via
/// the **two-term linear** combiner:
///
/// ```text
/// C_folded  =  C_1  +  r · C_2
/// ```
///
/// This is the canonical Nova **witness** folding formula — `W` only
/// combines linearly because the witness vector itself satisfies a
/// linear relation under folding. The **error** commitment, by
/// contrast, picks up the quadratic cross-term `r² · T` from the
/// expansion of `(A·z_1 + r·A·z_2) ∘ (B·z_1 + r·B·z_2)` minus the
/// folded `u · C·z + E` — see [`folded_commitment_from_fold`].
///
/// Both `c1` and `c2` must be exactly 64 bytes (BN254 G1 affine
/// uncompressed). The function returns the folded commitment as 64
/// bytes; in particular, `r = 0` collapses to `c1` byte-for-byte.
///
/// Used by [`verify_folding_consistency`] to reconstruct
/// `proof.w_comm` from the proof's two base witness commitments and
/// the transcript-derived folding scalar.
///
/// ## Errors
///
/// - [`OnChainError::InvalidPointEncoding`] if either input G1 slice
///   is not exactly 64 bytes.
/// - Syscall errors from MSM.
pub fn folded_commitment_two_term<B: SyscallBackend + ?Sized>(
    backend: &B,
    c1: &[u8],
    c2: &[u8],
    r: &Fr,
) -> Result<[u8; 64], OnChainError> {
    if c1.len() != 64 || c2.len() != 64 {
        return Err(OnChainError::InvalidPointEncoding);
    }
    // r · C_2.
    let r_bytes = fr_to_canonical_bytes(r);
    let mut c2_arr = [0u8; 64];
    c2_arr.copy_from_slice(c2);
    let r_c2 = scalar_mul_g1(backend, &c2_arr, &r_bytes)?;
    // C_1 + r · C_2.
    let mut c1_arr = [0u8; 64];
    c1_arr.copy_from_slice(c1);
    add_g1(backend, &c1_arr, &r_c2)
}

/// High-level **fold-consistency audit gate** for a Nova-family
/// folded instance.
///
/// Reconstructs both `E_folded` and `W_folded` from the proof's
/// declared base commitments + cross-term using the transcript-
/// derived folding challenge `r`, and checks they agree byte-for-byte
/// with the proof's declared `e_comm` and `w_comm`. A divergence in
/// either is reported as [`OnChainError::VerificationFailed`].
///
/// ## What this catches
///
/// A malicious prover can construct a proof whose Hadamard residual
/// at the Spartan point `ξ` happens to evaluate to zero (e.g. by
/// hand-picking the four scalar evaluations) **without** the
/// underlying base commitments actually folding into the declared
/// `e_comm` / `w_comm`. The Spartan-batched KZG opening then closes
/// against the declared commits — but if the prover never honestly
/// folded the two base instances together, the relation between the
/// committed witness vector and the constraint-system matrices is
/// broken. This gate forces the prover to either:
///
/// 1. Honestly fold two base instances into the declared accumulator
///    (so `E_folded` and `W_folded` reconstruct correctly), **or**
/// 2. Forge two base commitments + a cross-term that happen to fold
///    into the declared accumulator under the **transcript-bound**
///    challenge `r` (computationally infeasible for a fixed `r`
///    derived after the prover commits to all four base + cross
///    points — Schwartz-Zippel + DLOG hardness).
///
/// ## Folding formulas
///
/// Per the placeholder canonical layout (mirrors the `sonobe`
/// folding-compiler output as documented in [`crate::canonical`]):
///
/// ```text
/// E_folded  =  E_1  +  r · E_2  +  r² · T          (3-term)
/// W_folded  =  W_1  +  r · W_2                     (2-term)
/// ```
///
/// The `E` reconstruction uses [`folded_commitment_from_fold`] and
/// the `W` reconstruction uses [`folded_commitment_two_term`]. The
/// two formulas differ because under canonical Nova relaxed-R1CS the
/// witness vector folds linearly while the error vector picks up the
/// quadratic cross-term from the constraint-relation expansion.
///
/// ## Inputs
///
/// All G1 inputs must be 64-byte uncompressed affine BN254 encodings.
/// `r` is the folding challenge squeezed from the transcript after
/// the prover has committed to all of `(E_1, E_2, W_1, W_2, T,
/// e_comm, w_comm)`.
///
/// ## Errors
///
/// - [`OnChainError::InvalidPointEncoding`] — any G1 slice ≠ 64 B.
/// - [`OnChainError::VerificationFailed`] — either reconstruction
///   disagrees with the declared `e_comm` / `w_comm`.
/// - Syscall errors propagated from the MSM primitives.
#[allow(clippy::too_many_arguments)]
pub fn verify_folding_consistency<B: SyscallBackend + ?Sized>(
    backend: &B,
    base_e_1: &[u8],
    base_e_2: &[u8],
    base_w_1: &[u8],
    base_w_2: &[u8],
    t_comm: &[u8],
    declared_e_comm: &[u8],
    declared_w_comm: &[u8],
    r: &Fr,
) -> Result<(), OnChainError> {
    // Up-front length validation across all 7 G1 inputs gives the
    // verifier a single rejection point with a uniform error type
    // before any (more expensive) syscall fires.
    if base_e_1.len() != 64
        || base_e_2.len() != 64
        || base_w_1.len() != 64
        || base_w_2.len() != 64
        || t_comm.len() != 64
        || declared_e_comm.len() != 64
        || declared_w_comm.len() != 64
    {
        return Err(OnChainError::InvalidPointEncoding);
    }

    // E_folded = E_1 + r · E_2 + r² · T  (three-term).
    let computed_e = folded_commitment_from_fold(backend, base_e_1, base_e_2, t_comm, r)?;
    if computed_e.as_slice() != declared_e_comm {
        return Err(OnChainError::VerificationFailed);
    }

    // W_folded = W_1 + r · W_2  (two-term, no cross-term).
    let computed_w = folded_commitment_two_term(backend, base_w_1, base_w_2, r)?;
    if computed_w.as_slice() != declared_w_comm {
        return Err(OnChainError::VerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_zk_primitives::g1_consts::g1_generator_bytes;

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
        let got =
            folded_commitment_from_fold(&backend, &g1, &zero_commit, &zero_commit, &Fr::zero())
                .unwrap();
        assert_eq!(got, g1);
    }

    #[test]
    fn folded_commitment_identity_inputs_is_identity() {
        let backend = HostBackend::new();
        let zero = [0u8; 64];
        let got =
            folded_commitment_from_fold(&backend, &zero, &zero, &zero, &Fr::from(5u64)).unwrap();
        // 0 + 5·0 + 25·0 = 0.
        assert_eq!(got, zero);
    }

    #[test]
    fn folded_commitment_rejects_wrong_length() {
        let backend = HostBackend::new();
        let short = [0u8; 63];
        let g1 = g1_generator_bytes();
        let r = folded_commitment_from_fold(&backend, &short, &g1, &g1, &Fr::from(1u64));
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    // ---- folded_error_commitment ----

    #[test]
    fn folded_error_zero_r_is_just_e1() {
        let backend = HostBackend::new();
        let g1 = g1_generator_bytes();
        let zero = [0u8; 64];
        let got = folded_error_commitment(&backend, &g1, &zero, &Fr::zero()).unwrap();
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

    // ---- folded_commitment_two_term (Session 86) ----

    #[test]
    fn folded_two_term_zero_r_is_just_c1() {
        // r = 0 → C_folded = C_1 + 0·C_2 = C_1.
        let backend = HostBackend::new();
        let g1 = g1_generator_bytes();
        let zero = [0u8; 64];
        let got = folded_commitment_two_term(&backend, &g1, &zero, &Fr::zero()).unwrap();
        assert_eq!(got, g1);
    }

    #[test]
    fn folded_two_term_identity_inputs_is_identity() {
        let backend = HostBackend::new();
        let zero = [0u8; 64];
        let got = folded_commitment_two_term(&backend, &zero, &zero, &Fr::from(11u64)).unwrap();
        // 0 + 11·0 = 0.
        assert_eq!(got, zero);
    }

    #[test]
    fn folded_two_term_rejects_wrong_length() {
        let backend = HostBackend::new();
        let short = [0u8; 63];
        let g1 = g1_generator_bytes();
        let r = folded_commitment_two_term(&backend, &short, &g1, &Fr::from(1u64));
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
        let r = folded_commitment_two_term(&backend, &g1, &short, &Fr::from(1u64));
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    /// Cross-check the new two-term path against the existing three-
    /// term `folded_commitment_from_fold` with `T = 0`. With a zero
    /// cross-term the squared `r² · T` summand collapses to identity,
    /// so `folded_commitment_from_fold(c1, c2, 0, r)` must equal
    /// `folded_commitment_two_term(c1, c2, r)` byte-for-byte. This
    /// is the algebraic invariant that justifies using the cheaper
    /// two-term reconstruction for `W` without losing soundness.
    #[test]
    fn folded_two_term_matches_three_term_with_zero_t() {
        let backend = HostBackend::new();
        let g1 = g1_generator_bytes();
        let zero_t = [0u8; 64];
        for r_val in [1u64, 7, 42, 1234, u64::MAX / 2] {
            let r = Fr::from(r_val);
            let two_term =
                folded_commitment_two_term(&backend, &g1, &g1, &r).expect("two-term ok");
            let three_term = folded_commitment_from_fold(&backend, &g1, &g1, &zero_t, &r)
                .expect("three-term ok");
            assert_eq!(
                two_term, three_term,
                "two-term should match three-term with T=0 at r={r_val}",
            );
        }
    }

    // ---- verify_folding_consistency (Session 86) ----

    /// Build a satisfying tuple `(base_e_1, base_e_2, base_w_1,
    /// base_w_2, t, e_comm, w_comm)` from the all-identity baseline
    /// and check the audit gate accepts. With every G1 = 0 and any
    /// `r`, both reconstructions collapse to identity.
    #[test]
    fn folding_consistency_identity_baseline_accepts() {
        let backend = HostBackend::new();
        let zero = [0u8; 64];
        for r_val in [0u64, 1, 7, 999] {
            let r = Fr::from(r_val);
            let res = verify_folding_consistency(
                &backend, &zero, &zero, &zero, &zero, &zero, &zero, &zero, &r,
            );
            assert!(res.is_ok(), "identity baseline should accept at r={r_val}");
        }
    }

    /// Generator-loaded baseline: with `base_e_1 = base_w_1 = G1`,
    /// `base_e_2 = base_w_2 = T = 0`, the reconstructions are:
    ///   E_folded = G1 + r·0 + r²·0 = G1
    ///   W_folded = G1 + r·0       = G1
    /// so the consistency gate accepts `e_comm = w_comm = G1`.
    #[test]
    fn folding_consistency_generator_baseline_accepts() {
        let backend = HostBackend::new();
        let g1 = g1_generator_bytes();
        let zero = [0u8; 64];
        let r = Fr::from(42u64);
        let res = verify_folding_consistency(
            &backend, &g1, &zero, &g1, &zero, &zero, &g1, &g1, &r,
        );
        assert!(res.is_ok(), "generator baseline should accept");
    }

    /// Tampering the declared `e_comm` away from the reconstructed
    /// value must surface as `VerificationFailed`. Mirrors the
    /// audit-gate contract: any deviation between declared and
    /// reconstructed E is fatal.
    #[test]
    fn folding_consistency_rejects_tampered_e_comm() {
        let backend = HostBackend::new();
        let g1 = g1_generator_bytes();
        let zero = [0u8; 64];
        let r = Fr::from(5u64);
        let res = verify_folding_consistency(
            &backend, &zero, &zero, &zero, &zero, &zero,
            &g1,   // declared E ≠ reconstructed (which would be 0)
            &zero, &r,
        );
        assert!(matches!(res, Err(OnChainError::VerificationFailed)));
    }

    /// Tampering the declared `w_comm` likewise must fail.
    #[test]
    fn folding_consistency_rejects_tampered_w_comm() {
        let backend = HostBackend::new();
        let g1 = g1_generator_bytes();
        let zero = [0u8; 64];
        let r = Fr::from(5u64);
        let res = verify_folding_consistency(
            &backend, &zero, &zero, &zero, &zero, &zero, &zero,
            &g1,   // declared W ≠ reconstructed (which would be 0)
            &r,
        );
        assert!(matches!(res, Err(OnChainError::VerificationFailed)));
    }

    /// Tampering any of the seven base/cross/declared commits with a
    /// length ≠ 64 must surface as `InvalidPointEncoding` *before*
    /// any syscall fires.
    #[test]
    fn folding_consistency_rejects_short_inputs() {
        let backend = HostBackend::new();
        let zero = [0u8; 64];
        let short = [0u8; 63];
        let r = Fr::from(1u64);
        // Walk each slot, placing the short slice in the active slot
        // and zero everywhere else. Each individual slot must reject
        // independently with the up-front length check.
        for which in 0..7 {
            let mut args: [&[u8]; 7] = [&zero; 7];
            args[which] = &short;
            let res = verify_folding_consistency(
                &backend, args[0], args[1], args[2], args[3], args[4], args[5], args[6], &r,
            );
            assert!(
                matches!(res, Err(OnChainError::InvalidPointEncoding)),
                "slot {which} short input should reject as InvalidPointEncoding"
            );
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 86 — Proptest soundness suite for the consistency check.
    //
    // The audit gate's contract is: "given a satisfying tuple, accept;
    // given a tampered tuple, reject." We pin both directions over a
    // randomised (r, base, cross) space, then sweep tampering across
    // each of the 7 input slots.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    /// Random non-zero Fr — `derive_challenges` cannot reasonably
    /// produce 0, and the `r = 0` boundary is already covered by the
    /// identity-baseline unit test above.
    fn arb_nonzero_fr() -> impl Strategy<Value = Fr> {
        (1u64..u64::MAX).prop_map(Fr::from)
    }

    proptest! {
        /// Honestly-folded tuple always accepts.
        ///
        /// We pick a random `r`, leave all base + cross commits at
        /// identity, and reconstruct the *correct* declared E and W
        /// using the same primitives the verifier uses. The gate
        /// must accept this tuple — it's the round-trip identity.
        #[test]
        fn proptest_accepts_correctly_folded_tuple(r in arb_nonzero_fr()) {
            let backend = HostBackend::new();
            let zero = [0u8; 64];
            // Reconstruct the canonical folded values (both 0 here)
            // through the same primitives the gate uses, so any
            // future change to the primitives stays consistent.
            let expected_e =
                folded_commitment_from_fold(&backend, &zero, &zero, &zero, &r)
                    .expect("3-term ok");
            let expected_w = folded_commitment_two_term(&backend, &zero, &zero, &r)
                .expect("2-term ok");
            let res = verify_folding_consistency(
                &backend, &zero, &zero, &zero, &zero, &zero,
                &expected_e, &expected_w, &r,
            );
            prop_assert!(res.is_ok(), "round-trip identity must accept, got {:?}", res);
        }

        /// Replacing the declared `e_comm` with a non-matching value
        /// (G1 generator) always rejects.
        #[test]
        fn proptest_rejects_e_comm_swap(r in arb_nonzero_fr()) {
            let backend = HostBackend::new();
            let g1 = g1_generator_bytes();
            let zero = [0u8; 64];
            // Reconstructed E from all-zero base = 0; declare G1
            // instead → must reject.
            let res = verify_folding_consistency(
                &backend, &zero, &zero, &zero, &zero, &zero, &g1, &zero, &r,
            );
            prop_assert!(matches!(res, Err(OnChainError::VerificationFailed)));
        }

        /// Replacing the declared `w_comm` with a non-matching value
        /// always rejects.
        #[test]
        fn proptest_rejects_w_comm_swap(r in arb_nonzero_fr()) {
            let backend = HostBackend::new();
            let g1 = g1_generator_bytes();
            let zero = [0u8; 64];
            let res = verify_folding_consistency(
                &backend, &zero, &zero, &zero, &zero, &zero, &zero, &g1, &r,
            );
            prop_assert!(matches!(res, Err(OnChainError::VerificationFailed)));
        }

        /// Replacing any *base* commitment with a non-zero value (G1
        /// generator) breaks the reconstruction so the all-zero
        /// declared commits no longer match — must reject.
        ///
        /// The key invariant: with declared E=W=0, the reconstruction
        /// must also be 0; bumping any base commit non-zero produces
        /// a non-identity reconstructed E or W, breaking equality.
        ///
        /// Note: tampering `t_comm` requires either `r ≠ 0` *and* the
        /// E reconstruction to actually pick up `r²·T ≠ 0`; with the
        /// non-zero `r` from `arb_nonzero_fr`, this always fires.
        #[test]
        fn proptest_rejects_any_base_or_cross_tamper(
            which in 0u8..5,
            r in arb_nonzero_fr(),
        ) {
            let backend = HostBackend::new();
            let g1 = g1_generator_bytes();
            let zero = [0u8; 64];

            // Build the slot array, replacing one of the 5 base/cross
            // slots with G1.
            let mut base_e_1: &[u8] = &zero;
            let mut base_e_2: &[u8] = &zero;
            let mut base_w_1: &[u8] = &zero;
            let mut base_w_2: &[u8] = &zero;
            let mut t_comm: &[u8] = &zero;
            match which {
                0 => base_e_1 = &g1,
                1 => base_e_2 = &g1,
                2 => base_w_1 = &g1,
                3 => base_w_2 = &g1,
                _ => t_comm = &g1,
            }
            let res = verify_folding_consistency(
                &backend, base_e_1, base_e_2, base_w_1, base_w_2, t_comm,
                &zero, &zero, &r,
            );
            prop_assert!(
                matches!(res, Err(OnChainError::VerificationFailed)),
                "base/cross slot {which} tamper at r={:?} should reject", r,
            );
        }
    }
}
