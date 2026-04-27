//! Multi-scalar multiplication over G1 via [`SyscallBackend`].
//!
//! ## What this is for
//!
//! PLONK's linearization polynomial [r]_1 is reconstructed as a big
//! sum of `coeff_i · Commitment_i` terms. The same pattern shows up
//! in Groth16's public-input MSM (IC[0] + Σ `pi_i` · IC[i+1]) and in
//! batched verification. This module provides a shared primitive.
//!
//! ## Algorithm
//!
//! Naive `Σ k_i · P_i` — one `G1Mul` per point plus one `G1Add` per
//! accumulation step. For n points: n scalar muls + (n-1) adds = ~2n
//! syscalls.
//!
//! Pippenger's bucket method amortizes for large n (>64) but for the
//! ~20-point MSM in PLONK linearization and the 1-10 point MSM in
//! Groth16 IC, naive is competitive and easier to audit. Issue #37
//! tracks Pippenger as a later optimization.
//!
//! ## Wire format
//!
//! - `points`: each element is a 64-byte canonical G1 affine encoding
//!   (x ‖ y, both big-endian).
//! - `scalars`: each element is a 32-byte big-endian Fr value, already
//!   reduced mod r.
//!
//! Returns a 64-byte G1 affine in the same canonical form.

use alloc::vec::Vec;
use mosaic_core::{
    syscall::{AltBn128Op, InputEndianness, SyscallBackend},
    OnChainError,
};

/// 64-byte G1 affine representing the identity / zero point of the
/// curve. `alt_bn128_group_op` treats this as the additive neutral.
pub const G1_ZERO: [u8; 64] = [0u8; 64];

/// Compute `A = C - y·G1 + ξ·W` — the canonical left-hand side of a
/// KZG opening pairing check. Every KZG-based verifier in the
/// workspace builds this same G1 expression before pairing against
/// (-W, [x]_G2).
///
/// Internally: `commitment_minus_scalar_g1(C, y)` → `scalar_mul_g1(W, ξ)`
/// → `add_g1`. Five syscalls total (one G1Mul + one G1Add + the
/// three inside `commitment_minus_scalar_g1`).
///
/// Session-35 hoist — sessions 25/26 extracted the two sub-steps
/// (`verify_two_pair_pairing` + `commitment_minus_scalar_g1`); this
/// session closes the loop by combining the LHS construction into a
/// single primitive so the caller just supplies `(C, y, ξ, W)`.
///
/// # Errors
///
/// Propagates length/syscall errors from the underlying primitives
/// ([`commitment_minus_scalar_g1`], [`scalar_mul_g1`], [`add_g1`]).
///
/// # Examples
///
/// ```no_run
/// use mosaic_core::syscall::SyscallBackend;
/// use mosaic_zk_primitives::msm::compute_kzg_opening_lhs;
///
/// fn build_lhs<B: SyscallBackend + ?Sized>(
///     backend: &B,
///     c: &[u8; 64],
///     y_be: &[u8; 32],
///     xi_be: &[u8; 32],
///     w: &[u8; 64],
/// ) -> Result<[u8; 64], mosaic_core::OnChainError> {
///     compute_kzg_opening_lhs(backend, c, y_be, xi_be, w)
/// }
/// ```
pub fn compute_kzg_opening_lhs<B: SyscallBackend + ?Sized>(
    backend: &B,
    commitment: &[u8; 64],
    claimed_eval_be: &[u8; 32],
    xi_be: &[u8; 32],
    opening_commitment: &[u8; 64],
) -> Result<[u8; 64], OnChainError> {
    let c_minus_y = commitment_minus_scalar_g1(backend, commitment, claimed_eval_be)?;
    let xi_w = scalar_mul_g1(backend, opening_commitment, xi_be)?;
    add_g1(backend, &c_minus_y, &xi_w)
}

/// Compute `C - y·G1` — a commitment with the claimed evaluation
/// scalar-multiplied out of its value. This is the KZG opening
/// "C minus y times generator" step that appears identically in
/// every multivariate / univariate opening across mosaic-halo2,
/// mosaic-nova, and mosaic-hyperplonk.
///
/// Internally: `scalar_mul_g1(g1, y)` → `negate_g1` → `add_g1(C, -y·G1)`.
/// Three syscalls (`G1Mul` + `G1Add`; negation is a pure-byte flip of the
/// y-coordinate).
///
/// ## Errors
///
/// Propagates any syscall / length errors from the underlying
/// [`scalar_mul_g1`] and [`add_g1`] primitives.
///
/// # Examples
///
/// ```no_run
/// use mosaic_core::syscall::SyscallBackend;
/// use mosaic_zk_primitives::msm::commitment_minus_scalar_g1;
///
/// fn opening_lhs_piece<B: SyscallBackend + ?Sized>(
///     backend: &B,
///     commitment: &[u8; 64],
///     claimed_eval_be: &[u8; 32],
/// ) -> Result<[u8; 64], mosaic_core::OnChainError> {
///     commitment_minus_scalar_g1(backend, commitment, claimed_eval_be)
/// }
/// ```
pub fn commitment_minus_scalar_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    commitment: &[u8; 64],
    scalar_bytes: &[u8; 32],
) -> Result<[u8; 64], OnChainError> {
    use crate::g1_consts::g1_generator_bytes;
    let g1 = g1_generator_bytes();
    let y_g1 = scalar_mul_g1(backend, &g1, scalar_bytes)?;
    let neg_y_g1 = negate_g1(&y_g1);
    add_g1(backend, commitment, &neg_y_g1)
}

/// BN254 `alt_bn128` 2-pair pairing identity check: returns `Ok(())`
/// when `e(p1_g1, p1_g2) · e(p2_g1, p2_g2) == 1` in the Fq12 target,
/// `Err(PairingCheckFailed)` otherwise.
///
/// Wire encoding (big-endian, per Solana `alt_bn128` convention):
/// - `p1_g1`, `p2_g1` — 64-byte G1 affine (x ‖ y)
/// - `p1_g2`, `p2_g2` — 128-byte G2 affine (x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0)
///
/// Session-25 hoist — the same fixed-shape 2-pair pairing pattern
/// (build 384-byte input, call `AltBn128Op::Pairing`, inspect the
/// returned 32-byte boolean) was repeated at 4+ sites across
/// mosaic-halo2 and mosaic-nova. Factored here so the call-site
/// delta is exactly the two G1 + two G2 argument slots.
///
/// ## Errors
///
/// - [`OnChainError::InvalidPointEncoding`] if either G2 slice is
///   not 128 bytes.
/// - Backend errors from [`SyscallBackend::alt_bn128_group_op`].
/// - [`OnChainError::PairingCheckFailed`] on pairing ≠ 1.
///
/// # Examples
///
/// ```no_run
/// use mosaic_core::syscall::SyscallBackend;
/// use mosaic_zk_primitives::{
///     g1_consts::{g1_generator_bytes, g2_generator_bytes},
///     msm::{negate_g1, verify_two_pair_pairing},
/// };
///
/// // Canonical KZG opening: e(A, G2) · e(-W, [x]·G2) == 1 where
/// // A = C - y·G1 + ξ·W. The caller builds A and passes (-W, [x]G2)
/// // as the second pair.
/// fn check_kzg_opening<B: SyscallBackend + ?Sized>(
///     backend: &B,
///     a: &[u8; 64],
///     w: &[u8; 64],
///     x2_g2: &[u8; 128],
/// ) -> Result<(), mosaic_core::OnChainError> {
///     let neg_w = negate_g1(w);
///     verify_two_pair_pairing(backend, a, &g2_generator_bytes(), &neg_w, x2_g2)
/// }
/// ```
pub fn verify_two_pair_pairing<B: SyscallBackend + ?Sized>(
    backend: &B,
    p1_g1: &[u8; 64],
    p1_g2: &[u8],
    p2_g1: &[u8; 64],
    p2_g2: &[u8],
) -> Result<(), OnChainError> {
    verify_n_pair_pairing(backend, &[(p1_g1, p1_g2), (p2_g1, p2_g2)])
}

/// `N`-pair generic version of [`verify_two_pair_pairing`].
///
/// Asserts `Π e(g1_i, g2_i) == 1` (the multiplicative identity in
/// G_T) for an arbitrary number of pairs. Empty input is the
/// vacuously-true case and returns `Ok(())` without invoking the
/// syscall.
///
/// ## Why an N-pair primitive
///
/// Halo2's multi-poly batched opening (session 17) and Nova's
/// Spartan-batched 5-way opening (session 22) both build a
/// dynamically-sized list of `(G1, G2)` pairs and feed it to
/// `alt_bn128_pairing` in a single syscall. Both currently
/// inline the loop that concatenates pair bytes into the syscall
/// input buffer. This primitive lifts the loop into one
/// audit-grade helper.
///
/// The 2-pair version stays in the workspace for the canonical
/// KZG opening pattern (which is hot-path enough that a slice-
/// allocation-free signature matters). Callers with a known-2
/// pair count should prefer `verify_two_pair_pairing`; callers
/// with a dynamic pair count should use this one.
///
/// Session 66 (post-v0.8.2): eighth shared primitive.
///
/// ## Errors
///
/// - [`OnChainError::InvalidPointEncoding`] — any G2 byte slice
///   length differs from 128.
/// - [`OnChainError::PairingCheckFailed`] — the syscall returned
///   the multiplicative-identity check as `false`.
/// - Syscall errors from the backend.
pub fn verify_n_pair_pairing<B: SyscallBackend + ?Sized>(
    backend: &B,
    pairs: &[(&[u8; 64], &[u8])],
) -> Result<(), OnChainError> {
    const G2_LEN: usize = 128;
    if pairs.is_empty() {
        // Empty product is the multiplicative identity; vacuously
        // satisfies `Π e(g1_i, g2_i) == 1`. We return `Ok(())`
        // without a syscall round-trip.
        return Ok(());
    }
    // Pre-validate G2 lengths before any syscall work — a bad G2
    // mid-batch would otherwise leak partial syscall cost.
    for &(_, g2) in pairs {
        if g2.len() != G2_LEN {
            return Err(OnChainError::InvalidPointEncoding);
        }
    }
    let mut input: Vec<u8> = Vec::with_capacity(pairs.len() * (64 + G2_LEN));
    for &(g1, g2) in pairs {
        input.extend_from_slice(g1);
        input.extend_from_slice(g2);
    }
    let result =
        backend.alt_bn128_group_op(AltBn128Op::Pairing, InputEndianness::BigEndian, &input)?;
    if result.len() != 32 || result[31] != 0x01 {
        return Err(OnChainError::PairingCheckFailed);
    }
    Ok(())
}

/// Compute `Σ scalars_i · points_i` as a single G1 affine.
///
/// - `points.len()` must equal `scalars.len()`; otherwise
///   [`OnChainError::PublicInputCountMismatch`] is returned.
/// - An empty MSM returns the zero point (additive identity).
///
/// Each scalar is applied via one `G1Mul` syscall; results accumulate
/// via repeated `G1Add` syscalls.
///
/// # Errors
///
/// - [`OnChainError::PublicInputCountMismatch`] — `points.len() !=
///   scalars.len()`.
/// - [`OnChainError::InvalidPointEncoding`] — any point is not 64 bytes
///   (propagated from [`scalar_mul_g1`]).
/// - [`OnChainError::InternalInvariantViolation`] — the `alt_bn128`
///   syscall returned a non-64-byte result (propagated from
///   [`scalar_mul_g1`] / [`add_g1`]).
/// - Syscall errors from the backend.
pub fn msm_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    points: &[&[u8]],
    scalars: &[[u8; 32]],
) -> Result<[u8; 64], OnChainError> {
    if points.len() != scalars.len() {
        return Err(OnChainError::PublicInputCountMismatch);
    }
    if points.is_empty() {
        return Ok(G1_ZERO);
    }

    // First product initializes the accumulator so we don't waste a
    // G1Add against zero.
    let mut acc = scalar_mul_g1(backend, points[0], &scalars[0])?;

    for (point, scalar) in points.iter().skip(1).zip(scalars.iter().skip(1)) {
        let product = scalar_mul_g1(backend, point, scalar)?;
        acc = add_g1(backend, &acc, &product)?;
    }

    Ok(acc)
}

/// One G1 scalar multiplication: `k · P`. Wraps the syscall with wire-
/// format length checks.
///
/// # Errors
///
/// - [`OnChainError::InvalidPointEncoding`] — `point.len() != 64`.
/// - [`OnChainError::InternalInvariantViolation`] — the `alt_bn128`
///   syscall returned a result whose length wasn't 64 bytes.
/// - Syscall errors from the backend.
pub fn scalar_mul_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    point: &[u8],
    scalar: &[u8; 32],
) -> Result<[u8; 64], OnChainError> {
    if point.len() != 64 {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let mut input = Vec::with_capacity(96);
    input.extend_from_slice(point);
    input.extend_from_slice(scalar);
    let out = backend.alt_bn128_group_op(AltBn128Op::G1Mul, InputEndianness::BigEndian, &input)?;
    if out.len() != 64 {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut result = [0u8; 64];
    result.copy_from_slice(&out);
    Ok(result)
}

/// G1 point addition: `P + Q`. Wraps the syscall with wire-format
/// length checks.
///
/// # Errors
///
/// - [`OnChainError::InternalInvariantViolation`] — the `alt_bn128`
///   syscall returned a result whose length wasn't 64 bytes.
/// - Syscall errors from the backend.
pub fn add_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    a: &[u8; 64],
    b: &[u8; 64],
) -> Result<[u8; 64], OnChainError> {
    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    let out = backend.alt_bn128_group_op(AltBn128Op::G1Add, InputEndianness::BigEndian, &input)?;
    if out.len() != 64 {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut result = [0u8; 64];
    result.copy_from_slice(&out);
    Ok(result)
}

/// Negate a G1 point's y-coordinate: `(x, y) → (x, -y mod q)`.
///
/// `q = BN254 base field modulus`. Used in PLONK for building the E/F
/// commitments in the KZG batched opening check and for the verifier's
/// `e(-A, B) = ...` rewrite.
#[must_use]
pub fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    /// BN254 base-field modulus `q` in big-endian.
    const BN254_FQ_MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];
    let mut out = *point;
    let y_slice = &mut out[32..64];
    // If y == 0, negation is identity.
    if y_slice.iter().all(|b| *b == 0) {
        return out;
    }
    // Session-31 cast-safety rewrite: (q - y) mod q via big-endian
    // overflowing_sub borrow chain. Mirrors the mosaic-zk-primitives::
    // fr::sub_r rewrite — same correctness contract, no i16 widening,
    // no `as u8` truncation casts that clippy flagged.
    let mut borrow_in: u8 = 0;
    for i in (0..32).rev() {
        let (partial, b1) = BN254_FQ_MODULUS_BE[i].overflowing_sub(y_slice[i]);
        let (result, b2) = partial.overflowing_sub(borrow_in);
        y_slice[i] = result;
        borrow_in = u8::from(b1) | u8::from(b2);
    }
    // q > y by construction for any valid point, so borrow must be 0.
    debug_assert_eq!(borrow_in, 0, "negate_g1 saw y > q");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ark_bn254::{Fr, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use mosaic_core::syscall::host::HostBackend;

    fn seeded_rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    /// Encode an arkworks G1Affine into canonical 64-byte BE form matching
    /// our wire layout: `x ‖ y`, each 32 bytes big-endian.
    fn ark_g1_to_canonical(point: &G1Affine) -> [u8; 64] {
        let (x, y) = point
            .xy()
            .unwrap_or((ark_bn254::Fq::default(), ark_bn254::Fq::default()));
        let mut x_be = x.into_bigint().to_bytes_le();
        x_be.resize(32, 0);
        x_be.reverse();
        let mut y_be = y.into_bigint().to_bytes_le();
        y_be.resize(32, 0);
        y_be.reverse();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&x_be);
        out[32..].copy_from_slice(&y_be);
        out
    }

    /// Encode an arkworks Fr as 32-byte big-endian.
    fn ark_fr_to_be32(fr: &Fr) -> [u8; 32] {
        let mut le = fr.into_bigint().to_bytes_le();
        le.resize(32, 0);
        le.reverse();
        let mut out = [0u8; 32];
        out.copy_from_slice(&le);
        out
    }

    #[test]
    fn msm_empty_is_zero_point() {
        let backend = HostBackend::new();
        let r = msm_g1(&backend, &[], &[]).unwrap();
        assert_eq!(r, G1_ZERO);
    }

    #[test]
    fn msm_mismatched_lengths_rejected() {
        let backend = HostBackend::new();
        let generator = G1Affine::generator();
        let p_bytes = ark_g1_to_canonical(&generator);
        let points: Vec<&[u8]> = vec![&p_bytes];
        let scalars = vec![[0u8; 32], [0u8; 32]]; // 2 scalars, 1 point
        assert!(matches!(
            msm_g1(&backend, &points, &scalars),
            Err(OnChainError::PublicInputCountMismatch),
        ));
    }

    #[test]
    fn msm_single_point_matches_scalar_mul_oracle() {
        let backend = HostBackend::new();
        let mut rng = seeded_rng(1);
        let p = G1Projective::rand(&mut rng).into_affine();
        let k = Fr::rand(&mut rng);

        let p_bytes = ark_g1_to_canonical(&p);
        let k_be = ark_fr_to_be32(&k);

        let got = msm_g1(&backend, &[&p_bytes], &[k_be]).unwrap();

        let expected = (p * k).into_affine();
        let expected_bytes = ark_g1_to_canonical(&expected);

        assert_eq!(got, expected_bytes);
    }

    #[test]
    fn msm_matches_arkworks_multi_scalar_mul() {
        let backend = HostBackend::new();
        let mut rng = seeded_rng(2);

        for n_points in [2_usize, 3, 5, 8] {
            let points_proj: Vec<G1Projective> = (0..n_points)
                .map(|_| G1Projective::rand(&mut rng))
                .collect();
            let scalars_fr: Vec<Fr> = (0..n_points).map(|_| Fr::rand(&mut rng)).collect();

            let points_aff: Vec<G1Affine> = points_proj.iter().map(|p| p.into_affine()).collect();
            let points_bytes: Vec<[u8; 64]> = points_aff.iter().map(ark_g1_to_canonical).collect();
            let points_refs: Vec<&[u8]> = points_bytes.iter().map(|b| &b[..]).collect();
            let scalars_bytes: Vec<[u8; 32]> = scalars_fr.iter().map(ark_fr_to_be32).collect();

            let got = msm_g1(&backend, &points_refs, &scalars_bytes).unwrap();

            let mut expected = G1Projective::default();
            for (p, k) in points_proj.iter().zip(scalars_fr.iter()) {
                expected += *p * k;
            }
            let expected_bytes = ark_g1_to_canonical(&expected.into_affine());

            assert_eq!(got, expected_bytes, "n_points={n_points}");
        }
    }

    #[test]
    fn negate_g1_is_additive_inverse() {
        let backend = HostBackend::new();
        let mut rng = seeded_rng(3);
        let p = G1Projective::rand(&mut rng).into_affine();
        let p_bytes = ark_g1_to_canonical(&p);

        let neg_p = negate_g1(&p_bytes);
        let sum = add_g1(&backend, &p_bytes, &neg_p).unwrap();

        // P + (-P) must be the zero point.
        assert_eq!(sum, G1_ZERO);
    }

    #[test]
    fn negate_g1_of_zero_is_zero() {
        let neg = negate_g1(&G1_ZERO);
        assert_eq!(neg, G1_ZERO);
    }

    #[test]
    fn negate_g1_matches_arkworks_neg() {
        let mut rng = seeded_rng(4);
        for _ in 0..5 {
            let p = G1Projective::rand(&mut rng).into_affine();
            let p_bytes = ark_g1_to_canonical(&p);
            let neg_bytes = negate_g1(&p_bytes);
            let expected = ark_g1_to_canonical(&(-p));
            assert_eq!(neg_bytes, expected);
        }
    }

    #[test]
    fn scalar_mul_g1_rejects_wrong_point_length() {
        let backend = HostBackend::new();
        let short = [0u8; 63];
        let scalar = [0u8; 32];
        assert!(matches!(
            scalar_mul_g1(&backend, &short, &scalar),
            Err(OnChainError::InvalidPointEncoding),
        ));
    }

    // ---- commitment_minus_scalar_g1 ----

    #[test]
    fn commitment_minus_zero_returns_commitment() {
        // C - 0·G1 = C: subtracting zero is a no-op.
        let backend = HostBackend::new();
        let g1 = crate::g1_consts::g1_generator_bytes();
        let zero = [0u8; 32];
        let r = commitment_minus_scalar_g1(&backend, &g1, &zero).unwrap();
        assert_eq!(r, g1, "C - 0·G1 must equal C");
    }

    #[test]
    fn commitment_minus_one_equals_negate() {
        // G1 - 1·G1 = G1 - G1 = identity (zero point).
        let backend = HostBackend::new();
        let g1 = crate::g1_consts::g1_generator_bytes();
        let one_bytes = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        let r = commitment_minus_scalar_g1(&backend, &g1, &one_bytes).unwrap();
        assert_eq!(r, G1_ZERO, "G1 - 1·G1 must reduce to the identity point");
    }

    // ---- compute_kzg_opening_lhs ----

    #[test]
    fn kzg_opening_lhs_equals_composed_primitives() {
        // Session 35 sanity: compute_kzg_opening_lhs must produce
        // the same G1 point as composing commitment_minus_scalar_g1 +
        // scalar_mul_g1 + add_g1 manually. If these ever diverge,
        // downstream verifiers silently pass proofs they shouldn't.
        let backend = HostBackend::new();
        let mut rng = seeded_rng(42);
        let c = ark_g1_to_canonical(&G1Projective::rand(&mut rng).into_affine());
        let w = ark_g1_to_canonical(&G1Projective::rand(&mut rng).into_affine());
        let y_fr = Fr::rand(&mut rng);
        let xi_fr = Fr::rand(&mut rng);
        let y_bytes = fr_to_bytes_be(&y_fr);
        let xi_bytes = fr_to_bytes_be(&xi_fr);

        let via_primitive = compute_kzg_opening_lhs(&backend, &c, &y_bytes, &xi_bytes, &w).unwrap();

        // Manual composition.
        let c_minus_y = commitment_minus_scalar_g1(&backend, &c, &y_bytes).unwrap();
        let xi_w = scalar_mul_g1(&backend, &w, &xi_bytes).unwrap();
        let manual = add_g1(&backend, &c_minus_y, &xi_w).unwrap();

        assert_eq!(via_primitive, manual);
    }

    /// Helper: encode an `Fr` as 32 big-endian bytes.
    fn fr_to_bytes_be(fr: &Fr) -> [u8; 32] {
        let mut le = fr.into_bigint().to_bytes_le();
        le.resize(32, 0);
        le.reverse();
        let mut out = [0u8; 32];
        out.copy_from_slice(&le);
        out
    }

    // ---- verify_two_pair_pairing ----

    #[test]
    fn verify_two_pair_pairing_accepts_zero_points() {
        // e(0, G2) · e(0, x2·G2) = 1 · 1 = 1. The zero G1 point
        // pairs to identity with any G2 factor.
        let backend = HostBackend::new();
        let g2 = crate::g1_consts::g2_generator_bytes();
        let r = verify_two_pair_pairing(&backend, &G1_ZERO, &g2, &G1_ZERO, &g2);
        assert!(r.is_ok(), "zero-zero pairing should pass, got {r:?}");
    }

    #[test]
    fn verify_two_pair_pairing_accepts_canceling_pair() {
        // e(G1, G2) · e(-G1, G2) = e(G1 - G1, G2) = e(0, G2) = 1.
        let backend = HostBackend::new();
        let g1 = crate::g1_consts::g1_generator_bytes();
        let neg_g1 = negate_g1(&g1);
        let g2 = crate::g1_consts::g2_generator_bytes();
        let r = verify_two_pair_pairing(&backend, &g1, &g2, &neg_g1, &g2);
        assert!(r.is_ok(), "canceling pair should pass, got {r:?}");
    }

    #[test]
    fn verify_two_pair_pairing_rejects_nonzero_product() {
        // e(G1, G2) · e(G1, G2) = e(G1, G2)² ≠ 1 in the Fq12 target.
        let backend = HostBackend::new();
        let g1 = crate::g1_consts::g1_generator_bytes();
        let g2 = crate::g1_consts::g2_generator_bytes();
        let r = verify_two_pair_pairing(&backend, &g1, &g2, &g1, &g2);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "e(G1,G2)² ≠ 1 expected PairingCheckFailed, got {r:?}",
        );
    }

    #[test]
    fn verify_two_pair_pairing_rejects_wrong_g2_length() {
        let backend = HostBackend::new();
        let g1 = crate::g1_consts::g1_generator_bytes();
        let short_g2 = [0u8; 127];
        let g2 = crate::g1_consts::g2_generator_bytes();
        let r = verify_two_pair_pairing(&backend, &g1, &short_g2, &g1, &g2);
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    // ---- verify_n_pair_pairing (session 66) ----

    #[test]
    fn verify_n_pair_pairing_empty_is_vacuous_ok() {
        // Empty product is the multiplicative identity; vacuously
        // satisfies `Π e(g1_i, g2_i) == 1`. No syscall round-trip.
        let backend = HostBackend::new();
        let r = verify_n_pair_pairing(&backend, &[]);
        assert!(
            r.is_ok(),
            "empty pair list should be vacuously OK, got {r:?}"
        );
    }

    #[test]
    fn verify_n_pair_pairing_two_pair_matches_specialized() {
        // `verify_two_pair_pairing` now delegates to
        // `verify_n_pair_pairing(&[(p1, p2), (p3, p4)])`. Pin the
        // result equivalence on the canceling-pair case.
        let backend = HostBackend::new();
        let g1 = crate::g1_consts::g1_generator_bytes();
        let neg_g1 = negate_g1(&g1);
        let g2 = crate::g1_consts::g2_generator_bytes();
        let via_specialized = verify_two_pair_pairing(&backend, &g1, &g2, &neg_g1, &g2);
        let via_generic = verify_n_pair_pairing(&backend, &[(&g1, &g2[..]), (&neg_g1, &g2[..])]);
        assert_eq!(via_specialized.is_ok(), via_generic.is_ok());
    }

    #[test]
    fn verify_n_pair_pairing_three_pair_canceling() {
        // e(G1, G2) · e(G1, G2) · e(-2·G1, G2) = e(G1+G1-2·G1, G2)
        //                                       = e(0, G2) = 1.
        let backend = HostBackend::new();
        let g1 = crate::g1_consts::g1_generator_bytes();
        let g2 = crate::g1_consts::g2_generator_bytes();
        let two_bytes = {
            let mut b = [0u8; 32];
            b[31] = 2;
            b
        };
        let two_g1 = scalar_mul_g1(&backend, &g1, &two_bytes).unwrap();
        let neg_two_g1 = negate_g1(&two_g1);
        let r = verify_n_pair_pairing(
            &backend,
            &[(&g1, &g2[..]), (&g1, &g2[..]), (&neg_two_g1, &g2[..])],
        );
        assert!(
            r.is_ok(),
            "3-pair canceling combination should pass, got {r:?}"
        );
    }

    #[test]
    fn verify_n_pair_pairing_rejects_wrong_g2_length() {
        let backend = HostBackend::new();
        let g1 = crate::g1_consts::g1_generator_bytes();
        let g2 = crate::g1_consts::g2_generator_bytes();
        let short_g2 = [0u8; 127];
        let r = verify_n_pair_pairing(&backend, &[(&g1, &g2[..]), (&g1, &short_g2[..])]);
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    // ---- Property-based tests (session 34) ----
    //
    // `negate_g1` hand-rolls `(q − y) mod q` with the session-31
    // overflowing_sub borrow chain; scalar_mul_g1 + add_g1 round-
    // trips delegate to the syscall. The invariants under test:
    //
    //   1. Double-negation is the identity (up to the y=0 edge case
    //      where negate is defined as identity).
    //   2. P + (-P) = identity, for any valid on-curve P.
    //   3. MSM of one term: `msm_g1([P], [k]) = scalar_mul_g1(P, k)`.
    //   4. MSM-scalar-zero collapses to zero: any point × 0 = 0.

    use proptest::prelude::*;

    /// Strategy: random scalars for the arkworks `Fr` group. Seeded
    /// via a u64; we derive the Fr on demand so proptest's shrinking
    /// can bisect failing seeds without needing to shrink through
    /// 32-byte arrays (which doesn't compose well with field
    /// arithmetic invariants).
    fn fr_from_seed(seed: u64) -> ark_bn254::Fr {
        let mut rng = seeded_rng(seed);
        Fr::rand(&mut rng)
    }

    /// Strategy: a random on-curve G1 point, encoded as our canonical
    /// 64-byte BE form. Same seed-driven pattern as fr_from_seed.
    fn g1_from_seed(seed: u64) -> [u8; 64] {
        let mut rng = seeded_rng(seed);
        let p = G1Projective::rand(&mut rng).into_affine();
        ark_g1_to_canonical(&p)
    }

    proptest! {
        /// `negate_g1(negate_g1(P)) == P` for any on-curve P.
        /// Exercises the session-31 overflowing_sub borrow chain
        /// across every byte position.
        #[test]
        fn prop_negate_g1_is_involutive(seed in any::<u64>()) {
            let p = g1_from_seed(seed);
            let twice = negate_g1(&negate_g1(&p));
            prop_assert_eq!(twice, p);
        }

        /// `P + (-P) = identity (zero G1)` for any on-curve P.
        /// Cross-verifies negate_g1 against the `alt_bn128` G1Add
        /// syscall path.
        #[test]
        fn prop_p_plus_neg_p_is_identity(seed in any::<u64>()) {
            let backend = HostBackend::new();
            let p = g1_from_seed(seed);
            let neg_p = negate_g1(&p);
            let sum = add_g1(&backend, &p, &neg_p).unwrap();
            prop_assert_eq!(sum, G1_ZERO);
        }

        /// Single-term MSM collapses to the underlying scalar_mul.
        #[test]
        fn prop_msm_one_term_equals_scalar_mul(point_seed in any::<u64>(), scalar_seed in any::<u64>()) {
            let backend = HostBackend::new();
            let p = g1_from_seed(point_seed);
            let k = fr_from_seed(scalar_seed);
            let k_bytes = {
                let mut le = k.into_bigint().to_bytes_le();
                le.resize(32, 0);
                le.reverse();
                let mut out = [0u8; 32];
                out.copy_from_slice(&le);
                out
            };

            let direct = scalar_mul_g1(&backend, &p, &k_bytes).unwrap();
            let via_msm = msm_g1(&backend, &[&p], &[k_bytes]).unwrap();
            prop_assert_eq!(direct, via_msm);
        }

        /// Any point × 0 = identity. Tests the scalar_mul edge case
        /// that sometimes surprises syscall implementations.
        #[test]
        fn prop_scalar_mul_by_zero_is_identity(seed in any::<u64>()) {
            let backend = HostBackend::new();
            let p = g1_from_seed(seed);
            let zero_scalar = [0u8; 32];
            let product = scalar_mul_g1(&backend, &p, &zero_scalar).unwrap();
            prop_assert_eq!(product, G1_ZERO);
        }
    }
}
