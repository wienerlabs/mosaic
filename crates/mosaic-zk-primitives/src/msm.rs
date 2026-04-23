//! Multi-scalar multiplication over G1 via [`SyscallBackend`].
//!
//! ## What this is for
//!
//! PLONK's linearization polynomial [r]_1 is reconstructed as a big
//! sum of `coeff_i · Commitment_i` terms. The same pattern shows up
//! in Groth16's public-input MSM (IC[0] + Σ pi_i · IC[i+1]) and in
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

/// BN254 alt_bn128 2-pair pairing identity check: returns `Ok(())`
/// when `e(p1_g1, p1_g2) · e(p2_g1, p2_g2) == 1` in the Fq12 target,
/// `Err(PairingCheckFailed)` otherwise.
///
/// Wire encoding (big-endian, per Solana alt_bn128 convention):
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
pub fn verify_two_pair_pairing<B: SyscallBackend + ?Sized>(
    backend: &B,
    p1_g1: &[u8; 64],
    p1_g2: &[u8],
    p2_g1: &[u8; 64],
    p2_g2: &[u8],
) -> Result<(), OnChainError> {
    const G2_LEN: usize = 128;
    if p1_g2.len() != G2_LEN || p2_g2.len() != G2_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let mut input: Vec<u8> = Vec::with_capacity(2 * (64 + G2_LEN));
    input.extend_from_slice(p1_g1);
    input.extend_from_slice(p1_g2);
    input.extend_from_slice(p2_g1);
    input.extend_from_slice(p2_g2);
    let result = backend.alt_bn128_group_op(
        AltBn128Op::Pairing,
        InputEndianness::BigEndian,
        &input,
    )?;
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
    let out = backend.alt_bn128_group_op(
        AltBn128Op::G1Mul,
        InputEndianness::BigEndian,
        &input,
    )?;
    if out.len() != 64 {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut result = [0u8; 64];
    result.copy_from_slice(&out);
    Ok(result)
}

/// G1 point addition: `P + Q`. Wraps the syscall with wire-format
/// length checks.
pub fn add_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    a: &[u8; 64],
    b: &[u8; 64],
) -> Result<[u8; 64], OnChainError> {
    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    let out = backend.alt_bn128_group_op(
        AltBn128Op::G1Add,
        InputEndianness::BigEndian,
        &input,
    )?;
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
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
    ];
    let mut out = *point;
    let y_slice = &mut out[32..64];
    // If y == 0, negation is identity.
    if y_slice.iter().all(|b| *b == 0) {
        return out;
    }
    // (q - y) mod q via big-endian borrow-subtraction.
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let q_b = i16::from(BN254_FQ_MODULUS_BE[i]);
        let y_b = i16::from(y_slice[i]);
        let diff = q_b - y_b - borrow;
        if diff < 0 {
            y_slice[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            y_slice[i] = diff as u8;
            borrow = 0;
        }
    }
    // q > y by construction for any valid point, so borrow must be 0.
    debug_assert_eq!(borrow, 0, "negate_g1 saw y > q");
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
        let (x, y) = point.xy().unwrap_or((ark_bn254::Fq::default(), ark_bn254::Fq::default()));
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
            let points_proj: Vec<G1Projective> =
                (0..n_points).map(|_| G1Projective::rand(&mut rng)).collect();
            let scalars_fr: Vec<Fr> = (0..n_points).map(|_| Fr::rand(&mut rng)).collect();

            let points_aff: Vec<G1Affine> = points_proj.iter().map(|p| p.into_affine()).collect();
            let points_bytes: Vec<[u8; 64]> =
                points_aff.iter().map(ark_g1_to_canonical).collect();
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
}
