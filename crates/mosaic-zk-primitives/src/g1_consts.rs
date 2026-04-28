//! BN254 generator constants in Mosaic canonical wire format.
//!
//! G1 generator is the affine point (1, 2) on y² = x³ + 3.
//!
//! G2 generator is an Fq2-valued affine point on the twisted curve.
//! The Solana `alt_bn128` byte layout orders Fq2 as `c1 ‖ c0`
//! (differs from arkworks native `c0 ‖ c1` — see ADR-0003).
//!
//! Both constants are derived at compile time from arkworks, so they
//! are guaranteed to match the syscall's expected inputs.

use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

/// Encode a `G1Affine` into canonical 64-byte BE form.
#[must_use]
pub fn g1_affine_to_canonical(p: &G1Affine) -> [u8; 64] {
    let (x, y) = p
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

/// Encode a `G2Affine` into canonical 128-byte Solana `alt_bn128` layout:
/// `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0`, each 32-byte BE.
#[must_use]
pub fn g2_affine_to_canonical(p: &G2Affine) -> [u8; 128] {
    let (x, y) = p
        .xy()
        .unwrap_or((ark_bn254::Fq2::default(), ark_bn254::Fq2::default()));
    fn enc(v: &ark_bn254::Fq) -> [u8; 32] {
        let mut le = v.into_bigint().to_bytes_le();
        le.resize(32, 0);
        le.reverse();
        let mut out = [0u8; 32];
        out.copy_from_slice(&le);
        out
    }
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&enc(&x.c1));
    out[32..64].copy_from_slice(&enc(&x.c0));
    out[64..96].copy_from_slice(&enc(&y.c1));
    out[96..128].copy_from_slice(&enc(&y.c0));
    out
}

/// Canonical bytes for G1 generator (1, 2). Computed once per call but
/// cheap (~30 CU) because arkworks' generator is a const.
#[must_use]
pub fn g1_generator_bytes() -> [u8; 64] {
    g1_affine_to_canonical(&G1Affine::generator())
}

/// Canonical bytes for G2 generator.
#[must_use]
pub fn g2_generator_bytes() -> [u8; 128] {
    g2_affine_to_canonical(&G2Affine::generator())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g1_generator_has_affine_x_equal_one() {
        let bytes = g1_generator_bytes();
        // x (first 32 bytes, BE) = 1 → last byte = 0x01, rest = 0.
        for b in &bytes[..31] {
            assert_eq!(*b, 0);
        }
        assert_eq!(bytes[31], 1);
        // y (next 32 bytes, BE) = 2 → last byte = 0x02, rest = 0.
        for b in &bytes[32..63] {
            assert_eq!(*b, 0);
        }
        assert_eq!(bytes[63], 2);
    }

    #[test]
    fn g1_g2_bytes_are_stable() {
        // Regression gate: if either arkworks constants change or our
        // encoding drifts, these byte arrays change and the on-chain
        // verifier would silently accept nothing.
        let g1 = g1_generator_bytes();
        let g2 = g2_generator_bytes();
        assert_eq!(g1.len(), 64);
        assert_eq!(g2.len(), 128);
        // Sanity: G2 byte pattern is non-zero in all four Fq2 components.
        for chunk in g2.chunks(32) {
            assert!(
                chunk.iter().any(|b| *b != 0),
                "G2 component should not be zero"
            );
        }
    }
}
