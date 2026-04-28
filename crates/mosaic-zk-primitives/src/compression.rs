//! BN254 G1/G2 point compression helpers — wraps the
//! `alt_bn128_compression` syscall surface in verifier-friendly
//! signatures that work with the workspace's canonical
//! `[u8; G1_LEN]` / `[u8; G2_LEN]` types.
//!
//! ## Format
//!
//! BN254 affine points have two encodings:
//!
//! - **Uncompressed**: `(x, y)` concatenated.
//!   - G1: 32 + 32 = 64 bytes.
//!   - G2: 64 + 64 = 128 bytes.
//! - **Compressed**: `x` only, with the `y` sign bit packed into the
//!   most-significant bit of the first byte.
//!   - G1: 32 bytes.
//!   - G2: 64 bytes.
//!
//! Solana convention is big-endian; both
//! [`mosaic_core::syscall::SyscallBackend::alt_bn128_compression`]
//! implementations (SBF + host) use the same wire format.
//!
//! ## Cost trade-off
//!
//! Compression (encode 64→32) costs roughly ~2 K CU on SBF — a single
//! field-element write. Decompression (32→64) costs roughly ~10 K CU
//! because it computes a square-root mod q to recover `y`.
//!
//! For a typical Halo2 proof with 5 advice + 3 quotient + 2 opening
//! G1 commits (10 × 64 = 640 bytes uncompressed, 10 × 32 = 320 bytes
//! compressed):
//!
//! - **Bytes saved**: 320 (out of Solana's 1232 B instruction-data
//!   limit — meaningful headroom for additional public inputs).
//! - **CU cost**: ~100 K (10 decompress calls).
//!
//! Whether this is worthwhile depends on transaction priority. For
//! cost-sensitive verifiers the uncompressed wire format is still
//! the default; for bandwidth-constrained submissions the compressed
//! form is now available.
//!
//! ## Identity
//!
//! Both backends short-circuit the all-zero point (G1 identity at
//! `(0, 0)`, G2 identity at `(0, 0, 0, 0)`):
//!
//! - `compress_g1(zero) == [0; 32]`
//! - `decompress_g1([0; 32]) == [0; 64]`
//!
//! Same for G2 at the larger sizes.

use mosaic_core::{
    syscall::{AltBn128Compress, SyscallBackend},
    OnChainError,
};

/// G1 affine uncompressed length (32-byte x ‖ 32-byte y, big-endian).
pub const G1_LEN: usize = 64;
/// G1 compressed length (32-byte x with sign bit in MSB).
pub const G1_COMPRESSED_LEN: usize = 32;
/// G2 affine uncompressed length (Fq2 x + Fq2 y, each 64 bytes).
pub const G2_LEN: usize = 128;
/// G2 compressed length.
pub const G2_COMPRESSED_LEN: usize = 64;

/// Compress a G1 affine point from 64 bytes to 32 bytes via the
/// `alt_bn128_compression` syscall.
///
/// ## Errors
///
/// - [`OnChainError::AltBn128CompressionSyscallFailed`] — the input
///   is not a valid on-curve G1 point, or the syscall otherwise
///   rejected the input.
/// - [`OnChainError::InternalInvariantViolation`] — the syscall
///   returned a wrong-length payload (should never happen with the
///   real SBF + host backends, but the explicit check is consensus-
///   critical defense in depth).
pub fn compress_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    point: &[u8; G1_LEN],
) -> Result<[u8; G1_COMPRESSED_LEN], OnChainError> {
    let out = backend.alt_bn128_compression(AltBn128Compress::G1Compress, point)?;
    if out.len() != G1_COMPRESSED_LEN {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut arr = [0u8; G1_COMPRESSED_LEN];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// Decompress a G1 affine point from 32 bytes to 64 bytes via the
/// `alt_bn128_compression` syscall. Recovers `y` via square-root
/// mod q from the compressed `x` + sign bit.
///
/// ## Errors
///
/// Same as [`compress_g1`].
pub fn decompress_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    compressed: &[u8; G1_COMPRESSED_LEN],
) -> Result<[u8; G1_LEN], OnChainError> {
    let out = backend.alt_bn128_compression(AltBn128Compress::G1Decompress, compressed)?;
    if out.len() != G1_LEN {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut arr = [0u8; G1_LEN];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// Compress a G2 affine point from 128 bytes to 64 bytes via the
/// `alt_bn128_compression` syscall.
///
/// ## Errors
///
/// Same as [`compress_g1`].
pub fn compress_g2<B: SyscallBackend + ?Sized>(
    backend: &B,
    point: &[u8; G2_LEN],
) -> Result<[u8; G2_COMPRESSED_LEN], OnChainError> {
    let out = backend.alt_bn128_compression(AltBn128Compress::G2Compress, point)?;
    if out.len() != G2_COMPRESSED_LEN {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut arr = [0u8; G2_COMPRESSED_LEN];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// Decompress a G2 affine point from 64 bytes to 128 bytes via the
/// `alt_bn128_compression` syscall.
///
/// ## Errors
///
/// Same as [`compress_g1`].
pub fn decompress_g2<B: SyscallBackend + ?Sized>(
    backend: &B,
    compressed: &[u8; G2_COMPRESSED_LEN],
) -> Result<[u8; G2_LEN], OnChainError> {
    let out = backend.alt_bn128_compression(AltBn128Compress::G2Decompress, compressed)?;
    if out.len() != G2_LEN {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut arr = [0u8; G2_LEN];
    arr.copy_from_slice(&out);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mosaic_core::syscall::host::HostBackend;

    /// G1 generator: x = 1, y = 2 in big-endian uncompressed form.
    fn g1_generator() -> [u8; G1_LEN] {
        let mut out = [0u8; G1_LEN];
        out[31] = 1;
        out[63] = 2;
        out
    }

    #[test]
    fn g1_round_trip_generator() {
        let backend = HostBackend::new();
        let g1 = g1_generator();
        let c = compress_g1(&backend, &g1).expect("compress");
        let d = decompress_g1(&backend, &c).expect("decompress");
        assert_eq!(d, g1, "round-trip must yield original G1");
    }

    #[test]
    fn g1_identity_round_trip() {
        let backend = HostBackend::new();
        let zero = [0u8; G1_LEN];
        let c = compress_g1(&backend, &zero).unwrap();
        assert_eq!(c, [0u8; G1_COMPRESSED_LEN]);
        let d = decompress_g1(&backend, &c).unwrap();
        assert_eq!(d, zero);
    }

    #[test]
    fn g2_identity_round_trip() {
        let backend = HostBackend::new();
        let zero = [0u8; G2_LEN];
        let c = compress_g2(&backend, &zero).unwrap();
        assert_eq!(c, [0u8; G2_COMPRESSED_LEN]);
        let d = decompress_g2(&backend, &c).unwrap();
        assert_eq!(d, zero);
    }

    /// Compression preserves the BN254 generator across multiple
    /// consecutive round-trips. Pins the determinism contract: the
    /// syscall produces the same bytes every time, regardless of
    /// previous calls.
    #[test]
    fn g1_round_trip_is_deterministic_across_iterations() {
        let backend = HostBackend::new();
        let g1 = g1_generator();
        let c1 = compress_g1(&backend, &g1).unwrap();
        let c2 = compress_g1(&backend, &g1).unwrap();
        let c3 = compress_g1(&backend, &g1).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c2, c3);
    }

    /// Compose `decompress(compress(g1)) == g1` for the BN254
    /// generator using the high-level helpers (instead of going
    /// through the syscall trait directly). Pins the helper
    /// composition contract.
    #[test]
    fn g1_helper_composition_matches_identity_function() {
        let backend = HostBackend::new();
        let g1 = g1_generator();
        let identity_via_compose = decompress_g1(
            &backend,
            &compress_g1(&backend, &g1).unwrap(),
        )
        .unwrap();
        assert_eq!(identity_via_compose, g1);
    }

    /// Tampering a single bit of a compressed G1 point either yields
    /// a different decompressed point OR fails decompression — never
    /// silently accepts and yields the original.
    #[test]
    fn g1_compressed_bit_flip_changes_decompressed_or_rejects() {
        let backend = HostBackend::new();
        let g1 = g1_generator();
        let mut c = compress_g1(&backend, &g1).unwrap();
        // Flip a low bit in the x-coordinate (avoid the sign bit at
        // the MSB which has special meaning).
        c[16] ^= 0x01;
        let r = decompress_g1(&backend, &c);
        match r {
            Ok(d) => assert_ne!(d, g1, "tampered compressed must not decompress to original"),
            Err(_) => { /* rejected outright is also acceptable */ }
        }
    }
}
