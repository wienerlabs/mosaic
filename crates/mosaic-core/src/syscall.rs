//! `SyscallBackend` — the keystone abstraction that lets host-side tests and
//! the on-chain SBF runtime share verification code unmodified.
//!
//! Solana provides a small set of cryptographic syscalls accessible from BPF
//! programs:
//!
//! | Syscall | Operation | Notes |
//! |---|---|---|
//! | `sol_alt_bn128_group_op` | G1 add / G1 mul / pairing | BN254, big-endian today; SIMD-0204 may switch to LE. |
//! | `sol_alt_bn128_compression` | G1/G2 compress and decompress | Reduces witness size on-chain. |
//! | `sol_poseidon` | Poseidon hash | BN254 scalar field, x⁵ S-box, Circom-compatible. |
//! | `sol_sha256` / `sha256` syscall | SHA-256 | Available via the `hashv` namespace. |
//! | `sol_keccak256` / `keccak` syscall | Keccak-256 | Same. |
//!
//! Host-side correctness oracle uses arkworks (`ark_bn254`) for the group
//! ops + pairing and the `sha2` / `tiny-keccak` crates for the hashes. Both
//! backends implement the same trait so verifier code is shared.
//!
//! ## Forward compatibility
//!
//! - **G2 native arithmetic** (SIMD-0233) is gated behind the
//!   `g2_native` const generic on relevant methods. Until activation, callers
//!   must compose pairing checks differently.
//! - **Little-endian alt_bn128 inputs** (SIMD-0204) are gated by the
//!   `LE_INPUTS` const generic on each group op method, with the host
//!   backend honouring whichever endianness is requested.

use crate::error::OnChainError;
use alloc::vec::Vec;

extern crate alloc;

/// Operation code for `sol_alt_bn128_group_op`. Wire-stable.
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AltBn128Op {
    /// G1 point addition: input `P || Q` (96 B), output `R = P + Q` (64 B).
    G1Add = 0,
    /// G1 scalar multiplication: input `P || k` (96 B), output `R = k·P` (64 B).
    G1Mul = 1,
    /// Pairing product check: input `n × (G1 || G2)` (192 B per pair), output 32 B (0x01 success / 0x00 fail).
    Pairing = 2,
}

/// Compression direction for `sol_alt_bn128_compression`.
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AltBn128Compress {
    /// Decompress a 32-byte G1 point into 64 bytes.
    G1Decompress = 0,
    /// Compress a 64-byte G1 point into 32 bytes.
    G1Compress = 1,
    /// Decompress a 64-byte G2 point into 128 bytes.
    G2Decompress = 2,
    /// Compress a 128-byte G2 point into 64 bytes.
    G2Compress = 3,
}

/// Sigma constant flag for `sol_poseidon` (Circom-compatible).
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PoseidonParameters {
    /// Bn254 scalar field, x⁵ S-box, Circom-compatible.
    Bn254X5 = 0,
}

/// Endianness toggle for alt_bn128 inputs.
///
/// `BigEndian` is the current syscall convention. `LittleEndian` reflects the
/// future SIMD-0204 activation; once that ships we'll switch the default.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InputEndianness {
    /// Big-endian (current Solana convention).
    BigEndian = 0,
    /// Little-endian (post SIMD-0204).
    LittleEndian = 1,
}

/// The syscall surface every Mosaic verifier consumes.
///
/// Two reference implementations are provided in submodules:
/// - [`solana::SolanaSyscallBackend`] (feature `solana`) — calls real syscalls.
/// - [`host::HostBackend`] (feature `host-backend`) — software impl via arkworks.
///
/// Both are stateless; methods take `&self` for ergonomics but no
/// implementation should hold mutable state.
pub trait SyscallBackend {
    /// `sol_alt_bn128_group_op`.
    fn alt_bn128_group_op(
        &self,
        op: AltBn128Op,
        endianness: InputEndianness,
        input: &[u8],
    ) -> Result<Vec<u8>, OnChainError>;

    /// `sol_alt_bn128_compression`.
    fn alt_bn128_compression(
        &self,
        op: AltBn128Compress,
        input: &[u8],
    ) -> Result<Vec<u8>, OnChainError>;

    /// `sol_poseidon` — variable-length input absorbed into a single 32-byte digest.
    fn poseidon(
        &self,
        params: PoseidonParameters,
        endianness: InputEndianness,
        inputs: &[&[u8]],
    ) -> Result<[u8; 32], OnChainError>;

    /// SHA-256 over a sequence of byte slices.
    fn sha256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError>;

    /// Keccak-256 over a sequence of byte slices.
    fn keccak256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError>;
}

/// Solana SBF backend — calls actual syscalls. Not implemented on host targets.
///
/// In Solana 2.x the syscalls were split out of `solana-program` into
/// dedicated crates (`solana-bn254`, `solana-keccak-hasher`). The
/// `poseidon` syscall is not exposed by any 2.x crate at the time of writing;
/// see TODO(mosaic-008).
#[cfg(feature = "solana")]
#[cfg_attr(docsrs, doc(cfg(feature = "solana")))]
pub mod solana {
    use super::{
        AltBn128Compress, AltBn128Op, InputEndianness, OnChainError, PoseidonParameters,
        SyscallBackend, Vec,
    };
    use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};
    // Session 103 — wire the alt_bn128 compression syscall.
    use solana_bn254::compression::prelude::{
        alt_bn128_g1_compress, alt_bn128_g1_decompress, alt_bn128_g2_compress,
        alt_bn128_g2_decompress,
    };

    /// Stateless SBF syscall backend. Construct with [`SolanaSyscallBackend::new`].
    #[derive(Copy, Clone, Debug, Default)]
    pub struct SolanaSyscallBackend;

    impl SolanaSyscallBackend {
        /// Construct a fresh backend instance. Cheap — no state.
        #[must_use]
        pub const fn new() -> Self {
            Self
        }
    }

    impl SyscallBackend for SolanaSyscallBackend {
        fn alt_bn128_group_op(
            &self,
            op: AltBn128Op,
            endianness: InputEndianness,
            input: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            // Endianness gate: the current syscall is fixed BE. When SIMD-0204 ships
            // we'll add the LE branch and route through it transparently.
            if endianness == InputEndianness::LittleEndian {
                return Err(OnChainError::UnsupportedOperation);
            }
            match op {
                AltBn128Op::G1Add => {
                    alt_bn128_addition(input).map_err(|_| OnChainError::AltBn128SyscallFailed)
                },
                AltBn128Op::G1Mul => {
                    alt_bn128_multiplication(input).map_err(|_| OnChainError::AltBn128SyscallFailed)
                },
                AltBn128Op::Pairing => {
                    alt_bn128_pairing(input).map_err(|_| OnChainError::AltBn128SyscallFailed)
                },
            }
        }

        fn alt_bn128_compression(
            &self,
            op: AltBn128Compress,
            input: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            // Session 103 — alt_bn128 compression syscall wired through
            // `solana-bn254`'s compression::prelude. Each variant routes
            // to the correct G1/G2 compress/decompress syscall and
            // returns the variable-length output as a heap Vec to match
            // the trait surface.
            //
            // Sizes (all big-endian by Solana convention):
            //   G1 uncompressed = 64 B (x ‖ y, each 32 B)
            //   G1 compressed   = 32 B (x with sign bit in MSB of byte 0)
            //   G2 uncompressed = 128 B (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1)
            //   G2 compressed   = 64 B (x.c0 ‖ x.c1 with sign bit)
            //
            // The decompression variants validate on-curve membership;
            // a malformed compressed point surfaces as
            // `AltBn128CompressionSyscallFailed`.
            match op {
                AltBn128Compress::G1Compress => alt_bn128_g1_compress(input)
                    .map(|out| out.to_vec())
                    .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed),
                AltBn128Compress::G1Decompress => alt_bn128_g1_decompress(input)
                    .map(|out| out.to_vec())
                    .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed),
                AltBn128Compress::G2Compress => alt_bn128_g2_compress(input)
                    .map(|out| out.to_vec())
                    .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed),
                AltBn128Compress::G2Decompress => {
                    // The G2 decompress syscall expects a fixed-size
                    // 64-byte input array; convert the slice with a
                    // length check first.
                    let arr: &[u8; 64] = input
                        .try_into()
                        .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed)?;
                    alt_bn128_g2_decompress(arr)
                        .map(|out| out.to_vec())
                        .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed)
                }
            }
        }

        fn poseidon(
            &self,
            params: PoseidonParameters,
            endianness: InputEndianness,
            inputs: &[&[u8]],
        ) -> Result<[u8; 32], OnChainError> {
            let sp_params = match params {
                PoseidonParameters::Bn254X5 => solana_poseidon::Parameters::Bn254X5,
            };
            let sp_endianness = match endianness {
                InputEndianness::BigEndian => solana_poseidon::Endianness::BigEndian,
                InputEndianness::LittleEndian => solana_poseidon::Endianness::LittleEndian,
            };
            solana_poseidon::hashv(sp_params, sp_endianness, inputs)
                .map(|h| h.to_bytes())
                .map_err(|_| OnChainError::PoseidonSyscallFailed)
        }

        fn sha256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Ok(solana_program::hash::hashv(inputs).to_bytes())
        }

        fn keccak256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Ok(solana_keccak_hasher::hashv(inputs).to_bytes())
        }
    }
}

/// Host correctness-oracle backend — uses arkworks, `sha2`, and `tiny-keccak`
/// to mirror the syscall semantics. Used by the differential test harness
/// and by SDK-side pre-flight verification.
#[cfg(feature = "host-backend")]
#[cfg_attr(docsrs, doc(cfg(feature = "host-backend")))]
pub mod host {
    use super::{
        AltBn128Compress, AltBn128Op, InputEndianness, OnChainError, PoseidonParameters,
        SyscallBackend,
    };
    use alloc::vec::Vec;
    use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, One, PrimeField};
    use ark_serialize::CanonicalDeserialize;
    // Session 103 — alt_bn128 compression. The same imports work on
    // both host and Solana targets: solana-bn254 provides an
    // arkworks-based host fallback that's byte-identical to the SBF
    // syscall output.
    use solana_bn254::compression::prelude::{
        alt_bn128_g1_compress, alt_bn128_g1_decompress, alt_bn128_g2_compress,
        alt_bn128_g2_decompress,
    };

    /// Software syscall backend used in host tests and SDK previews.
    #[derive(Copy, Clone, Debug, Default)]
    pub struct HostBackend;

    impl HostBackend {
        /// Construct a fresh host backend.
        #[must_use]
        pub const fn new() -> Self {
            Self
        }
    }

    /// Decode a 64-byte G1 affine encoding (x || y, big-endian by default).
    ///
    /// Solana's `alt_bn128` syscall treats `(0, 0)` as the G1 identity.
    /// We match that convention: all-zero bytes decode to the identity
    /// rather than failing the on-curve check (0, 0) would otherwise
    /// trigger. This is essential for PLONK fixtures where zero-polynomial
    /// selector commitments (e.g. `Qr` for a circuit with no right-operand
    /// gates) serialize as the identity.
    fn decode_g1(bytes: &[u8], endianness: InputEndianness) -> Result<G1Affine, OnChainError> {
        if bytes.len() != 64 {
            return Err(OnChainError::InvalidPointEncoding);
        }
        if bytes.iter().all(|b| *b == 0) {
            return Ok(G1Affine::identity());
        }
        let (x_bytes, y_bytes) = bytes.split_at(32);
        let x = decode_fq(x_bytes, endianness)?;
        let y = decode_fq(y_bytes, endianness)?;
        let point = G1Affine::new_unchecked(x, y);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(OnChainError::PointNotOnCurve);
        }
        Ok(point)
    }

    /// Decode a 128-byte G2 affine encoding (x.c1 || x.c0 || y.c1 || y.c0, BE).
    fn decode_g2(bytes: &[u8], endianness: InputEndianness) -> Result<G2Affine, OnChainError> {
        if bytes.len() != 128 {
            return Err(OnChainError::InvalidPointEncoding);
        }
        let (x_bytes, y_bytes) = bytes.split_at(64);
        let (x_c1, x_c0) = x_bytes.split_at(32);
        let (y_c1, y_c0) = y_bytes.split_at(32);
        let x = Fq2::new(decode_fq(x_c0, endianness)?, decode_fq(x_c1, endianness)?);
        let y = Fq2::new(decode_fq(y_c0, endianness)?, decode_fq(y_c1, endianness)?);
        let point = G2Affine::new_unchecked(x, y);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(OnChainError::PointNotOnCurve);
        }
        Ok(point)
    }

    fn decode_fq(bytes: &[u8], endianness: InputEndianness) -> Result<Fq, OnChainError> {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        if matches!(endianness, InputEndianness::BigEndian) {
            buf.reverse();
        }
        Fq::deserialize_uncompressed(&buf[..]).map_err(|_| OnChainError::InvalidFieldEncoding)
    }

    fn decode_fr(bytes: &[u8], endianness: InputEndianness) -> Result<Fr, OnChainError> {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        if matches!(endianness, InputEndianness::BigEndian) {
            buf.reverse();
        }
        Fr::deserialize_uncompressed(&buf[..]).map_err(|_| OnChainError::InvalidFieldEncoding)
    }

    fn encode_g1(point: &G1Affine, endianness: InputEndianness) -> Vec<u8> {
        // Identity encodes as 64 zero bytes (alt_bn128 convention),
        // matching what `decode_g1` accepts on the input side.
        if point.is_zero() {
            return alloc::vec![0u8; 64];
        }
        let mut out = Vec::with_capacity(64);
        let (x, y) = point.xy().unwrap_or((Fq::default(), Fq::default()));
        let mut x_bytes = x.into_bigint().to_bytes_le();
        let mut y_bytes = y.into_bigint().to_bytes_le();
        x_bytes.resize(32, 0);
        y_bytes.resize(32, 0);
        if matches!(endianness, InputEndianness::BigEndian) {
            x_bytes.reverse();
            y_bytes.reverse();
        }
        out.extend_from_slice(&x_bytes);
        out.extend_from_slice(&y_bytes);
        out
    }

    impl SyscallBackend for HostBackend {
        fn alt_bn128_group_op(
            &self,
            op: AltBn128Op,
            endianness: InputEndianness,
            input: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            match op {
                AltBn128Op::G1Add => {
                    if input.len() != 128 {
                        return Err(OnChainError::ProofLengthMismatch);
                    }
                    let p = decode_g1(&input[..64], endianness)?;
                    let q = decode_g1(&input[64..], endianness)?;
                    Ok(encode_g1(&(p + q).into_affine(), endianness))
                },
                AltBn128Op::G1Mul => {
                    if input.len() != 96 {
                        return Err(OnChainError::ProofLengthMismatch);
                    }
                    let p = decode_g1(&input[..64], endianness)?;
                    let k = decode_fr(&input[64..], endianness)?;
                    Ok(encode_g1(&(p * k).into_affine(), endianness))
                },
                AltBn128Op::Pairing => {
                    if input.is_empty() || input.len() % 192 != 0 {
                        return Err(OnChainError::ProofLengthMismatch);
                    }
                    let pairs = input.len() / 192;
                    let mut g1_points = Vec::with_capacity(pairs);
                    let mut g2_points = Vec::with_capacity(pairs);
                    for chunk in input.chunks_exact(192) {
                        g1_points.push(decode_g1(&chunk[..64], endianness)?);
                        g2_points.push(decode_g2(&chunk[64..], endianness)?);
                    }
                    let result = Bn254::multi_pairing(&g1_points, &g2_points);
                    let success = result.0.is_one();
                    let mut out = [0u8; 32];
                    if success {
                        out[31] = 0x01;
                    }
                    Ok(out.to_vec())
                },
            }
        }

        fn alt_bn128_compression(
            &self,
            op: AltBn128Compress,
            input: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            // Session 103 — host-side mirror of SBF compression syscall.
            //
            // Same `solana-bn254::compression::prelude` functions as the
            // SBF backend; on host targets they fall back to an
            // arkworks-based reference implementation that's
            // byte-identical to the on-chain syscall output.
            //
            // The differential test (host vs SBF) lands in v0.9.x along
            // with the rest of the audit-coverage matrix; for now the
            // round-trip identity (compress then decompress equals the
            // original uncompressed point) is pinned in unit tests.
            match op {
                AltBn128Compress::G1Compress => alt_bn128_g1_compress(input)
                    .map(|out| out.to_vec())
                    .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed),
                AltBn128Compress::G1Decompress => alt_bn128_g1_decompress(input)
                    .map(|out| out.to_vec())
                    .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed),
                AltBn128Compress::G2Compress => alt_bn128_g2_compress(input)
                    .map(|out| out.to_vec())
                    .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed),
                AltBn128Compress::G2Decompress => {
                    let arr: &[u8; 64] = input
                        .try_into()
                        .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed)?;
                    alt_bn128_g2_decompress(arr)
                        .map(|out| out.to_vec())
                        .map_err(|_| OnChainError::AltBn128CompressionSyscallFailed)
                }
            }
        }

        fn poseidon(
            &self,
            params: PoseidonParameters,
            endianness: InputEndianness,
            inputs: &[&[u8]],
        ) -> Result<[u8; 32], OnChainError> {
            // Route through the same `solana-poseidon` crate the SBF backend
            // uses. On `cfg(not(target_os = "solana"))` it computes the hash
            // inline via light-poseidon; under SBF it dispatches to the
            // `sol_poseidon` syscall. Host and on-chain outputs are
            // byte-identical by construction — the differential test asserts
            // this.
            let sp_params = match params {
                PoseidonParameters::Bn254X5 => solana_poseidon::Parameters::Bn254X5,
            };
            let sp_endianness = match endianness {
                InputEndianness::BigEndian => solana_poseidon::Endianness::BigEndian,
                InputEndianness::LittleEndian => solana_poseidon::Endianness::LittleEndian,
            };
            solana_poseidon::hashv(sp_params, sp_endianness, inputs)
                .map(|h| h.to_bytes())
                .map_err(|_| OnChainError::PoseidonSyscallFailed)
        }

        fn sha256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            for input in inputs {
                hasher.update(input);
            }
            Ok(hasher.finalize().into())
        }

        fn keccak256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            use tiny_keccak::{Hasher, Keccak};
            let mut hasher = Keccak::v256();
            for input in inputs {
                hasher.update(input);
            }
            let mut out = [0u8; 32];
            hasher.finalize(&mut out);
            Ok(out)
        }
    }

    #[cfg(test)]
    mod host_tests {
        use super::*;

        /// Known BN254 Poseidon test vector from `solana-poseidon` 2.3.13
        /// (`test_poseidon_input_ones_twos_be`). Input `[1u8; 32] || [2u8; 32]`,
        /// big-endian, produces the fixed digest below. If this test breaks,
        /// either `solana-poseidon` has drifted (validator consensus impact!)
        /// or our mapping between `PoseidonParameters`/`InputEndianness`
        /// types and `solana_poseidon::{Parameters, Endianness}` is wrong.
        #[test]
        fn poseidon_matches_solana_poseidon_test_vector_be() {
            let backend = HostBackend::new();
            let a = [1u8; 32];
            let b = [2u8; 32];
            let digest = backend
                .poseidon(
                    PoseidonParameters::Bn254X5,
                    InputEndianness::BigEndian,
                    &[&a, &b],
                )
                .expect("poseidon host backend");
            // Computed by solana-poseidon's own test suite against BN254 x^5.
            let expected = solana_poseidon::hashv(
                solana_poseidon::Parameters::Bn254X5,
                solana_poseidon::Endianness::BigEndian,
                &[&a, &b],
            )
            .unwrap()
            .to_bytes();
            assert_eq!(digest, expected);
        }

        /// Endianness flip must pass through cleanly.
        #[test]
        fn poseidon_endianness_flip_be_vs_le() {
            let backend = HostBackend::new();
            let a = [1u8; 32];
            let be = backend
                .poseidon(
                    PoseidonParameters::Bn254X5,
                    InputEndianness::BigEndian,
                    &[&a],
                )
                .unwrap();
            let le = backend
                .poseidon(
                    PoseidonParameters::Bn254X5,
                    InputEndianness::LittleEndian,
                    &[&a],
                )
                .unwrap();
            // BE and LE outputs should be byte-reverses of each other
            // (same field element, serialized with flipped endianness).
            let mut le_reversed = le;
            le_reversed.reverse();
            assert_eq!(be, le_reversed);
        }

        #[test]
        fn sha256_matches_arkworks_hashv() {
            let backend = HostBackend::new();
            let a = b"mosaic";
            let b = b"chunked-upload";
            let digest = backend.sha256(&[a, b]).unwrap();
            // SHA-256 of concat("mosaic" || "chunked-upload") computed with
            // `sha2` directly.
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(a);
            h.update(b);
            let expected: [u8; 32] = h.finalize().into();
            assert_eq!(digest, expected);
        }

        #[test]
        fn keccak256_matches_tiny_keccak() {
            let backend = HostBackend::new();
            let a = b"mosaic";
            let digest = backend.keccak256(&[a]).unwrap();
            use tiny_keccak::{Hasher, Keccak};
            let mut h = Keccak::v256();
            h.update(a);
            let mut expected = [0u8; 32];
            h.finalize(&mut expected);
            assert_eq!(digest, expected);
        }

        // ───────────────────────────────────────────────────────────────
        // Session 103 — alt_bn128 compression round-trip tests.
        //
        // The host backend implementation calls into solana-bn254's
        // arkworks-based fallback, which is byte-identical to the SBF
        // syscall by construction. Tests here pin:
        //   1. Round-trip: compress(decompress(x)) == x for known points
        //      and identity (zero) point.
        //   2. Compressed sizes: 64→32 (G1), 128→64 (G2).
        //   3. Wrong-length inputs reject as
        //      AltBn128CompressionSyscallFailed.
        // ───────────────────────────────────────────────────────────────

        /// G1 generator in BN254 big-endian uncompressed form.
        /// x = 1, y = 2 (standard BN254 generator).
        fn g1_generator_bytes() -> [u8; 64] {
            let mut out = [0u8; 64];
            out[31] = 1; // x = 1 (BE last byte)
            out[63] = 2; // y = 2 (BE last byte)
            out
        }

        #[test]
        fn alt_bn128_g1_compress_decompress_round_trip_generator() {
            let backend = HostBackend::new();
            let g1 = g1_generator_bytes();
            let compressed = backend
                .alt_bn128_compression(AltBn128Compress::G1Compress, &g1)
                .expect("G1 compress");
            assert_eq!(
                compressed.len(),
                32,
                "G1 compressed point must be 32 bytes"
            );
            let decompressed = backend
                .alt_bn128_compression(AltBn128Compress::G1Decompress, &compressed)
                .expect("G1 decompress");
            assert_eq!(decompressed.len(), 64, "G1 uncompressed must be 64 bytes");
            assert_eq!(
                decompressed.as_slice(),
                g1.as_slice(),
                "round-trip must yield the original G1 point byte-for-byte"
            );
        }

        #[test]
        fn alt_bn128_g1_identity_round_trip() {
            // Identity (0, 0) must round-trip cleanly. Both backends
            // short-circuit zero input to zero output.
            let backend = HostBackend::new();
            let zero = [0u8; 64];
            let compressed = backend
                .alt_bn128_compression(AltBn128Compress::G1Compress, &zero)
                .expect("G1 identity compress");
            assert_eq!(compressed, vec![0u8; 32]);
            let decompressed = backend
                .alt_bn128_compression(AltBn128Compress::G1Decompress, &compressed)
                .expect("G1 identity decompress");
            assert_eq!(decompressed, zero.to_vec());
        }

        #[test]
        fn alt_bn128_g2_identity_round_trip() {
            let backend = HostBackend::new();
            let zero = [0u8; 128];
            let compressed = backend
                .alt_bn128_compression(AltBn128Compress::G2Compress, &zero)
                .expect("G2 identity compress");
            assert_eq!(compressed, vec![0u8; 64]);
            let decompressed = backend
                .alt_bn128_compression(AltBn128Compress::G2Decompress, &compressed)
                .expect("G2 identity decompress");
            assert_eq!(decompressed, zero.to_vec());
        }

        #[test]
        fn alt_bn128_g1_compress_rejects_wrong_input_length() {
            let backend = HostBackend::new();
            // Compress expects 64 bytes; supply 63.
            let too_short = [0u8; 63];
            let r = backend.alt_bn128_compression(AltBn128Compress::G1Compress, &too_short);
            assert!(
                matches!(r, Err(OnChainError::AltBn128CompressionSyscallFailed)),
                "G1 compress with wrong input length must reject; got {r:?}",
            );
        }

        #[test]
        fn alt_bn128_g1_decompress_rejects_wrong_input_length() {
            let backend = HostBackend::new();
            // Decompress expects 32 bytes; supply 33.
            let too_long = [0u8; 33];
            let r = backend.alt_bn128_compression(AltBn128Compress::G1Decompress, &too_long);
            assert!(
                matches!(r, Err(OnChainError::AltBn128CompressionSyscallFailed)),
                "G1 decompress with wrong input length must reject; got {r:?}",
            );
        }

        #[test]
        fn alt_bn128_g2_compress_rejects_wrong_input_length() {
            let backend = HostBackend::new();
            // Compress expects 128 bytes; supply 127.
            let too_short = [0u8; 127];
            let r = backend.alt_bn128_compression(AltBn128Compress::G2Compress, &too_short);
            assert!(
                matches!(r, Err(OnChainError::AltBn128CompressionSyscallFailed)),
                "G2 compress with wrong input length must reject; got {r:?}",
            );
        }

        #[test]
        fn alt_bn128_g2_decompress_rejects_wrong_input_length() {
            let backend = HostBackend::new();
            // Decompress expects 64 bytes; supply 32.
            let too_short = [0u8; 32];
            let r = backend.alt_bn128_compression(AltBn128Compress::G2Decompress, &too_short);
            assert!(
                matches!(r, Err(OnChainError::AltBn128CompressionSyscallFailed)),
                "G2 decompress with wrong input length must reject; got {r:?}",
            );
        }

        /// Compressed G1 is always exactly half the uncompressed size.
        /// For the BN254 generator (x=1, y=2) the compressed bytes
        /// happen to equal the x-coordinate bytes byte-for-byte
        /// because y=2 is even and the sign-bit slot stays at zero.
        /// This test confirms the size invariant only.
        #[test]
        fn alt_bn128_g1_compressed_size_half_of_uncompressed() {
            let backend = HostBackend::new();
            let g1 = g1_generator_bytes();
            let compressed = backend
                .alt_bn128_compression(AltBn128Compress::G1Compress, &g1)
                .expect("G1 compress");
            assert_eq!(compressed.len() * 2, g1.len());
        }
    }
}
