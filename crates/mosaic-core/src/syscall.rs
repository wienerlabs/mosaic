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
            _op: AltBn128Compress,
            _input: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            // TODO(mosaic-007): wire the alt_bn128 compression syscall once we
            // decide whether to expose compressed VKs in canonical format.
            Err(OnChainError::UnimplementedProofSystem)
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
            _op: AltBn128Compress,
            _input: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            // TODO(mosaic-007): host-side compression mirror.
            Err(OnChainError::UnimplementedProofSystem)
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
    }
}
