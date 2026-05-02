//! Canonical (Mosaic-internal) byte layout for KZG-PLONK artifacts.
//!
//! ## Wire format — `PlonkProof` (512 bytes)
//!
//! | Offset | Length | Field | Type |
//! |---|---|---|---|
//! | 0   | 64  | `a`    | G1 commitment to witness column A |
//! | 64  | 64  | `b`    | G1 commitment to witness column B |
//! | 128 | 64  | `c`    | G1 commitment to witness column C |
//! | 192 | 64  | `z`    | G1 commitment to grand-product polynomial |
//! | 256 | 64  | `t1`   | G1 commitment to quotient part 1 |
//! | 320 | 64  | `t2`   | G1 commitment to quotient part 2 |
//! | 384 | 64  | `t3`   | G1 commitment to quotient part 3 |
//! | 448 | 64  | `w_xi` | G1 opening proof at challenge `xi` |
//! | 512 | 64  | `w_xiw`| G1 opening proof at `xi · omega` |
//! | 576 | 32  | `eval_a`  | Fr evaluation of A at `xi` |
//! | 608 | 32  | `eval_b`  | Fr evaluation of B at `xi` |
//! | 640 | 32  | `eval_c`  | Fr evaluation of C at `xi` |
//! | 672 | 32  | `eval_s1` | Fr evaluation of σ1 at `xi` |
//! | 704 | 32  | `eval_s2` | Fr evaluation of σ2 at `xi` |
//! | 736 | 32  | `eval_zw` | Fr evaluation of Z at `xi · omega` |
//!
//! Total: 9 × 64 (G1) + 6 × 32 (Fr) = **768 bytes**.
//!
//! ## Wire format — `PlonkVerifyingKey`
//!
//! Fixed header (8 × G1 + 1 × G2 + scalar-field constants):
//!
//! | Offset | Length | Field | Notes |
//! |---|---|---|---|
//! | 0   | 64  | `qm_g1` | Multiplication-selector commitment |
//! | 64  | 64  | `ql_g1` | Left-operand selector |
//! | 128 | 64  | `qr_g1` | Right-operand selector |
//! | 192 | 64  | `qo_g1` | Output selector |
//! | 256 | 64  | `qc_g1` | Constant selector |
//! | 320 | 64  | `s1_g1` | Permutation σ1 |
//! | 384 | 64  | `s2_g1` | Permutation σ2 |
//! | 448 | 64  | `s3_g1` | Permutation σ3 |
//! | 512 | 128 | `x2_g2` | SRS element for pairing check |
//! | 640 | 4   | `power` (u32 LE) | Domain power, so size = 2^power |
//! | 644 | 32  | `k1`    | Non-residue 1 for permutation |
//! | 676 | 32  | `k2`    | Non-residue 2 for permutation |
//! | 708 | 32  | `omega` | Domain generator |
//! | 740 | 4   | `n_public` (u32 LE) | Number of public inputs |
//!
//! Total fixed header: **744 bytes**. No IC vector — PLONK public-input
//! handling differs from Groth16 and goes directly into the linearization.
//!
//! Layout matches the semantics of snarkjs's PLONK output; adapter layer
//! performs endianness + G2 `c0/c1` swap where needed (see ADR-0003).
//!
//! ## Phase-1 status
//!
//! This module defines the types, byte layout, and parsing code. The
//! verifier in [`crate::verifier`] returns
//! [`mosaic_core::OnChainError::UnimplementedProofSystem`] — full
//! implementation is tracked by
//! [issue #1](https://github.com/wienerlabs/mosaic/issues/1).

use alloc::vec::Vec;
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// Canonical sizes for the byte layout.
pub mod sizes {
    /// G1 affine point: 32-byte x || 32-byte y.
    pub const G1_LEN: usize = 64;
    /// G2 affine point: 128 bytes (Fq2 x and y).
    pub const G2_LEN: usize = 128;
    /// Field element (BN254 scalar field).
    pub const FR_LEN: usize = 32;
    /// Total proof length.
    pub const PROOF_LEN: usize = 9 * G1_LEN + 6 * FR_LEN; // 768
    /// VK fixed header length.
    pub const VK_HEADER_LEN: usize = 8 * G1_LEN + G2_LEN + 4 + 3 * FR_LEN + 4; // 744
}

/// Zero-copy view into a 768-byte PLONK proof.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PlonkProof<'a> {
    /// G1 commitment to witness column A.
    pub a: &'a [u8],
    /// G1 commitment to witness column B.
    pub b: &'a [u8],
    /// G1 commitment to witness column C.
    pub c: &'a [u8],
    /// G1 commitment to grand-product polynomial Z.
    pub z: &'a [u8],
    /// G1 commitment to quotient polynomial part 1.
    pub t1: &'a [u8],
    /// G1 commitment to quotient polynomial part 2.
    pub t2: &'a [u8],
    /// G1 commitment to quotient polynomial part 3.
    pub t3: &'a [u8],
    /// G1 opening proof at `xi`.
    pub w_xi: &'a [u8],
    /// G1 opening proof at `xi · omega`.
    pub w_xiw: &'a [u8],
    /// Fr evaluation of A at `xi`.
    pub eval_a: &'a [u8],
    /// Fr evaluation of B at `xi`.
    pub eval_b: &'a [u8],
    /// Fr evaluation of C at `xi`.
    pub eval_c: &'a [u8],
    /// Fr evaluation of σ1 at `xi`.
    pub eval_s1: &'a [u8],
    /// Fr evaluation of σ2 at `xi`.
    pub eval_s2: &'a [u8],
    /// Fr evaluation of Z at `xi · omega`.
    pub eval_zw: &'a [u8],
}

impl<'a> PlonkProof<'a> {
    /// Parse a canonical PLONK proof from `bytes`. Borrows; no allocation.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, OnChainError> {
        use sizes::{FR_LEN, G1_LEN, PROOF_LEN};
        if bytes.len() != PROOF_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let (a, rest) = bytes.split_at(G1_LEN);
        let (b, rest) = rest.split_at(G1_LEN);
        let (c, rest) = rest.split_at(G1_LEN);
        let (z, rest) = rest.split_at(G1_LEN);
        let (t1, rest) = rest.split_at(G1_LEN);
        let (t2, rest) = rest.split_at(G1_LEN);
        let (t3, rest) = rest.split_at(G1_LEN);
        let (w_xi, rest) = rest.split_at(G1_LEN);
        let (w_xiw, rest) = rest.split_at(G1_LEN);
        let (eval_a, rest) = rest.split_at(FR_LEN);
        let (eval_b, rest) = rest.split_at(FR_LEN);
        let (eval_c, rest) = rest.split_at(FR_LEN);
        let (eval_s1, rest) = rest.split_at(FR_LEN);
        let (eval_s2, eval_zw) = rest.split_at(FR_LEN);
        debug_assert_eq!(eval_zw.len(), FR_LEN);
        Ok(Self {
            a,
            b,
            c,
            z,
            t1,
            t2,
            t3,
            w_xi,
            w_xiw,
            eval_a,
            eval_b,
            eval_c,
            eval_s1,
            eval_s2,
            eval_zw,
        })
    }
}

/// **Session 110** — PLONK proof compression utilities.
///
/// PLONK proof shape:
///   9 G1 commits: A, B, C, Z, T1, T2, T3, W_xi, W_xiw
///   6 Fr evals:   eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw
///
/// Uncompressed: 9·64 + 6·32 = 576 + 192 = 768 bytes
/// Compressed:   9·32 + 6·32 = 288 + 192 = 480 bytes
/// Saving:       288 bytes (37.5 %)
///
/// CU cost per `decompress_to_canonical_bytes`:
///   9 × ~10 K CU = ~90 K CU. Plus the existing ~970 K CU PLONK
///   verify cost = ~9 % overhead.
impl PlonkProof<'_> {
    /// Compressed PLONK proof byte length.
    pub const COMPRESSED_LEN: usize = 9 * 32 + 6 * 32;

    /// Decompress a compressed-format PLONK proof into the canonical
    /// 768-byte uncompressed wire format.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] — input is not exactly
    ///   `COMPRESSED_LEN` (480) bytes.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any G1
    ///   commit fails decompression.
    pub fn decompress_to_canonical_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        compressed: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        use sizes::{FR_LEN, G1_LEN, PROOF_LEN};
        const G1_C: usize = 32;

        if compressed.len() != Self::COMPRESSED_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let mut out = Vec::with_capacity(PROOF_LEN);

        // Decompress 9 G1 commits in order.
        let mut o = 0;
        for _ in 0..9 {
            let mut arr = [0u8; G1_C];
            arr.copy_from_slice(&compressed[o..o + G1_C]);
            let full =
                mosaic_zk_primitives::compression::decompress_g1(backend, &arr)?;
            out.extend_from_slice(&full);
            o += G1_C;
        }
        debug_assert_eq!(out.len(), 9 * G1_LEN);

        // Copy 6 Fr evaluations as-is (not curve points, not compressed).
        out.extend_from_slice(&compressed[o..o + 6 * FR_LEN]);
        debug_assert_eq!(out.len(), PROOF_LEN);
        Ok(out)
    }

    /// Compress a canonical PLONK proof byte buffer.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] — input is not exactly
    ///   `PROOF_LEN` (768) bytes.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any G1
    ///   commit fails compression (off-curve, etc.).
    pub fn compress_from_canonical_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        canonical: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        use sizes::{FR_LEN, G1_LEN, PROOF_LEN};

        if canonical.len() != PROOF_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let mut out = Vec::with_capacity(Self::COMPRESSED_LEN);
        // Compress 9 G1 commits in order.
        let mut o = 0;
        for _ in 0..9 {
            let mut arr = [0u8; G1_LEN];
            arr.copy_from_slice(&canonical[o..o + G1_LEN]);
            let c = mosaic_zk_primitives::compression::compress_g1(backend, &arr)?;
            out.extend_from_slice(&c);
            o += G1_LEN;
        }
        // Copy 6 Fr evaluations as-is.
        out.extend_from_slice(&canonical[o..o + 6 * FR_LEN]);
        debug_assert_eq!(out.len(), Self::COMPRESSED_LEN);
        Ok(out)
    }
}

/// Canonical-format PLONK verifying key. Owns its fixed-size data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkVerifyingKey {
    /// Gate multiplication selector commitment (G1).
    pub qm_g1: [u8; sizes::G1_LEN],
    /// Left-operand selector (G1).
    pub ql_g1: [u8; sizes::G1_LEN],
    /// Right-operand selector (G1).
    pub qr_g1: [u8; sizes::G1_LEN],
    /// Output selector (G1).
    pub qo_g1: [u8; sizes::G1_LEN],
    /// Constant selector (G1).
    pub qc_g1: [u8; sizes::G1_LEN],
    /// Permutation σ1 commitment (G1).
    pub s1_g1: [u8; sizes::G1_LEN],
    /// Permutation σ2 commitment (G1).
    pub s2_g1: [u8; sizes::G1_LEN],
    /// Permutation σ3 commitment (G1).
    pub s3_g1: [u8; sizes::G1_LEN],
    /// SRS element for the pairing check (G2).
    pub x2_g2: [u8; sizes::G2_LEN],
    /// Domain power: circuit size is 2^power.
    pub power: u32,
    /// Non-residue 1 for coset evaluation.
    pub k1: [u8; sizes::FR_LEN],
    /// Non-residue 2 for coset evaluation.
    pub k2: [u8; sizes::FR_LEN],
    /// Primitive domain generator.
    pub omega: [u8; sizes::FR_LEN],
    /// Number of public inputs.
    pub n_public: u32,
}

impl PlonkVerifyingKey {
    /// Serialized fixed-header length.
    #[must_use]
    pub const fn serialized_len(&self) -> usize {
        sizes::VK_HEADER_LEN
    }

    /// Decode from canonical bytes. Validates length only; on-curve
    /// checks are deferred to the syscall layer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        use sizes::{FR_LEN, G1_LEN, G2_LEN, VK_HEADER_LEN};
        if bytes.len() != VK_HEADER_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let mut o = 0_usize;
        macro_rules! take {
            ($len:expr) => {{
                let start = o;
                o += $len;
                let slice = bytes
                    .get(start..o)
                    .ok_or(OnChainError::VerifyingKeyLengthMismatch)?;
                slice
            }};
        }
        fn copy_g1(slice: &[u8]) -> Result<[u8; G1_LEN], OnChainError> {
            let mut a = [0u8; G1_LEN];
            a.copy_from_slice(slice);
            Ok(a)
        }
        fn copy_g2(slice: &[u8]) -> Result<[u8; G2_LEN], OnChainError> {
            let mut a = [0u8; G2_LEN];
            a.copy_from_slice(slice);
            Ok(a)
        }
        fn copy_fr(slice: &[u8]) -> Result<[u8; FR_LEN], OnChainError> {
            let mut a = [0u8; FR_LEN];
            a.copy_from_slice(slice);
            Ok(a)
        }
        let qm_g1 = copy_g1(take!(G1_LEN))?;
        let ql_g1 = copy_g1(take!(G1_LEN))?;
        let qr_g1 = copy_g1(take!(G1_LEN))?;
        let qo_g1 = copy_g1(take!(G1_LEN))?;
        let qc_g1 = copy_g1(take!(G1_LEN))?;
        let s1_g1 = copy_g1(take!(G1_LEN))?;
        let s2_g1 = copy_g1(take!(G1_LEN))?;
        let s3_g1 = copy_g1(take!(G1_LEN))?;
        let x2_g2 = copy_g2(take!(G2_LEN))?;
        let power = {
            let b = take!(4);
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        };
        let k1 = copy_fr(take!(FR_LEN))?;
        let k2 = copy_fr(take!(FR_LEN))?;
        let omega = copy_fr(take!(FR_LEN))?;
        let n_public = {
            let b = take!(4);
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        };
        Ok(Self {
            qm_g1,
            ql_g1,
            qr_g1,
            qo_g1,
            qc_g1,
            s1_g1,
            s2_g1,
            s3_g1,
            x2_g2,
            power,
            k1,
            k2,
            omega,
            n_public,
        })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(sizes::VK_HEADER_LEN);
        out.extend_from_slice(&self.qm_g1);
        out.extend_from_slice(&self.ql_g1);
        out.extend_from_slice(&self.qr_g1);
        out.extend_from_slice(&self.qo_g1);
        out.extend_from_slice(&self.qc_g1);
        out.extend_from_slice(&self.s1_g1);
        out.extend_from_slice(&self.s2_g1);
        out.extend_from_slice(&self.s3_g1);
        out.extend_from_slice(&self.x2_g2);
        out.extend_from_slice(&self.power.to_le_bytes());
        out.extend_from_slice(&self.k1);
        out.extend_from_slice(&self.k2);
        out.extend_from_slice(&self.omega);
        out.extend_from_slice(&self.n_public.to_le_bytes());
        debug_assert_eq!(out.len(), sizes::VK_HEADER_LEN);
        out
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 110 — PLONK compressed VK support.
    //
    // VK shape: 8 G1 (selectors q_M/L/R/O/C + perm σ_1/2/3) + 1 G2
    //   (X_2 SRS) + Fr fields (k1, k2, omega) + u32 fields (power,
    //   n_public).
    //
    // Uncompressed: 8·64 + 128 + 3·32 + 2·4 = 512 + 128 + 96 + 8 = 744 B
    // Compressed:   8·32 + 64  + 3·32 + 2·4 = 256 + 64  + 96 + 8 = 424 B
    // Saving:       320 bytes (43 %)
    //
    // CU per from_compressed_bytes: 8 × ~10 K + 1 × ~12 K = ~92 K CU.
    // ───────────────────────────────────────────────────────────────────

    /// Compressed PLONK VK byte length: 8 compressed G1 + 1 compressed
    /// G2 + Fr/u32 fields = 424 bytes.
    pub const COMPRESSED_LEN: usize = 8 * 32 + 64 + 3 * 32 + 2 * 4;

    /// Decode a compressed-format PLONK VK byte buffer.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::VerifyingKeyLengthMismatch`] — input length
    ///   ≠ `COMPRESSED_LEN`.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   compressed point fails decompression.
    pub fn from_compressed_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        bytes: &[u8],
    ) -> Result<Self, OnChainError> {
        use sizes::FR_LEN;
        const G1_C: usize = 32;
        const G2_C: usize = 64;

        if bytes.len() != Self::COMPRESSED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        let mut o = 0_usize;
        macro_rules! decompress_g1_field {
            () => {{
                let mut arr = [0u8; G1_C];
                arr.copy_from_slice(&bytes[o..o + G1_C]);
                o += G1_C;
                mosaic_zk_primitives::compression::decompress_g1(backend, &arr)?
            }};
        }
        let qm_g1 = decompress_g1_field!();
        let ql_g1 = decompress_g1_field!();
        let qr_g1 = decompress_g1_field!();
        let qo_g1 = decompress_g1_field!();
        let qc_g1 = decompress_g1_field!();
        let s1_g1 = decompress_g1_field!();
        let s2_g1 = decompress_g1_field!();
        let s3_g1 = decompress_g1_field!();

        // G2: SRS element X_2.
        let mut x2_arr = [0u8; G2_C];
        x2_arr.copy_from_slice(&bytes[o..o + G2_C]);
        o += G2_C;
        let x2_g2 =
            mosaic_zk_primitives::compression::decompress_g2(backend, &x2_arr)?;

        // power (u32 LE)
        let power = u32::from_le_bytes([
            bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3],
        ]);
        o += 4;

        // k1, k2, omega (32-byte Fr fields)
        let mut k1 = [0u8; FR_LEN];
        k1.copy_from_slice(&bytes[o..o + FR_LEN]);
        o += FR_LEN;
        let mut k2 = [0u8; FR_LEN];
        k2.copy_from_slice(&bytes[o..o + FR_LEN]);
        o += FR_LEN;
        let mut omega = [0u8; FR_LEN];
        omega.copy_from_slice(&bytes[o..o + FR_LEN]);
        o += FR_LEN;

        // n_public (u32 LE)
        let n_public = u32::from_le_bytes([
            bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3],
        ]);

        Ok(Self {
            qm_g1,
            ql_g1,
            qr_g1,
            qo_g1,
            qc_g1,
            s1_g1,
            s2_g1,
            s3_g1,
            x2_g2,
            power,
            k1,
            k2,
            omega,
            n_public,
        })
    }

    /// Encode this VK in compressed form.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   point fails to compress (off-curve, etc.).
    pub fn to_compressed_bytes<B: SyscallBackend + ?Sized>(
        &self,
        backend: &B,
    ) -> Result<Vec<u8>, OnChainError> {
        let mut out = Vec::with_capacity(Self::COMPRESSED_LEN);

        macro_rules! compress_g1_field {
            ($field:expr) => {{
                let c = mosaic_zk_primitives::compression::compress_g1(
                    backend, &$field,
                )?;
                out.extend_from_slice(&c);
            }};
        }
        compress_g1_field!(self.qm_g1);
        compress_g1_field!(self.ql_g1);
        compress_g1_field!(self.qr_g1);
        compress_g1_field!(self.qo_g1);
        compress_g1_field!(self.qc_g1);
        compress_g1_field!(self.s1_g1);
        compress_g1_field!(self.s2_g1);
        compress_g1_field!(self.s3_g1);

        let x2_c =
            mosaic_zk_primitives::compression::compress_g2(backend, &self.x2_g2)?;
        out.extend_from_slice(&x2_c);

        out.extend_from_slice(&self.power.to_le_bytes());
        out.extend_from_slice(&self.k1);
        out.extend_from_slice(&self.k2);
        out.extend_from_slice(&self.omega);
        out.extend_from_slice(&self.n_public.to_le_bytes());

        debug_assert_eq!(out.len(), Self::COMPRESSED_LEN);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sizes::{FR_LEN, G1_LEN, G2_LEN, PROOF_LEN, VK_HEADER_LEN};

    #[test]
    fn proof_layout_constants_are_consistent() {
        assert_eq!(PROOF_LEN, 9 * G1_LEN + 6 * FR_LEN);
        assert_eq!(PROOF_LEN, 768);
    }

    #[test]
    fn vk_header_layout_constants_are_consistent() {
        assert_eq!(VK_HEADER_LEN, 8 * G1_LEN + G2_LEN + 4 + 3 * FR_LEN + 4,);
        assert_eq!(VK_HEADER_LEN, 744);
    }

    #[test]
    fn proof_view_parses_correct_slices() {
        let buf = vec![0xAB; PROOF_LEN];
        let p = PlonkProof::from_bytes(&buf).unwrap();
        assert_eq!(p.a.len(), G1_LEN);
        assert_eq!(p.b.len(), G1_LEN);
        assert_eq!(p.c.len(), G1_LEN);
        assert_eq!(p.z.len(), G1_LEN);
        assert_eq!(p.t1.len(), G1_LEN);
        assert_eq!(p.t2.len(), G1_LEN);
        assert_eq!(p.t3.len(), G1_LEN);
        assert_eq!(p.w_xi.len(), G1_LEN);
        assert_eq!(p.w_xiw.len(), G1_LEN);
        for eval in [
            p.eval_a, p.eval_b, p.eval_c, p.eval_s1, p.eval_s2, p.eval_zw,
        ] {
            assert_eq!(eval.len(), FR_LEN);
        }
    }

    #[test]
    fn proof_length_mismatch_rejected() {
        let short = vec![0u8; PROOF_LEN - 1];
        assert!(matches!(
            PlonkProof::from_bytes(&short),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn vk_roundtrip() {
        let vk = PlonkVerifyingKey {
            qm_g1: [1; G1_LEN],
            ql_g1: [2; G1_LEN],
            qr_g1: [3; G1_LEN],
            qo_g1: [4; G1_LEN],
            qc_g1: [5; G1_LEN],
            s1_g1: [6; G1_LEN],
            s2_g1: [7; G1_LEN],
            s3_g1: [8; G1_LEN],
            x2_g2: [9; G2_LEN],
            power: 11,
            k1: [10; FR_LEN],
            k2: [11; FR_LEN],
            omega: [12; FR_LEN],
            n_public: 3,
        };
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), VK_HEADER_LEN);
        let decoded = PlonkVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
    }

    #[test]
    fn vk_length_mismatch_rejected() {
        let short = vec![0u8; VK_HEADER_LEN - 1];
        assert!(matches!(
            PlonkVerifyingKey::from_bytes(&short),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 39 — proptest coverage for KZG-PLONK canonical layout.
    //
    // The PLONK proof envelope is fixed-length (768 B = 9 G1 + 6 Fr) and
    // the VK header is fixed-length (744 B = 8 G1 + G2 + 4 + 3 Fr + 4),
    // so the parameter space collapses to:
    //
    //   1. Length adversary — any byte buffer whose length differs from
    //      the canonical constant must be rejected.
    //   2. Content randomness — any random fill of the canonical length
    //      yields a parseable view (length checks are the only
    //      validation at this layer; on-curve / Fr-range checks happen
    //      downstream in the verifier).
    //   3. VK round-trip — encode then decode is the identity for any
    //      well-formed VK in our bounded shape space.
    //
    // Because there are no dynamic counters or variant tags here, the
    // test surface is smaller than for HyperPlonk / Halo2 / Nova; the
    // value is in pinning the fixed envelope so any future shape drift
    // (a new field added without bumping the constants) surfaces as a
    // proptest regression rather than a silent on-chain decode failure.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    prop_compose! {
        /// Random VK with distinct byte fills for each commit slot so a
        /// reordering bug between, say, `s2_g1` and `s3_g1` would
        /// surface as inequality after round-trip rather than
        /// silently passing.
        fn arb_vk()(
            qm in any::<u8>(),
            ql in any::<u8>(),
            qr in any::<u8>(),
            qo in any::<u8>(),
            qc in any::<u8>(),
            s1 in any::<u8>(),
            s2 in any::<u8>(),
            s3 in any::<u8>(),
            x2 in any::<u8>(),
            power in 0u32..=28,
            k1 in any::<u8>(),
            k2 in any::<u8>(),
            omega in any::<u8>(),
            n_public in 0u32..=64,
        ) -> PlonkVerifyingKey {
            PlonkVerifyingKey {
                qm_g1: [qm; G1_LEN],
                ql_g1: [ql; G1_LEN],
                qr_g1: [qr; G1_LEN],
                qo_g1: [qo; G1_LEN],
                qc_g1: [qc; G1_LEN],
                s1_g1: [s1; G1_LEN],
                s2_g1: [s2; G1_LEN],
                s3_g1: [s3; G1_LEN],
                x2_g2: [x2; G2_LEN],
                power,
                k1: [k1; FR_LEN],
                k2: [k2; FR_LEN],
                omega: [omega; FR_LEN],
                n_public,
            }
        }
    }

    proptest! {
        /// Any canonical-length byte buffer parses into a proof view
        /// whose 9 G1 + 6 Fr slice lengths match the layout. Catches
        /// off-by-one slice splits — e.g. a future refactor that
        /// shaves a byte off `eval_zw` would fail this property.
        #[test]
        fn proptest_proof_view_parses_any_canonical_payload(
            buf in proptest::collection::vec(any::<u8>(), PROOF_LEN..=PROOF_LEN),
        ) {
            let p = PlonkProof::from_bytes(&buf).expect("canonical len parses");
            for g1 in [p.a, p.b, p.c, p.z, p.t1, p.t2, p.t3, p.w_xi, p.w_xiw] {
                prop_assert_eq!(g1.len(), G1_LEN);
            }
            for fr in [p.eval_a, p.eval_b, p.eval_c, p.eval_s1, p.eval_s2, p.eval_zw] {
                prop_assert_eq!(fr.len(), FR_LEN);
            }
            // The 9 G1 + 6 Fr slices must reconstruct the original
            // buffer exactly — pin the field ordering against future
            // reorderings of `split_at` calls.
            let mut reassembled = alloc::vec::Vec::with_capacity(PROOF_LEN);
            reassembled.extend_from_slice(p.a);
            reassembled.extend_from_slice(p.b);
            reassembled.extend_from_slice(p.c);
            reassembled.extend_from_slice(p.z);
            reassembled.extend_from_slice(p.t1);
            reassembled.extend_from_slice(p.t2);
            reassembled.extend_from_slice(p.t3);
            reassembled.extend_from_slice(p.w_xi);
            reassembled.extend_from_slice(p.w_xiw);
            reassembled.extend_from_slice(p.eval_a);
            reassembled.extend_from_slice(p.eval_b);
            reassembled.extend_from_slice(p.eval_c);
            reassembled.extend_from_slice(p.eval_s1);
            reassembled.extend_from_slice(p.eval_s2);
            reassembled.extend_from_slice(p.eval_zw);
            prop_assert_eq!(reassembled, buf);
        }

        /// Any byte buffer whose length differs from `PROOF_LEN` must
        /// be rejected. Excludes the canonical length itself.
        #[test]
        fn proptest_proof_rejects_any_wrong_length(
            len in 0usize..=2 * PROOF_LEN,
        ) {
            prop_assume!(len != PROOF_LEN);
            let buf = vec![0u8; len];
            prop_assert!(matches!(
                PlonkProof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// Trailing garbage of any non-zero length must be rejected.
        /// Catches "decoder ignored trailing bytes" failure modes.
        #[test]
        fn proptest_proof_rejects_trailing_garbage(
            extra in 1usize..=64,
        ) {
            let mut buf = vec![0u8; PROOF_LEN];
            buf.extend(core::iter::repeat_n(0xDE, extra));
            prop_assert!(matches!(
                PlonkProof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// VK encode-then-decode is the identity for any well-formed
        /// VK over our bounded shape space.
        #[test]
        fn proptest_vk_roundtrip(vk in arb_vk()) {
            let bytes = vk.to_bytes();
            prop_assert_eq!(bytes.len(), VK_HEADER_LEN);
            let decoded = PlonkVerifyingKey::from_bytes(&bytes)
                .expect("well-formed VK round-trips");
            prop_assert_eq!(vk, decoded);
        }

        /// Any VK byte buffer whose length differs from `VK_HEADER_LEN`
        /// must be rejected.
        #[test]
        fn proptest_vk_rejects_any_wrong_length(
            len in 0usize..=2 * VK_HEADER_LEN,
        ) {
            prop_assume!(len != VK_HEADER_LEN);
            let buf = vec![0u8; len];
            prop_assert!(matches!(
                PlonkVerifyingKey::from_bytes(&buf),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }

        /// Trailing garbage on encoded VK bytes must be rejected.
        #[test]
        fn proptest_vk_rejects_trailing_garbage(
            vk in arb_vk(),
            extra in 1usize..=32,
        ) {
            let mut bytes = vk.to_bytes();
            bytes.extend(core::iter::repeat_n(0xFF, extra));
            prop_assert!(matches!(
                PlonkVerifyingKey::from_bytes(&bytes),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }

        /// VK named-field byte fill survives round-trip. Pins the
        /// canonical concat order: any reorder between, say, `qm_g1`
        /// and `ql_g1` in `to_bytes` / `from_bytes` would surface as
        /// a fill-byte mismatch on the named field.
        #[test]
        fn proptest_vk_named_field_fills_survive_roundtrip(vk in arb_vk()) {
            let decoded = PlonkVerifyingKey::from_bytes(&vk.to_bytes()).unwrap();
            prop_assert_eq!(decoded.qm_g1, vk.qm_g1);
            prop_assert_eq!(decoded.ql_g1, vk.ql_g1);
            prop_assert_eq!(decoded.qr_g1, vk.qr_g1);
            prop_assert_eq!(decoded.qo_g1, vk.qo_g1);
            prop_assert_eq!(decoded.qc_g1, vk.qc_g1);
            prop_assert_eq!(decoded.s1_g1, vk.s1_g1);
            prop_assert_eq!(decoded.s2_g1, vk.s2_g1);
            prop_assert_eq!(decoded.s3_g1, vk.s3_g1);
            prop_assert_eq!(decoded.x2_g2, vk.x2_g2);
            prop_assert_eq!(decoded.power, vk.power);
            prop_assert_eq!(decoded.k1, vk.k1);
            prop_assert_eq!(decoded.k2, vk.k2);
            prop_assert_eq!(decoded.omega, vk.omega);
            prop_assert_eq!(decoded.n_public, vk.n_public);
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 110 — PLONK compressed proof + VK round-trip tests.
    //
    // PLONK proof shape: 9 G1 commits + 6 Fr evals.
    //   Uncompressed: 768 B   Compressed: 480 B   Saving: 288 B (37.5 %)
    //
    // PLONK VK shape: 8 G1 + 1 G2 + Fr/u32 fields.
    //   Uncompressed: 744 B   Compressed: 424 B   Saving: 320 B (43 %)
    // ───────────────────────────────────────────────────────────────────
    mod compression {
        use super::*;
        use mosaic_core::syscall::host::HostBackend;

        fn realistic_proof() -> Vec<u8> {
            use sizes::{FR_LEN, G1_LEN, PROOF_LEN};
            let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
            let mut buf = Vec::with_capacity(PROOF_LEN);
            // 9 G1 commits.
            for _ in 0..9 {
                buf.extend_from_slice(&g1_gen);
            }
            // 6 Fr evals — leave zero for simplicity.
            buf.extend_from_slice(&[0u8; 6 * FR_LEN]);
            debug_assert_eq!(buf.len(), PROOF_LEN);
            // Sanity: each G1 commit fits exactly.
            debug_assert_eq!(g1_gen.len(), G1_LEN);
            buf
        }

        fn realistic_vk() -> PlonkVerifyingKey {
            let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
            let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
            PlonkVerifyingKey {
                qm_g1: g1_gen,
                ql_g1: g1_gen,
                qr_g1: g1_gen,
                qo_g1: g1_gen,
                qc_g1: g1_gen,
                s1_g1: g1_gen,
                s2_g1: g1_gen,
                s3_g1: g1_gen,
                x2_g2: g2_gen,
                power: 10,
                k1: [0u8; sizes::FR_LEN],
                k2: [0u8; sizes::FR_LEN],
                omega: [0u8; sizes::FR_LEN],
                n_public: 3,
            }
        }

        // ── Proof tests ─────────────────────────────────────────────

        #[test]
        fn proof_round_trip_with_real_generators() {
            let backend = HostBackend::new();
            let canonical = realistic_proof();
            let compressed =
                PlonkProof::compress_from_canonical_bytes(&backend, &canonical)
                    .expect("compress");
            assert_eq!(compressed.len(), PlonkProof::COMPRESSED_LEN);
            let decoded =
                PlonkProof::decompress_to_canonical_bytes(&backend, &compressed)
                    .expect("decompress");
            assert_eq!(decoded, canonical);
        }

        #[test]
        fn proof_compressed_size_saves_288_bytes() {
            let backend = HostBackend::new();
            let canonical = realistic_proof();
            let compressed =
                PlonkProof::compress_from_canonical_bytes(&backend, &canonical)
                    .unwrap();
            let saving = canonical.len() - compressed.len();
            // 9 G1 × 32 B = 288 B saved (Fr evals stay 32 B).
            assert_eq!(saving, 288, "expected exactly 288 B saving");
            assert_eq!(canonical.len(), 768);
            assert_eq!(compressed.len(), 480);
        }

        #[test]
        fn proof_zero_only_round_trips() {
            let backend = HostBackend::new();
            let canonical = vec![0u8; sizes::PROOF_LEN];
            let compressed =
                PlonkProof::compress_from_canonical_bytes(&backend, &canonical)
                    .unwrap();
            let decoded =
                PlonkProof::decompress_to_canonical_bytes(&backend, &compressed)
                    .unwrap();
            assert_eq!(decoded, canonical);
        }

        #[test]
        fn proof_compress_rejects_wrong_canonical_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; sizes::PROOF_LEN - 1];
            let r =
                PlonkProof::compress_from_canonical_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
        }

        #[test]
        fn proof_decompress_rejects_wrong_compressed_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; PlonkProof::COMPRESSED_LEN - 1];
            let r =
                PlonkProof::decompress_to_canonical_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
        }

        #[test]
        fn proof_decompressed_parses_via_from_bytes() {
            let backend = HostBackend::new();
            let canonical = realistic_proof();
            let compressed =
                PlonkProof::compress_from_canonical_bytes(&backend, &canonical)
                    .unwrap();
            let decoded =
                PlonkProof::decompress_to_canonical_bytes(&backend, &compressed)
                    .unwrap();
            let proof = PlonkProof::from_bytes(&decoded).expect("from_bytes parse");
            assert_eq!(proof.a.len(), sizes::G1_LEN);
            assert_eq!(proof.eval_zw.len(), sizes::FR_LEN);
        }

        // ── VK tests ───────────────────────────────────────────────

        #[test]
        fn vk_round_trip_with_real_generators() {
            let backend = HostBackend::new();
            let vk = realistic_vk();
            let compressed = vk.to_compressed_bytes(&backend).expect("compress");
            assert_eq!(compressed.len(), PlonkVerifyingKey::COMPRESSED_LEN);
            let decoded = PlonkVerifyingKey::from_compressed_bytes(
                &backend, &compressed,
            )
            .expect("decompress");
            assert_eq!(vk, decoded);
        }

        #[test]
        fn vk_compressed_size_saves_320_bytes() {
            let backend = HostBackend::new();
            let vk = realistic_vk();
            let uncompressed = vk.to_bytes();
            let compressed = vk.to_compressed_bytes(&backend).unwrap();
            // 8 G1 × 32 + 1 G2 × 64 = 256 + 64 = 320 B saved.
            // Fr/u32 fields stay unchanged.
            let saving = uncompressed.len() - compressed.len();
            assert_eq!(saving, 320, "expected exactly 320 B saving");
            assert_eq!(uncompressed.len(), 744);
            assert_eq!(compressed.len(), 424);
        }

        #[test]
        fn vk_zero_only_round_trips() {
            let backend = HostBackend::new();
            let vk = PlonkVerifyingKey {
                qm_g1: [0u8; sizes::G1_LEN],
                ql_g1: [0u8; sizes::G1_LEN],
                qr_g1: [0u8; sizes::G1_LEN],
                qo_g1: [0u8; sizes::G1_LEN],
                qc_g1: [0u8; sizes::G1_LEN],
                s1_g1: [0u8; sizes::G1_LEN],
                s2_g1: [0u8; sizes::G1_LEN],
                s3_g1: [0u8; sizes::G1_LEN],
                x2_g2: [0u8; sizes::G2_LEN],
                power: 0,
                k1: [0u8; sizes::FR_LEN],
                k2: [0u8; sizes::FR_LEN],
                omega: [0u8; sizes::FR_LEN],
                n_public: 0,
            };
            let compressed = vk.to_compressed_bytes(&backend).unwrap();
            let decoded =
                PlonkVerifyingKey::from_compressed_bytes(&backend, &compressed)
                    .unwrap();
            assert_eq!(vk, decoded);
        }

        #[test]
        fn vk_decompress_rejects_wrong_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; PlonkVerifyingKey::COMPRESSED_LEN - 1];
            let r = PlonkVerifyingKey::from_compressed_bytes(
                &backend, &too_short,
            );
            assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));

            let too_long = vec![0u8; PlonkVerifyingKey::COMPRESSED_LEN + 1];
            let r = PlonkVerifyingKey::from_compressed_bytes(
                &backend, &too_long,
            );
            assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
        }

        #[test]
        fn vk_compressed_preserves_non_curve_fields_byte_for_byte() {
            // Fr fields and u32 counters bypass compression — they
            // must round-trip byte-identical regardless of curve-point
            // arithmetic.
            let backend = HostBackend::new();
            let mut vk = realistic_vk();
            vk.power = 0xDEAD_BEEF;
            vk.n_public = 0x1234_5678;
            // Set k1/k2/omega to distinct non-zero patterns.
            vk.k1 = [0xAA; sizes::FR_LEN];
            vk.k2 = [0xBB; sizes::FR_LEN];
            vk.omega = [0xCC; sizes::FR_LEN];

            let compressed = vk.to_compressed_bytes(&backend).unwrap();
            let decoded =
                PlonkVerifyingKey::from_compressed_bytes(&backend, &compressed)
                    .unwrap();
            assert_eq!(decoded.power, 0xDEAD_BEEF);
            assert_eq!(decoded.n_public, 0x1234_5678);
            assert_eq!(decoded.k1, [0xAA; sizes::FR_LEN]);
            assert_eq!(decoded.k2, [0xBB; sizes::FR_LEN]);
            assert_eq!(decoded.omega, [0xCC; sizes::FR_LEN]);
        }
    }
}
