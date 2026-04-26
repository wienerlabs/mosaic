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
use mosaic_core::OnChainError;

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
}
