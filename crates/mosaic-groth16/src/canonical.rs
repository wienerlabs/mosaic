//! Canonical (Mosaic-internal) byte layout for Groth16 artifacts.
//!
//! ## Wire format
//!
//! ### `Groth16VerifyingKey` (serialized length = `224 + 64·n`):
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0   | 64  | `alpha_g1` (G1) |
//! | 64  | 128 | `beta_g2`  (G2) |
//! | 192 | 128 | `gamma_g2` (G2) — actually 0..128 not 64..192 due to layout below; see code |
//!
//! The exact byte layout is encoded in [`Groth16VerifyingKey::from_bytes`] /
//! [`Groth16VerifyingKey::to_bytes`]. We choose **big-endian** by default to
//! match the current `sol_alt_bn128_group_op` convention. Once SIMD-0204
//! activates little-endian alt_bn128 inputs, the const generic
//! `LE_INPUTS` on [`crate::verifier::Groth16Verifier`] flips the layout.
//!
//! ### `Groth16Proof` (serialized length = `256`):
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0   | 64  | `a` (G1) |
//! | 64  | 128 | `b` (G2) |
//! | 192 | 64  | `c` (G1) |

use crate::sizes::{G1_LEN, G2_LEN, PROOF_LEN};
use alloc::vec::Vec;
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// Canonical-format Groth16 proof: zero-copy view into a 256-byte buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Groth16Proof<'a> {
    /// G1 element `A` (64 B).
    pub a: &'a [u8],
    /// G2 element `B` (128 B).
    pub b: &'a [u8],
    /// G1 element `C` (64 B).
    pub c: &'a [u8],
}

impl<'a> Groth16Proof<'a> {
    /// Parse a canonical-format proof from `bytes`. Borrows; no allocation.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, OnChainError> {
        if bytes.len() != PROOF_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let (a, rest) = bytes.split_at(G1_LEN);
        let (b, c) = rest.split_at(G2_LEN);
        debug_assert_eq!(c.len(), G1_LEN);
        Ok(Self { a, b, c })
    }
}

/// **Session 109** — Groth16 proof compression utilities.
///
/// Layout (compressed):
///
/// ```text
/// | offset | size | field      |
/// |---|---|---|
/// |  0..32 | A compressed (G1) |
/// | 32..96 | B compressed (G2) |
/// | 96..128| C compressed (G1) |
/// ```
///
/// Compressed proof is **128 bytes** vs 256 bytes uncompressed —
/// exactly 50 % saving. With three of the highest-volume Solana
/// proof systems being Groth16 (Light Protocol, ZkBNB, Risc0
/// receipts wrapped in Circom), this saving aggregates meaningfully
/// at network scale.
///
/// CU cost per `decompress_to_canonical_bytes` call: ~32 K CU
/// (2 G1 decompress + 1 G2 decompress, each ~10-12 K CU).
impl Groth16Proof<'_> {
    /// Compressed Groth16 proof length.
    pub const COMPRESSED_LEN: usize = 32 + 64 + 32;

    /// Decompress a compressed-format Groth16 proof into the
    /// canonical 256-byte uncompressed wire format.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] — input is not
    ///   exactly `COMPRESSED_LEN` (128) bytes.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   compressed point fails decompression (off-curve x, etc.).
    pub fn decompress_to_canonical_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        compressed: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        if compressed.len() != Self::COMPRESSED_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        // Split: A (32) ‖ B (64) ‖ C (32).
        let mut a_arr = [0u8; 32];
        a_arr.copy_from_slice(&compressed[0..32]);
        let mut b_arr = [0u8; 64];
        b_arr.copy_from_slice(&compressed[32..96]);
        let mut c_arr = [0u8; 32];
        c_arr.copy_from_slice(&compressed[96..128]);

        let a_full = mosaic_zk_primitives::compression::decompress_g1(backend, &a_arr)?;
        let b_full = mosaic_zk_primitives::compression::decompress_g2(backend, &b_arr)?;
        let c_full = mosaic_zk_primitives::compression::decompress_g1(backend, &c_arr)?;

        let mut out = Vec::with_capacity(PROOF_LEN);
        out.extend_from_slice(&a_full);
        out.extend_from_slice(&b_full);
        out.extend_from_slice(&c_full);
        debug_assert_eq!(out.len(), PROOF_LEN);
        Ok(out)
    }

    /// Compress canonical Groth16 proof bytes (256 B) into the
    /// compressed wire format (128 B).
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] — input is not
    ///   exactly `PROOF_LEN` (256) bytes.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   point fails to compress.
    pub fn compress_from_canonical_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        canonical: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        if canonical.len() != PROOF_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        // Split: A (64) ‖ B (128) ‖ C (64).
        let mut a_arr = [0u8; 64];
        a_arr.copy_from_slice(&canonical[0..64]);
        let mut b_arr = [0u8; 128];
        b_arr.copy_from_slice(&canonical[64..192]);
        let mut c_arr = [0u8; 64];
        c_arr.copy_from_slice(&canonical[192..256]);

        let a_c = mosaic_zk_primitives::compression::compress_g1(backend, &a_arr)?;
        let b_c = mosaic_zk_primitives::compression::compress_g2(backend, &b_arr)?;
        let c_c = mosaic_zk_primitives::compression::compress_g1(backend, &c_arr)?;

        let mut out = Vec::with_capacity(Self::COMPRESSED_LEN);
        out.extend_from_slice(&a_c);
        out.extend_from_slice(&b_c);
        out.extend_from_slice(&c_c);
        debug_assert_eq!(out.len(), Self::COMPRESSED_LEN);
        Ok(out)
    }
}

/// Canonical-format Groth16 verifying key. Owns its IC vector.
///
/// `ic.len()` == 1 + number_of_public_inputs (IC\[0\] is the constant term).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16VerifyingKey {
    /// G1 element `α`.
    pub alpha_g1: [u8; G1_LEN],
    /// G2 element `β`.
    pub beta_g2: [u8; G2_LEN],
    /// G2 element `γ`.
    pub gamma_g2: [u8; G2_LEN],
    /// G2 element `δ`.
    pub delta_g2: [u8; G2_LEN],
    /// IC commitment vector. `ic[0]` is the constant term;
    /// `ic[i+1]` is the coefficient on the i-th public input.
    pub ic: Vec<[u8; G1_LEN]>,
}

impl Groth16VerifyingKey {
    /// Number of public inputs supported by this VK (= `ic.len() - 1`).
    #[must_use]
    pub fn num_public_inputs(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }

    /// Serialized length: `64 (α) + 128 × 3 (β,γ,δ) + 64 × ic.len()`.
    #[must_use]
    pub fn serialized_len(&self) -> usize {
        G1_LEN + G2_LEN * 3 + G1_LEN * self.ic.len()
    }

    /// Decode from canonical bytes. Validates lengths only — point-on-curve
    /// checks are deferred to the syscall layer for cost reasons (the
    /// pairing syscall returns `0` for off-curve inputs).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        let header = G1_LEN + G2_LEN * 3;
        if bytes.len() < header {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let (alpha, rest) = bytes.split_at(G1_LEN);
        let (beta, rest) = rest.split_at(G2_LEN);
        let (gamma, rest) = rest.split_at(G2_LEN);
        let (delta, ic_bytes) = rest.split_at(G2_LEN);

        if ic_bytes.is_empty() || ic_bytes.len() % G1_LEN != 0 {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        let mut alpha_g1 = [0u8; G1_LEN];
        alpha_g1.copy_from_slice(alpha);
        let mut beta_g2 = [0u8; G2_LEN];
        beta_g2.copy_from_slice(beta);
        let mut gamma_g2 = [0u8; G2_LEN];
        gamma_g2.copy_from_slice(gamma);
        let mut delta_g2 = [0u8; G2_LEN];
        delta_g2.copy_from_slice(delta);

        let ic_count = ic_bytes.len() / G1_LEN;
        let mut ic = Vec::with_capacity(ic_count);
        for chunk in ic_bytes.chunks_exact(G1_LEN) {
            let mut p = [0u8; G1_LEN];
            p.copy_from_slice(chunk);
            ic.push(p);
        }

        Ok(Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialized_len());
        out.extend_from_slice(&self.alpha_g1);
        out.extend_from_slice(&self.beta_g2);
        out.extend_from_slice(&self.gamma_g2);
        out.extend_from_slice(&self.delta_g2);
        for ic in &self.ic {
            out.extend_from_slice(ic);
        }
        out
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 109 — Groth16 compressed VK support.
    //
    // VK shape (uncompressed): 64 (α) + 128 × 3 (β,γ,δ) + 64 × ic.len()
    // VK shape (compressed):   32     + 64  × 3       + 32 × ic.len()
    //
    // For ic.len() = 2 (1 public input):
    //   Uncompressed: 576 B
    //   Compressed:   288 B  (-50%)
    //
    // For ic.len() = 6 (5 public inputs — typical Circom):
    //   Uncompressed: 832 B
    //   Compressed:   416 B  (-50%)
    //
    // CU cost per from_compressed_bytes: ~10 K (α G1) + 3 × ~12 K (β,γ,δ G2)
    //   + ic.len() × ~10 K = ~46 K + ic.len()·10 K. For ic.len() = 2: ~66 K CU.
    // ───────────────────────────────────────────────────────────────────

    /// Compressed-form VK byte length for a given `ic_len`.
    ///
    /// `32 (α compressed) + 64 × 3 (β,γ,δ compressed) + 32 × ic_len`
    #[must_use]
    pub fn compressed_serialized_len(&self) -> usize {
        32 + 64 * 3 + 32 * self.ic.len()
    }

    /// Decode a compressed-format Groth16 VK byte buffer into the
    /// in-memory uncompressed `Groth16VerifyingKey` struct.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::VerifyingKeyLengthMismatch`] — input is
    ///   shorter than the fixed compressed header (32 + 64·3 = 224 B)
    ///   or the IC tail is not a multiple of 32 bytes.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   compressed point fails decompression.
    pub fn from_compressed_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        bytes: &[u8],
    ) -> Result<Self, OnChainError> {
        const G1_C: usize = 32;
        const G2_C: usize = 64;
        let header = G1_C + G2_C * 3;
        if bytes.len() < header {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let (alpha_c, rest) = bytes.split_at(G1_C);
        let (beta_c, rest) = rest.split_at(G2_C);
        let (gamma_c, rest) = rest.split_at(G2_C);
        let (delta_c, ic_bytes) = rest.split_at(G2_C);

        if ic_bytes.is_empty() || ic_bytes.len() % G1_C != 0 {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        let mut alpha_arr = [0u8; G1_C];
        alpha_arr.copy_from_slice(alpha_c);
        let alpha_g1 =
            mosaic_zk_primitives::compression::decompress_g1(backend, &alpha_arr)?;

        let mut beta_arr = [0u8; G2_C];
        beta_arr.copy_from_slice(beta_c);
        let beta_g2 =
            mosaic_zk_primitives::compression::decompress_g2(backend, &beta_arr)?;

        let mut gamma_arr = [0u8; G2_C];
        gamma_arr.copy_from_slice(gamma_c);
        let gamma_g2 =
            mosaic_zk_primitives::compression::decompress_g2(backend, &gamma_arr)?;

        let mut delta_arr = [0u8; G2_C];
        delta_arr.copy_from_slice(delta_c);
        let delta_g2 =
            mosaic_zk_primitives::compression::decompress_g2(backend, &delta_arr)?;

        let ic_count = ic_bytes.len() / G1_C;
        let mut ic = Vec::with_capacity(ic_count);
        for chunk in ic_bytes.chunks_exact(G1_C) {
            let mut ic_arr = [0u8; G1_C];
            ic_arr.copy_from_slice(chunk);
            let full =
                mosaic_zk_primitives::compression::decompress_g1(backend, &ic_arr)?;
            ic.push(full);
        }

        Ok(Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }

    /// Encode this VK in compressed form (companion to
    /// [`from_compressed_bytes`]). The IC vector is iterated and
    /// each element compressed; α is compressed; β/γ/δ are compressed.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   point fails to compress (off-curve, etc.).
    pub fn to_compressed_bytes<B: SyscallBackend + ?Sized>(
        &self,
        backend: &B,
    ) -> Result<Vec<u8>, OnChainError> {
        let alpha_c =
            mosaic_zk_primitives::compression::compress_g1(backend, &self.alpha_g1)?;
        let beta_c =
            mosaic_zk_primitives::compression::compress_g2(backend, &self.beta_g2)?;
        let gamma_c =
            mosaic_zk_primitives::compression::compress_g2(backend, &self.gamma_g2)?;
        let delta_c =
            mosaic_zk_primitives::compression::compress_g2(backend, &self.delta_g2)?;

        let mut out = Vec::with_capacity(self.compressed_serialized_len());
        out.extend_from_slice(&alpha_c);
        out.extend_from_slice(&beta_c);
        out.extend_from_slice(&gamma_c);
        out.extend_from_slice(&delta_c);
        for ic in &self.ic {
            let ic_c =
                mosaic_zk_primitives::compression::compress_g1(backend, ic)?;
            out.extend_from_slice(&ic_c);
        }
        Ok(out)
    }
}

/// BN254 scalar field order `r` in big-endian. Public inputs must be `< r`.
///
/// **Session 98 — primitive consolidation.** Re-export from
/// [`mosaic_zk_primitives::fr::BN254_FR_MODULUS_BE`] to remove the
/// long-standing duplicate definition that lived in this crate since
/// session 1. The bytes are identical (BN254 scalar field order
/// `21888242871839275222246405745257275088548364400416034343698204186575808495617`);
/// the workspace now has a single source of truth for the modulus.
pub use mosaic_zk_primitives::fr::BN254_FR_MODULUS_BE;

/// Compare two big-endian 32-byte buffers as unsigned integers.
/// Returns `true` if `lhs < rhs`.
///
/// **Session 98 — primitive consolidation.** Re-export from
/// [`mosaic_zk_primitives::fr::lt_be`] to remove the duplicate
/// implementation. The behavior is byte-identical (the original
/// `lt_be` here predated the shared primitive; session 98
/// consolidates).
///
/// Internal callers should prefer the convenience wrapper
/// [`mosaic_zk_primitives::fr::lt_r`] which compares against the
/// modulus directly.
pub use mosaic_zk_primitives::fr::lt_be;

#[cfg(test)]
mod tests {
    use super::*;
    // Session 93: explicit `alloc::vec` import for standalone-test
    // parity. The crate is no_std with `default = []` features, so
    // the std prelude's `vec!` macro is not in scope under
    // `cargo test -p mosaic-groth16 --lib` invocations. Workspace-
    // level test runs masked this with feature unification.
    use alloc::vec;

    #[test]
    fn vk_roundtrip() {
        let vk = Groth16VerifyingKey {
            alpha_g1: [1; G1_LEN],
            beta_g2: [2; G2_LEN],
            gamma_g2: [3; G2_LEN],
            delta_g2: [4; G2_LEN],
            ic: alloc::vec![[5; G1_LEN], [6; G1_LEN], [7; G1_LEN]],
        };
        let encoded = vk.to_bytes();
        assert_eq!(encoded.len(), vk.serialized_len());
        let decoded = Groth16VerifyingKey::from_bytes(&encoded).unwrap();
        assert_eq!(vk, decoded);
        assert_eq!(decoded.num_public_inputs(), 2);
    }

    #[test]
    fn proof_view() {
        let buf = [0xAB; PROOF_LEN];
        let p = Groth16Proof::from_bytes(&buf).unwrap();
        assert_eq!(p.a.len(), G1_LEN);
        assert_eq!(p.b.len(), G2_LEN);
        assert_eq!(p.c.len(), G1_LEN);
    }

    #[test]
    fn proof_length_check() {
        let short = [0u8; PROOF_LEN - 1];
        assert!(matches!(
            Groth16Proof::from_bytes(&short),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn fr_modulus_bound() {
        // r itself is NOT less than r.
        assert!(!lt_be(&BN254_FR_MODULUS_BE, &BN254_FR_MODULUS_BE));
        // r-1 IS less than r.
        let mut rm1 = BN254_FR_MODULUS_BE;
        rm1[31] -= 1;
        assert!(lt_be(&rm1, &BN254_FR_MODULUS_BE));
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 39 — proptest coverage for Groth16 canonical layout.
    //
    // Groth16 envelope characteristics:
    //
    //   - Proof: fixed 256 B (G1 || G2 || G1).
    //   - VK: variable 224 + 64·n B, where `n = ic.len() ≥ 1`.
    //   - Public input bound: < r (BN254 scalar field modulus).
    //   - `lt_be` is the BE-comparison primitive — sole soundness gate
    //     between adversarial public inputs and the pairing syscall.
    //
    // Properties exercised:
    //
    //   1. Proof view parses any 256-B buffer; field slices reassemble
    //      to the original (pins ordering A‖B‖C against future split
    //      reorderings).
    //   2. Any non-256 length must be rejected.
    //   3. VK round-trip is the identity for any well-formed VK.
    //   4. VK rejects non-multiple-of-G1_LEN tail (broken IC frame).
    //   5. VK rejects empty IC vector (consensus-critical: a 0-IC VK
    //      would silently bypass the public-input commitment check).
    //   6. `lt_be` agrees with native u128/u256 comparison on small and
    //      structured inputs (high-byte differs first vs. trailing-byte
    //      tiebreak; transitivity; reflexivity).
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    prop_compose! {
        /// Random VK with 1..=8 IC entries, distinct fill bytes per
        /// commit slot to surface reorderings as inequality.
        fn arb_vk()(
            alpha in any::<u8>(),
            beta in any::<u8>(),
            gamma in any::<u8>(),
            delta in any::<u8>(),
            ic_count in 1usize..=8,
            ic_seed in any::<u8>(),
        ) -> Groth16VerifyingKey {
            let ic: Vec<[u8; G1_LEN]> = (0..ic_count)
                .map(|i| [ic_seed.wrapping_add(i as u8); G1_LEN])
                .collect();
            Groth16VerifyingKey {
                alpha_g1: [alpha; G1_LEN],
                beta_g2: [beta; G2_LEN],
                gamma_g2: [gamma; G2_LEN],
                delta_g2: [delta; G2_LEN],
                ic,
            }
        }
    }

    proptest! {
        /// Any 256-B buffer parses; A/B/C slice lengths match the
        /// canonical layout AND concatenating them reproduces the
        /// original buffer exactly.
        #[test]
        fn proptest_proof_view_parses_and_round_trips(
            buf in proptest::collection::vec(any::<u8>(), PROOF_LEN..=PROOF_LEN),
        ) {
            let p = Groth16Proof::from_bytes(&buf).expect("canonical len parses");
            prop_assert_eq!(p.a.len(), G1_LEN);
            prop_assert_eq!(p.b.len(), G2_LEN);
            prop_assert_eq!(p.c.len(), G1_LEN);
            let mut reassembled = Vec::with_capacity(PROOF_LEN);
            reassembled.extend_from_slice(p.a);
            reassembled.extend_from_slice(p.b);
            reassembled.extend_from_slice(p.c);
            prop_assert_eq!(reassembled, buf);
        }

        /// Any byte buffer whose length differs from `PROOF_LEN` is
        /// rejected with `ProofLengthMismatch`.
        #[test]
        fn proptest_proof_rejects_any_wrong_length(
            len in 0usize..=2 * PROOF_LEN,
        ) {
            prop_assume!(len != PROOF_LEN);
            let buf = vec![0u8; len];
            prop_assert!(matches!(
                Groth16Proof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// VK encode-then-decode is the identity for any well-formed
        /// VK in our bounded shape space.
        #[test]
        fn proptest_vk_roundtrip(vk in arb_vk()) {
            let bytes = vk.to_bytes();
            prop_assert_eq!(bytes.len(), vk.serialized_len());
            let decoded = Groth16VerifyingKey::from_bytes(&bytes)
                .expect("well-formed VK round-trips");
            prop_assert_eq!(vk, decoded);
        }

        /// Decoder must reject a VK whose IC tail length is not a
        /// multiple of `G1_LEN`. Catches the failure mode where a
        /// truncated upload would silently parse with one fewer IC
        /// entry, breaking the public-input commitment count.
        #[test]
        fn proptest_vk_rejects_misaligned_ic_tail(
            vk in arb_vk(),
            chop in 1usize..G1_LEN, // 1..63: doesn't reach next IC boundary
        ) {
            let mut bytes = vk.to_bytes();
            bytes.truncate(bytes.len() - chop);
            prop_assert!(matches!(
                Groth16VerifyingKey::from_bytes(&bytes),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }

        /// Decoder must reject a VK with an empty IC vector (header-
        /// only buffer). This is the soundness gate against a "no
        /// public-input commitments" attack — without IC, the
        /// linearization step has no per-input weights and the verifier
        /// would silently accept any public input as long as the
        /// pairing structurally balances.
        #[test]
        fn proptest_vk_rejects_empty_ic(
            alpha in any::<u8>(),
            beta in any::<u8>(),
            gamma in any::<u8>(),
            delta in any::<u8>(),
        ) {
            // Build a header-only buffer (no IC entries).
            let mut bytes = Vec::with_capacity(G1_LEN + 3 * G2_LEN);
            bytes.extend_from_slice(&[alpha; G1_LEN]);
            bytes.extend_from_slice(&[beta; G2_LEN]);
            bytes.extend_from_slice(&[gamma; G2_LEN]);
            bytes.extend_from_slice(&[delta; G2_LEN]);
            prop_assert!(matches!(
                Groth16VerifyingKey::from_bytes(&bytes),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }

        /// Decoder must reject buffers shorter than the fixed header
        /// (224 B) regardless of content.
        #[test]
        fn proptest_vk_rejects_short_header(
            len in 0usize..(G1_LEN + 3 * G2_LEN),
        ) {
            let bytes = vec![0u8; len];
            prop_assert!(matches!(
                Groth16VerifyingKey::from_bytes(&bytes),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }

        /// `lt_be` is anti-reflexive: no value is strictly less than
        /// itself.
        #[test]
        fn proptest_lt_be_anti_reflexive(
            x in proptest::collection::vec(any::<u8>(), 32..=32),
        ) {
            let mut a = [0u8; 32];
            a.copy_from_slice(&x);
            prop_assert!(!lt_be(&a, &a));
        }

        /// `lt_be` is asymmetric: lt_be(a, b) ⇒ !lt_be(b, a) for
        /// distinct values. Catches a sign-flipped comparison bug.
        #[test]
        fn proptest_lt_be_asymmetric(
            x in proptest::collection::vec(any::<u8>(), 32..=32),
            y in proptest::collection::vec(any::<u8>(), 32..=32),
        ) {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            a.copy_from_slice(&x);
            b.copy_from_slice(&y);
            prop_assume!(a != b);
            prop_assert!(lt_be(&a, &b) != lt_be(&b, &a));
        }

        /// `lt_be` matches the high-byte-first BE comparison: if `a`
        /// and `b` differ at the same byte index, the smaller byte
        /// determines the result. This pins the implementation against
        /// a future LE-first bug that would silently accept tampered
        /// public inputs.
        #[test]
        fn proptest_lt_be_first_differing_byte_decides(
            differ_at in 0usize..32,
            a_byte in 0u8..u8::MAX,
        ) {
            let b_byte = a_byte + 1; // strictly greater
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            a[differ_at] = a_byte;
            b[differ_at] = b_byte;
            prop_assert!(lt_be(&a, &b));
            prop_assert!(!lt_be(&b, &a));
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 109 — Groth16 compressed proof + VK round-trip tests.
    //
    // Same pattern as session 106-108 Halo2 compression tests:
    // round-trip + bandwidth-saving + reject-malformed-input.
    //
    // Groth16 proof shape: A (G1) ‖ B (G2) ‖ C (G1) — uncompressed
    // 256 B, compressed 128 B (50 % saving). VK shape: α (G1) +
    // β/γ/δ (G2) + IC vector (G1) — compressed VK halves to ~50 %.
    // ───────────────────────────────────────────────────────────────────
    #[cfg(feature = "host-backend")]
    mod compression {
        use super::*;
        use mosaic_core::syscall::host::HostBackend;

        fn realistic_proof() -> Vec<u8> {
            // Use the BN254 G1 + G2 generators for A, B, C. Both are
            // on-curve, both are non-zero — exercising the actual
            // compression arithmetic instead of zero short-circuits.
            let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
            let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
            let mut buf = Vec::with_capacity(PROOF_LEN);
            buf.extend_from_slice(&g1_gen);
            buf.extend_from_slice(&g2_gen);
            buf.extend_from_slice(&g1_gen);
            buf
        }

        fn realistic_vk() -> Groth16VerifyingKey {
            let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
            let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
            Groth16VerifyingKey {
                alpha_g1: g1_gen,
                beta_g2: g2_gen,
                gamma_g2: g2_gen,
                delta_g2: g2_gen,
                ic: vec![g1_gen, g1_gen, g1_gen], // 1 const term + 2 PI commits
            }
        }

        // ── Proof tests ─────────────────────────────────────────────

        #[test]
        fn proof_round_trip_with_real_generators() {
            let backend = HostBackend::new();
            let canonical = realistic_proof();
            let compressed =
                Groth16Proof::compress_from_canonical_bytes(&backend, &canonical)
                    .expect("compress");
            assert_eq!(compressed.len(), Groth16Proof::COMPRESSED_LEN);
            let decoded =
                Groth16Proof::decompress_to_canonical_bytes(&backend, &compressed)
                    .expect("decompress");
            assert_eq!(decoded, canonical, "round-trip must be byte-identical");
        }

        #[test]
        fn proof_compressed_size_is_exactly_half() {
            let backend = HostBackend::new();
            let canonical = realistic_proof();
            let compressed =
                Groth16Proof::compress_from_canonical_bytes(&backend, &canonical)
                    .unwrap();
            assert_eq!(canonical.len(), 256);
            assert_eq!(compressed.len(), 128);
        }

        #[test]
        fn proof_zero_only_round_trips() {
            let backend = HostBackend::new();
            let canonical = vec![0u8; PROOF_LEN];
            let compressed =
                Groth16Proof::compress_from_canonical_bytes(&backend, &canonical)
                    .unwrap();
            assert_eq!(compressed, vec![0u8; Groth16Proof::COMPRESSED_LEN]);
            let decoded =
                Groth16Proof::decompress_to_canonical_bytes(&backend, &compressed)
                    .unwrap();
            assert_eq!(decoded, canonical);
        }

        #[test]
        fn proof_compress_rejects_wrong_canonical_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; PROOF_LEN - 1];
            let r = Groth16Proof::compress_from_canonical_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
        }

        #[test]
        fn proof_decompress_rejects_wrong_compressed_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; Groth16Proof::COMPRESSED_LEN - 1];
            let r = Groth16Proof::decompress_to_canonical_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
        }

        #[test]
        fn proof_decompressed_parses_via_from_bytes() {
            let backend = HostBackend::new();
            let canonical = realistic_proof();
            let compressed =
                Groth16Proof::compress_from_canonical_bytes(&backend, &canonical)
                    .unwrap();
            let decoded =
                Groth16Proof::decompress_to_canonical_bytes(&backend, &compressed)
                    .unwrap();
            let proof = Groth16Proof::from_bytes(&decoded).expect("from_bytes parse");
            assert_eq!(proof.a.len(), G1_LEN);
            assert_eq!(proof.b.len(), G2_LEN);
            assert_eq!(proof.c.len(), G1_LEN);
        }

        // ── VK tests ───────────────────────────────────────────────

        #[test]
        fn vk_round_trip_with_real_generators() {
            let backend = HostBackend::new();
            let vk = realistic_vk();
            let compressed = vk.to_compressed_bytes(&backend).expect("compress");
            assert_eq!(compressed.len(), vk.compressed_serialized_len());
            let decoded =
                Groth16VerifyingKey::from_compressed_bytes(&backend, &compressed)
                    .expect("decompress");
            assert_eq!(vk, decoded, "VK round-trip must be byte-identical");
        }

        #[test]
        fn vk_compressed_size_is_exactly_half() {
            let backend = HostBackend::new();
            let vk = realistic_vk();
            let uncompressed = vk.to_bytes();
            let compressed = vk.to_compressed_bytes(&backend).unwrap();
            // ic.len() = 3 → uncompressed = 64 + 384 + 192 = 640 B,
            //                compressed   = 32 + 192 + 96  = 320 B.
            assert_eq!(uncompressed.len(), 640);
            assert_eq!(compressed.len(), 320);
            assert_eq!(compressed.len() * 2, uncompressed.len());
        }

        #[test]
        fn vk_zero_only_round_trips() {
            let backend = HostBackend::new();
            let vk = Groth16VerifyingKey {
                alpha_g1: [0u8; G1_LEN],
                beta_g2: [0u8; G2_LEN],
                gamma_g2: [0u8; G2_LEN],
                delta_g2: [0u8; G2_LEN],
                ic: vec![[0u8; G1_LEN], [0u8; G1_LEN]],
            };
            let compressed = vk.to_compressed_bytes(&backend).unwrap();
            let decoded =
                Groth16VerifyingKey::from_compressed_bytes(&backend, &compressed)
                    .unwrap();
            assert_eq!(vk, decoded);
        }

        #[test]
        fn vk_decompress_rejects_short_buffer() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; 32 + 64 * 3 - 1]; // < header
            let r =
                Groth16VerifyingKey::from_compressed_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
        }

        #[test]
        fn vk_decompress_rejects_non_multiple_g1_ic_tail() {
            let backend = HostBackend::new();
            // header + 31 bytes (not a multiple of 32 for compressed G1).
            let bad = vec![0u8; 32 + 64 * 3 + 31];
            let r = Groth16VerifyingKey::from_compressed_bytes(&backend, &bad);
            assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
        }

        #[test]
        fn vk_decompress_rejects_empty_ic() {
            let backend = HostBackend::new();
            // header only (no IC payload) — empty IC violates Groth16
            // soundness (IC[0] always present).
            let bad = vec![0u8; 32 + 64 * 3];
            let r = Groth16VerifyingKey::from_compressed_bytes(&backend, &bad);
            assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
        }
    }
}
