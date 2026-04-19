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
use mosaic_core::OnChainError;

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

        Ok(Self { alpha_g1, beta_g2, gamma_g2, delta_g2, ic })
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
}

/// BN254 scalar field order `r` in big-endian. Public inputs must be `< r`.
///
/// `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
pub const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Compare two big-endian 32-byte buffers as unsigned integers.
/// Returns `true` if `lhs < rhs`.
#[must_use]
pub fn lt_be(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        if a != b {
            return a < b;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
