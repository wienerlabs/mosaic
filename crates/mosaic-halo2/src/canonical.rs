//! Halo2-KZG canonical byte layout — **placeholder shape** derived from
//! the PSE Halo2-KZG proof encoding.
//!
//! ## Reference wire format
//!
//! Privacy Scaling Explorations'
//! [`halo2_proofs::plonk::verify_proof`](https://github.com/privacy-scaling-explorations/halo2/blob/main/halo2_proofs/src/plonk/verifier.rs)
//! consumes proofs laid out as:
//!
//! ```text
//! [advice_col_commits...]          (n_advice × G1)
//! [lookup_m_polys...]              (n_lookups × G1)   -- m_poly per lookup
//! [permutation_z_polys...]         (n_perms × G1)
//! [vanishing_h_pieces...]          (n_quotient_chunks × G1)
//! [ξ evaluations of everything]    (variable count × Fr)
//! [instance_evals...]              (n_instances × Fr)
//! [opening_proof]                  (2 × G1 for multipoint opening Wξ + Wξω)
//! ```
//!
//! The exact count of each section depends on the circuit shape
//! (advice columns, lookup arguments, permutation chunks). Our
//! canonical layout parametrizes these via the VK so a single wire
//! format works across circuits.
//!
//! ## Layout
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0 | 4 | `n_advice` (u32 LE) — advice column commitment count |
//! | 4 | 4 | `n_lookups` (u32 LE) — lookup argument count |
//! | 8 | 4 | `n_quotient` (u32 LE) — quotient polynomial chunk count |
//! | 12 | 4 | `n_evals` (u32 LE) — evaluation count at ξ |
//! | 16 | 64 × n_advice | advice column commitments (G1) |
//! | … | 64 × n_lookups | lookup `m` polynomial commitments (G1) |
//! | … | 64 | permutation grand-product commitment (G1) |
//! | … | 64 × n_quotient | quotient chunks (G1) |
//! | … | 32 × n_evals | polynomial evaluations at ξ (Fr) |
//! | … | 64 | `W_ξ` opening (G1) |
//! | … | 64 | `W_ξω` opening (G1) |
//!
//! For a typical 2^10 circuit (5 advice, 1 lookup, 3 quotient chunks,
//! ~15 evals) the proof is:
//!
//!   16 + 5·64 + 1·64 + 64 + 3·64 + 15·32 + 2·64 = **1104 B**
//!
//! **TODO(mosaic-halo2)**: pin this layout against the PSE
//! `halo2_proofs::plonk::verifier::verify_proof` byte ordering before
//! Phase 3 writes an adapter in `mosaic-serde::halo2`.

use alloc::vec::Vec;
use mosaic_core::OnChainError;

/// Size constants for the Halo2-KZG canonical layout.
pub mod sizes {
    /// G1 affine point (x || y, each 32-byte BE).
    pub const G1_LEN: usize = 64;
    /// Fr element (BN254 scalar field, big-endian).
    pub const FR_LEN: usize = 32;
    /// G2 affine (for KZG SRS element in VK).
    pub const G2_LEN: usize = 128;
    /// Fixed header length: 4 u32 counters.
    pub const FIXED_HEADER_LEN: usize = 16;
    /// Max advice columns — sanity cap to guard against adversarial proof
    /// sizes. Solana instruction data limit is 1232 B, so any real-world
    /// Halo2 proof fits in a single tx if under 1200 B; bigger needs
    /// chunked upload.
    pub const MAX_ADVICE_COLUMNS: u32 = 64;
    /// Max lookup argument count.
    pub const MAX_LOOKUPS: u32 = 32;
    /// Max quotient polynomial chunk count.
    pub const MAX_QUOTIENT_CHUNKS: u32 = 32;
    /// Max evaluation count at the sumcheck point ξ.
    pub const MAX_EVALUATIONS: u32 = 256;
}

/// Zero-copy view into a Halo2-KZG proof buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Halo2KzgProof<'a> {
    /// Advice column commitment count.
    pub n_advice: u32,
    /// Lookup argument count.
    pub n_lookups: u32,
    /// Quotient polynomial chunk count.
    pub n_quotient: u32,
    /// Number of polynomial evaluations at ξ.
    pub n_evals: u32,
    /// Concatenated advice column commitments. Length = `n_advice * 64`.
    pub advice_commits: &'a [u8],
    /// Concatenated lookup `m` polynomial commitments. Length = `n_lookups * 64`.
    pub lookup_commits: &'a [u8],
    /// Permutation grand-product commitment (single G1).
    pub permutation_z: &'a [u8],
    /// Concatenated quotient polynomial chunks. Length = `n_quotient * 64`.
    pub quotient_chunks: &'a [u8],
    /// Concatenated polynomial evaluations at ξ. Length = `n_evals * 32`.
    pub evaluations: &'a [u8],
    /// KZG opening at ξ (G1).
    pub w_xi: &'a [u8],
    /// KZG opening at `ξω` (G1).
    pub w_xiw: &'a [u8],
}

impl<'a> Halo2KzgProof<'a> {
    /// Parse a canonical Halo2-KZG proof.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, OnChainError> {
        use sizes::{
            FIXED_HEADER_LEN, FR_LEN, G1_LEN, MAX_ADVICE_COLUMNS, MAX_EVALUATIONS, MAX_LOOKUPS,
            MAX_QUOTIENT_CHUNKS,
        };
        if bytes.len() < FIXED_HEADER_LEN + G1_LEN + 2 * G1_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let n_advice = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let n_lookups = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let n_quotient = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let n_evals = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        if n_advice > MAX_ADVICE_COLUMNS
            || n_lookups > MAX_LOOKUPS
            || n_quotient > MAX_QUOTIENT_CHUNKS
            || n_evals > MAX_EVALUATIONS
        {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let advice_len = (n_advice as usize)
            .checked_mul(G1_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let lookup_len = (n_lookups as usize)
            .checked_mul(G1_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let quotient_len = (n_quotient as usize)
            .checked_mul(G1_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let evals_len = (n_evals as usize)
            .checked_mul(FR_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;

        let expected_len = FIXED_HEADER_LEN
            + advice_len
            + lookup_len
            + G1_LEN // permutation_z
            + quotient_len
            + evals_len
            + 2 * G1_LEN; // w_xi, w_xiw

        if bytes.len() != expected_len {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let mut o = FIXED_HEADER_LEN;
        let advice_commits = &bytes[o..o + advice_len];
        o += advice_len;
        let lookup_commits = &bytes[o..o + lookup_len];
        o += lookup_len;
        let permutation_z = &bytes[o..o + G1_LEN];
        o += G1_LEN;
        let quotient_chunks = &bytes[o..o + quotient_len];
        o += quotient_len;
        let evaluations = &bytes[o..o + evals_len];
        o += evals_len;
        let w_xi = &bytes[o..o + G1_LEN];
        o += G1_LEN;
        let w_xiw = &bytes[o..o + G1_LEN];

        Ok(Self {
            n_advice, n_lookups, n_quotient, n_evals,
            advice_commits, lookup_commits, permutation_z,
            quotient_chunks, evaluations, w_xi, w_xiw,
        })
    }

    /// Iterate advice column commitments as 64-byte slices.
    pub fn advice_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.advice_commits.chunks_exact(sizes::G1_LEN)
    }

    /// Iterate quotient polynomial chunk commitments.
    pub fn quotient_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.quotient_chunks.chunks_exact(sizes::G1_LEN)
    }

    /// Iterate evaluations as 32-byte Fr slices.
    pub fn evaluations_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.evaluations.chunks_exact(sizes::FR_LEN)
    }
}

/// Halo2-KZG verifying key.
///
/// **Placeholder** — real VK has preprocessing commitments for custom
/// gates + permutation + lookup tables. Pinning waits for Phase-3
/// implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Halo2KzgVerifyingKey {
    /// Circuit `k` parameter: domain size = 2^k.
    pub k: u32,
    /// Number of instance (public) columns.
    pub n_instances: u32,
    /// Number of advice columns (witness).
    pub n_advice: u32,
    /// Number of fixed columns (preprocessing).
    pub n_fixed: u32,
    /// G2 SRS element for KZG pairing check.
    pub x2_g2: [u8; sizes::G2_LEN],
    /// Fixed column commitments concatenated (length = `n_fixed * 64`).
    /// Boxed via Vec so the VK size is dynamic at decode time.
    pub fixed_commits: Vec<u8>,
    /// Permutation commitment set (one per permuted column).
    /// Length = `n_advice * 64` in the typical case.
    pub permutation_commits: Vec<u8>,
}

impl Halo2KzgVerifyingKey {
    /// Fixed-portion length before the two variable-sized commitment buffers.
    pub const FIXED_LEN: usize = 4 // k
        + 4 // n_instances
        + 4 // n_advice
        + 4 // n_fixed
        + sizes::G2_LEN
        + 4 // fixed_commits.len() (bytes)
        + 4; // permutation_commits.len() (bytes)

    /// Decode from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let k = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let n_instances = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let n_advice = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let n_fixed = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let mut x2_g2 = [0u8; sizes::G2_LEN];
        x2_g2.copy_from_slice(&bytes[16..16 + sizes::G2_LEN]);
        let after_g2 = 16 + sizes::G2_LEN;
        let fixed_len = u32::from_le_bytes([
            bytes[after_g2],
            bytes[after_g2 + 1],
            bytes[after_g2 + 2],
            bytes[after_g2 + 3],
        ]) as usize;
        let perm_len = u32::from_le_bytes([
            bytes[after_g2 + 4],
            bytes[after_g2 + 5],
            bytes[after_g2 + 6],
            bytes[after_g2 + 7],
        ]) as usize;
        let payload_start = after_g2 + 8;
        let expected = payload_start + fixed_len + perm_len;
        if bytes.len() != expected {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let fixed_commits = bytes[payload_start..payload_start + fixed_len].to_vec();
        let permutation_commits =
            bytes[payload_start + fixed_len..payload_start + fixed_len + perm_len].to_vec();
        Ok(Self {
            k, n_instances, n_advice, n_fixed,
            x2_g2, fixed_commits, permutation_commits,
        })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            Self::FIXED_LEN + self.fixed_commits.len() + self.permutation_commits.len(),
        );
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.n_instances.to_le_bytes());
        out.extend_from_slice(&self.n_advice.to_le_bytes());
        out.extend_from_slice(&self.n_fixed.to_le_bytes());
        out.extend_from_slice(&self.x2_g2);
        out.extend_from_slice(&(self.fixed_commits.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.permutation_commits.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.fixed_commits);
        out.extend_from_slice(&self.permutation_commits);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN};

    fn proof_bytes(n_advice: u32, n_lookups: u32, n_quotient: u32, n_evals: u32) -> Vec<u8> {
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN // permutation_z
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = vec![0xAA; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
        buf
    }

    #[test]
    fn proof_parses_typical_shape() {
        let buf = proof_bytes(5, 1, 3, 15);
        let p = Halo2KzgProof::from_bytes(&buf).unwrap();
        assert_eq!(p.n_advice, 5);
        assert_eq!(p.n_lookups, 1);
        assert_eq!(p.n_quotient, 3);
        assert_eq!(p.n_evals, 15);
        assert_eq!(p.advice_iter().count(), 5);
        assert_eq!(p.quotient_iter().count(), 3);
        assert_eq!(p.evaluations_iter().count(), 15);
    }

    #[test]
    fn proof_parses_minimal_shape() {
        let buf = proof_bytes(0, 0, 0, 0);
        let p = Halo2KzgProof::from_bytes(&buf).unwrap();
        assert_eq!(p.n_advice, 0);
        assert_eq!(p.advice_iter().count(), 0);
    }

    #[test]
    fn proof_rejects_advice_over_max() {
        let buf = proof_bytes(sizes::MAX_ADVICE_COLUMNS + 1, 1, 1, 1);
        assert!(matches!(
            Halo2KzgProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_evals_over_max() {
        let buf = proof_bytes(1, 1, 1, sizes::MAX_EVALUATIONS + 1);
        assert!(matches!(
            Halo2KzgProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_trailing_garbage() {
        let mut buf = proof_bytes(2, 0, 1, 3);
        buf.push(0xDE);
        assert!(matches!(
            Halo2KzgProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn vk_roundtrip_no_commits() {
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: [0xCD; G2_LEN],
            fixed_commits: vec![],
            permutation_commits: vec![],
        };
        let bytes = vk.to_bytes();
        let decoded = Halo2KzgVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
    }

    #[test]
    fn vk_roundtrip_with_commits() {
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: [0xCD; G2_LEN],
            fixed_commits: vec![0x11; 2 * G1_LEN], // 2 fixed columns
            permutation_commits: vec![0x22; 5 * G1_LEN], // 5 advice columns permuted
        };
        let bytes = vk.to_bytes();
        let decoded = Halo2KzgVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
        assert_eq!(decoded.fixed_commits.len(), 2 * G1_LEN);
        assert_eq!(decoded.permutation_commits.len(), 5 * G1_LEN);
    }

    #[test]
    fn vk_rejects_short_buffer() {
        let short = vec![0u8; Halo2KzgVerifyingKey::FIXED_LEN - 1];
        assert!(matches!(
            Halo2KzgVerifyingKey::from_bytes(&short),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }

    #[test]
    fn vk_rejects_mismatched_tail_length() {
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: [0; G2_LEN],
            fixed_commits: vec![0x11; G1_LEN],
            permutation_commits: vec![],
        };
        let mut bytes = vk.to_bytes();
        bytes.push(0xFF); // extra byte
        assert!(matches!(
            Halo2KzgVerifyingKey::from_bytes(&bytes),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }
}
