//! HyperPlonk canonical byte layout — **placeholder shape**.
//!
//! ## Reference impl survey
//!
//! Multiple HyperPlonk prover implementations exist today with divergent
//! wire formats:
//!
//! | Impl | Proof size (2^10 circuit) | Notes |
//! |---|---|---|
//! | [Espresso `hyperplonk`](https://github.com/EspressoSystems/hyperplonk) | ~3 KB | Reference; most active |
//! | `arkworks-rs/poly-commit` MLE path | ~2 KB | Pairing-free; WIP |
//! | Privacy-Scaling-Explorations variant | ~4 KB | Includes lookup argument |
//!
//! Until Phase 3 picks one format to be byte-compatible with, this
//! module defines a **conservative placeholder** sized for the Espresso
//! layout: 4 G1 commitments + `log₂ n` Fr tuples (sumcheck round
//! polynomials) + O(log n) Fr evaluations. Real layout will be pinned
//! in an ADR amendment when the Phase 3 impl lands.
//!
//! ## Layout
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0   | 64   | `a`: G1 commitment to witness A (as MLE) |
//! | 64  | 64   | `b`: G1 commitment to witness B |
//! | 128 | 64   | `c`: G1 commitment to witness C |
//! | 192 | 64   | `z`: G1 commitment to permutation grand-product MLE |
//! | 256 | 4    | `sumcheck_rounds` (u32 LE) — = log₂(circuit size) |
//! | 260 | 96 × N | `sumcheck_polys` — N round polynomials, each 3 × 32 B Fr coefficients (degree-2 per round for the zero-check sumcheck) |
//! | …   | 32 × 4 | Final-round MLE evaluations (a, b, c, z at the sumcheck challenge point) |
//! | …   | 64   | KZG opening proof at the random evaluation point |
//!
//! Total size for `sumcheck_rounds = 10` (2^10 circuit): 4×64 + 4 + 10×96 + 4×32 + 64 = **1476 B**.
//!
//! **TODO(mosaic-002)**: Pin the layout against the chosen upstream
//! reference before any adapter in `mosaic-serde` can be written.

use alloc::vec::Vec;
use mosaic_core::OnChainError;

/// Size constants for the HyperPlonk canonical layout.
pub mod sizes {
    /// G1 affine point (x || y, each 32-byte BE).
    pub const G1_LEN: usize = 64;
    /// Fr element (BN254 scalar field, big-endian).
    pub const FR_LEN: usize = 32;
    /// Sumcheck round polynomial coefficient count (degree-2 = 3 coeffs).
    pub const SUMCHECK_POLY_COEFFS: usize = 3;
    /// Bytes per sumcheck round polynomial.
    pub const SUMCHECK_POLY_LEN: usize = SUMCHECK_POLY_COEFFS * FR_LEN;
    /// Number of Fr evaluations in the final round (a, b, c, z at challenge point).
    pub const FINAL_EVALS: usize = 4;
    /// Fixed header length (everything before `sumcheck_polys`): 4 × G1 + u32.
    pub const FIXED_HEADER_LEN: usize = 4 * G1_LEN + 4;
    /// Fixed tail length (final evals + KZG opening): 4 × Fr + G1.
    pub const FIXED_TAIL_LEN: usize = FINAL_EVALS * FR_LEN + G1_LEN;

    /// Minimum proof size (0 sumcheck rounds, edge case).
    pub const MIN_PROOF_LEN: usize = FIXED_HEADER_LEN + FIXED_TAIL_LEN;
    /// Maximum supported sumcheck rounds. Circuits of size 2^28 or
    /// smaller fit; matches arkworks' `TWO_ADICITY` ceiling.
    pub const MAX_SUMCHECK_ROUNDS: u32 = 28;
}

/// Zero-copy view into a HyperPlonk proof buffer.
///
/// Because the sumcheck-polynomial count is dynamic (one per round), the
/// `sumcheck_polys` and evaluation slices are raw byte windows rather
/// than fixed-size arrays. Callers iterate in `SUMCHECK_POLY_LEN`
/// chunks for round polynomials.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HyperPlonkProof<'a> {
    /// Witness commitment A (G1).
    pub a: &'a [u8],
    /// Witness commitment B (G1).
    pub b: &'a [u8],
    /// Witness commitment C (G1).
    pub c: &'a [u8],
    /// Permutation grand-product commitment (G1).
    pub z: &'a [u8],
    /// Number of sumcheck rounds (= log₂ of circuit size).
    pub sumcheck_rounds: u32,
    /// All round polynomials concatenated. Length == `sumcheck_rounds * SUMCHECK_POLY_LEN`.
    pub sumcheck_polys: &'a [u8],
    /// Final-round MLE evaluations: eval_a || eval_b || eval_c || eval_z.
    pub final_evals: &'a [u8],
    /// KZG opening proof (G1) at the final sumcheck challenge point.
    pub kzg_opening: &'a [u8],
}

impl<'a> HyperPlonkProof<'a> {
    /// Parse a canonical HyperPlonk proof. Length-only validation; the
    /// sumcheck polynomials are not checked for Fr-range validity (that
    /// happens inside the verifier during challenge derivation).
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, OnChainError> {
        use sizes::{
            FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN, G1_LEN, MAX_SUMCHECK_ROUNDS, MIN_PROOF_LEN,
            SUMCHECK_POLY_LEN,
        };
        if bytes.len() < MIN_PROOF_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let (a, rest) = bytes.split_at(G1_LEN);
        let (b, rest) = rest.split_at(G1_LEN);
        let (c, rest) = rest.split_at(G1_LEN);
        let (z, rest) = rest.split_at(G1_LEN);
        let (rounds_bytes, rest) = rest.split_at(4);
        let sumcheck_rounds = u32::from_le_bytes([
            rounds_bytes[0], rounds_bytes[1], rounds_bytes[2], rounds_bytes[3],
        ]);
        if sumcheck_rounds > MAX_SUMCHECK_ROUNDS {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let polys_len = (sumcheck_rounds as usize)
            .checked_mul(SUMCHECK_POLY_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let expected_len = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        if bytes.len() != expected_len {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let (sumcheck_polys, rest) = rest.split_at(polys_len);
        let (final_evals, kzg_opening) = rest.split_at(FINAL_EVALS * FR_LEN);
        debug_assert_eq!(kzg_opening.len(), G1_LEN);
        Ok(Self {
            a, b, c, z, sumcheck_rounds,
            sumcheck_polys, final_evals, kzg_opening,
        })
    }

    /// Iterate over the `sumcheck_rounds` round polynomials.
    pub fn round_polys(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.sumcheck_polys.chunks_exact(sizes::SUMCHECK_POLY_LEN)
    }
}

/// HyperPlonk verifying key.
///
/// Smaller than PLONK's because there's no `Q_*` selector polynomial
/// commitments (gates are checked via MLE sumcheck directly) nor
/// permutation σ_i (handled by the grand-product MLE).
///
/// **Placeholder** — real VK fields TBD per Phase 3 reference impl.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperPlonkVerifyingKey {
    /// Number of public inputs.
    pub n_public: u32,
    /// `log₂` of circuit size (defines the boolean hypercube dimension).
    pub num_variables: u32,
    /// G2 SRS element for KZG pairing check.
    pub x2_g2: [u8; 128],
    /// Preprocessing commitment for the gate constraint
    /// (placeholder — real impl will have several of these).
    pub gate_g1: [u8; sizes::G1_LEN],
}

impl HyperPlonkVerifyingKey {
    /// Serialized VK length.
    pub const SERIALIZED_LEN: usize = 4 + 4 + 128 + sizes::G1_LEN;

    /// Decode from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let n_public =
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let num_variables =
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut x2_g2 = [0u8; 128];
        x2_g2.copy_from_slice(&bytes[8..136]);
        let mut gate_g1 = [0u8; sizes::G1_LEN];
        gate_g1.copy_from_slice(&bytes[136..136 + sizes::G1_LEN]);
        Ok(Self { n_public, num_variables, x2_g2, gate_g1 })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SERIALIZED_LEN);
        out.extend_from_slice(&self.n_public.to_le_bytes());
        out.extend_from_slice(&self.num_variables.to_le_bytes());
        out.extend_from_slice(&self.x2_g2);
        out.extend_from_slice(&self.gate_g1);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sizes::{
        FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN, G1_LEN, MIN_PROOF_LEN, SUMCHECK_POLY_LEN,
    };

    fn proof_bytes_for_rounds(rounds: u32) -> Vec<u8> {
        let polys_len = (rounds as usize) * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        let mut buf = vec![0xAB; total];
        // Fill sumcheck_rounds u32 LE at offset 256.
        buf[256..260].copy_from_slice(&rounds.to_le_bytes());
        buf
    }

    #[test]
    fn proof_layout_constants_consistent() {
        assert_eq!(MIN_PROOF_LEN, 4 * G1_LEN + 4 + 4 * FR_LEN + G1_LEN);
        assert_eq!(MIN_PROOF_LEN, 452);
    }

    #[test]
    fn proof_parses_zero_rounds_edge_case() {
        let buf = proof_bytes_for_rounds(0);
        let p = HyperPlonkProof::from_bytes(&buf).unwrap();
        assert_eq!(p.sumcheck_rounds, 0);
        assert_eq!(p.sumcheck_polys.len(), 0);
        assert_eq!(p.round_polys().count(), 0);
    }

    #[test]
    fn proof_parses_10_rounds_circuit_size_1024() {
        let buf = proof_bytes_for_rounds(10);
        let p = HyperPlonkProof::from_bytes(&buf).unwrap();
        assert_eq!(p.sumcheck_rounds, 10);
        assert_eq!(p.sumcheck_polys.len(), 10 * SUMCHECK_POLY_LEN);
        assert_eq!(p.round_polys().count(), 10);
        for rp in p.round_polys() {
            assert_eq!(rp.len(), SUMCHECK_POLY_LEN);
        }
    }

    #[test]
    fn proof_rejects_rounds_over_max() {
        let bad_rounds = sizes::MAX_SUMCHECK_ROUNDS + 1;
        let polys_len = (bad_rounds as usize) * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        let mut buf = vec![0xAB; total];
        buf[256..260].copy_from_slice(&bad_rounds.to_le_bytes());
        assert!(matches!(
            HyperPlonkProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_wrong_length() {
        let buf = vec![0u8; MIN_PROOF_LEN - 1];
        assert!(matches!(
            HyperPlonkProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn vk_roundtrip() {
        let vk = HyperPlonkVerifyingKey {
            n_public: 3,
            num_variables: 10,
            x2_g2: [0xCD; 128],
            gate_g1: [0xEF; G1_LEN],
        };
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), HyperPlonkVerifyingKey::SERIALIZED_LEN);
        let decoded = HyperPlonkVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
    }

    #[test]
    fn vk_rejects_wrong_length() {
        let short = vec![0u8; HyperPlonkVerifyingKey::SERIALIZED_LEN - 1];
        assert!(matches!(
            HyperPlonkVerifyingKey::from_bytes(&short),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }
}
