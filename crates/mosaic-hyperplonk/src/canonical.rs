//! HyperPlonk canonical byte layout — **session-3d revision**.
//!
//! Expanded from the session-3 scaffold placeholder to a PLONK-style
//! gate + permutation layout, which is what Espresso's HyperPlonk
//! reference impl actually uses. The exact byte ordering still needs
//! to be pinned against an upstream fixture in session 3e; this
//! revision locks the *shape* so the verifier body can reference
//! stable field names.
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
//! This revision targets the Espresso-style layout: 4 witness
//! commitments + permutation grand-product + sumcheck round polys +
//! 12 final evaluations (4 wires + 5 selectors + 3 permutation σ) +
//! KZG opening.
//!
//! ## Proof layout
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0   | 64   | `a`: G1 commitment to witness A (as MLE) |
//! | 64  | 64   | `b`: G1 commitment to witness B |
//! | 128 | 64   | `c`: G1 commitment to witness C |
//! | 192 | 64   | `z`: G1 commitment to permutation grand-product MLE |
//! | 256 | 4    | `sumcheck_rounds` (u32 LE) — = log₂(circuit size) |
//! | 260 | 96 × N | `sumcheck_polys` — N round polynomials, each 3 × 32 B Fr coefficients (degree-2 per round for the zero-check sumcheck) |
//! | …   | 32 × 12 | Final evaluations at the sumcheck challenge point: `a, b, c, z, q_m, q_l, q_r, q_o, q_c, σ_1, σ_2, σ_3` |
//! | …   | 64   | KZG batched opening proof at the challenge point |
//!
//! Total size for `sumcheck_rounds = 10` (2^10 circuit):
//! 4·64 + 4 + 10·96 + 12·32 + 64 = **1732 B**. Still fits a single
//! Solana tx (1232 B limit → needs chunked upload for this size, but
//! borderline — circuits up to 2^6 with simple gates fit inline).
//!
//! ## Final-evals bundle convention
//!
//! The 12 × 32-byte evaluations appear in a fixed order matching
//! [`FinalEvalsIndex`]. The verifier's gate + permutation check reads
//! this bundle and feeds values into [`crate::gate::WireEvals`] +
//! [`crate::gate::SelectorEvals`] + the permutation σ struct (session
//! 3d-2).
//!
//! **TODO(mosaic-002-3e)**: Pin this layout against the chosen upstream
//! reference (Espresso) before any adapter in `mosaic-serde` can be
//! written.

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
    /// Number of Fr evaluations in the final bundle.
    ///
    /// Layout (session 3d):
    /// - 4 wire evaluations: `a, b, c, z` (indexes 0..4)
    /// - 5 selector evaluations: `q_m, q_l, q_r, q_o, q_c` (indexes 4..9)
    /// - 3 permutation σ evaluations: `σ_1, σ_2, σ_3` (indexes 9..12)
    pub const FINAL_EVALS: usize = 12;
    /// Fixed header length (everything before `sumcheck_polys`): 4 × G1 + u32.
    pub const FIXED_HEADER_LEN: usize = 4 * G1_LEN + 4;
    /// Fixed tail length (final evals + KZG opening): 12 × Fr + G1.
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

/// Byte offsets into the proof's `final_evals` bundle (12 × 32 B).
///
/// The ordering is fixed and defines the canonical layout contract
/// between provers and verifiers.
pub mod final_evals_index {
    /// Witness `a` evaluation at the sumcheck challenge point.
    pub const A: usize = 0;
    /// Witness `b` evaluation.
    pub const B: usize = 1;
    /// Witness `c` evaluation.
    pub const C: usize = 2;
    /// Permutation grand-product `z` evaluation.
    pub const Z: usize = 3;
    /// Multiplication-selector `q_M` evaluation.
    pub const Q_M: usize = 4;
    /// Left-wire selector `q_L` evaluation.
    pub const Q_L: usize = 5;
    /// Right-wire selector `q_R` evaluation.
    pub const Q_R: usize = 6;
    /// Output-wire selector `q_O` evaluation.
    pub const Q_O: usize = 7;
    /// Constant selector `q_C` evaluation.
    pub const Q_C: usize = 8;
    /// Permutation `σ_1` (left-wire) evaluation.
    pub const SIGMA_1: usize = 9;
    /// Permutation `σ_2` (right-wire) evaluation.
    pub const SIGMA_2: usize = 10;
    /// Permutation `σ_3` (output-wire) evaluation.
    pub const SIGMA_3: usize = 11;
}

/// HyperPlonk verifying key.
///
/// Session-3d revision expands the VK from a single `gate_g1`
/// placeholder to the full PLONK-style preprocessing:
/// 5 selector commitments + 3 permutation σ commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperPlonkVerifyingKey {
    /// Number of public inputs.
    pub n_public: u32,
    /// `log₂` of circuit size (defines the boolean hypercube dimension).
    pub num_variables: u32,
    /// G2 SRS element for KZG pairing check.
    pub x2_g2: [u8; 128],
    /// Selector commitment `[Q_M]` — multiplication selector MLE.
    pub q_m_g1: [u8; sizes::G1_LEN],
    /// Selector commitment `[Q_L]` — left-wire linear selector.
    pub q_l_g1: [u8; sizes::G1_LEN],
    /// Selector commitment `[Q_R]` — right-wire linear selector.
    pub q_r_g1: [u8; sizes::G1_LEN],
    /// Selector commitment `[Q_O]` — output-wire linear selector.
    pub q_o_g1: [u8; sizes::G1_LEN],
    /// Selector commitment `[Q_C]` — constant selector.
    pub q_c_g1: [u8; sizes::G1_LEN],
    /// Permutation σ commitment `[σ_1]` — left-wire permutation MLE.
    pub sigma_1_g1: [u8; sizes::G1_LEN],
    /// Permutation σ commitment `[σ_2]` — right-wire permutation MLE.
    pub sigma_2_g1: [u8; sizes::G1_LEN],
    /// Permutation σ commitment `[σ_3]` — output-wire permutation MLE.
    pub sigma_3_g1: [u8; sizes::G1_LEN],
    /// Permutation coset constant `k_1` for the left-wire identity
    /// factor in the PLONK grand-product (canonical 32-byte BE Fr).
    /// Sessions ≤17 hardcoded the triplet `(k_1, k_2, k_3) = (1, 2, 3)`;
    /// session 18 lifts this to a VK-side circuit-specific value so
    /// multi-point reductions can use any three distinct cosets.
    pub k_1: [u8; sizes::FR_LEN],
    /// Permutation coset constant `k_2` for the middle-wire identity
    /// factor. Must differ from `k_1` and `k_3` (otherwise the
    /// permutation argument loses its identity-separation property).
    pub k_2: [u8; sizes::FR_LEN],
    /// Permutation coset constant `k_3` for the output-wire identity
    /// factor. Must differ from `k_1` and `k_2`.
    pub k_3: [u8; sizes::FR_LEN],
}

impl HyperPlonkVerifyingKey {
    /// Number of preprocessed commitments (5 selectors + 3 σ).
    pub const NUM_COMMITS: usize = 8;

    /// Canonical BE-encoded Fr for the small integer `n`. Used to build
    /// the default `(k_1, k_2, k_3) = (1, 2, 3)` cosets in tests; real
    /// circuits pick distinct cosets via the VK ceremony.
    #[must_use]
    pub const fn fr_be_from_u64(n: u64) -> [u8; sizes::FR_LEN] {
        let mut out = [0u8; sizes::FR_LEN];
        let bytes = n.to_be_bytes();
        out[24] = bytes[0];
        out[25] = bytes[1];
        out[26] = bytes[2];
        out[27] = bytes[3];
        out[28] = bytes[4];
        out[29] = bytes[5];
        out[30] = bytes[6];
        out[31] = bytes[7];
        out
    }

    /// Serialized VK length:
    /// `n_public (4) + num_variables (4) + x2_g2 (128) + 8 × G1 (64)
    ///  + 3 × Fr (32)`.
    pub const SERIALIZED_LEN: usize =
        4 + 4 + 128 + Self::NUM_COMMITS * sizes::G1_LEN + 3 * sizes::FR_LEN;

    /// Decode from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let n_public = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let num_variables = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut x2_g2 = [0u8; 128];
        x2_g2.copy_from_slice(&bytes[8..136]);

        let mut off = 136;
        let mut take = || -> [u8; sizes::G1_LEN] {
            let mut out = [0u8; sizes::G1_LEN];
            out.copy_from_slice(&bytes[off..off + sizes::G1_LEN]);
            off += sizes::G1_LEN;
            out
        };
        let q_m_g1 = take();
        let q_l_g1 = take();
        let q_r_g1 = take();
        let q_o_g1 = take();
        let q_c_g1 = take();
        let sigma_1_g1 = take();
        let sigma_2_g1 = take();
        let sigma_3_g1 = take();
        let k_start = off;
        let mut take_fr = |i: usize| -> [u8; sizes::FR_LEN] {
            let mut out = [0u8; sizes::FR_LEN];
            let from = k_start + i * sizes::FR_LEN;
            out.copy_from_slice(&bytes[from..from + sizes::FR_LEN]);
            out
        };
        let k_1 = take_fr(0);
        let k_2 = take_fr(1);
        let k_3 = take_fr(2);
        Ok(Self {
            n_public,
            num_variables,
            x2_g2,
            q_m_g1,
            q_l_g1,
            q_r_g1,
            q_o_g1,
            q_c_g1,
            sigma_1_g1,
            sigma_2_g1,
            sigma_3_g1,
            k_1,
            k_2,
            k_3,
        })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SERIALIZED_LEN);
        out.extend_from_slice(&self.n_public.to_le_bytes());
        out.extend_from_slice(&self.num_variables.to_le_bytes());
        out.extend_from_slice(&self.x2_g2);
        out.extend_from_slice(&self.q_m_g1);
        out.extend_from_slice(&self.q_l_g1);
        out.extend_from_slice(&self.q_r_g1);
        out.extend_from_slice(&self.q_o_g1);
        out.extend_from_slice(&self.q_c_g1);
        out.extend_from_slice(&self.sigma_1_g1);
        out.extend_from_slice(&self.sigma_2_g1);
        out.extend_from_slice(&self.sigma_3_g1);
        out.extend_from_slice(&self.k_1);
        out.extend_from_slice(&self.k_2);
        out.extend_from_slice(&self.k_3);
        out
    }

    /// Iterate all 8 commitments in canonical order (matches the absorb
    /// order used by the Fiat-Shamir transcript in session 3d-2).
    pub fn commits_iter(&self) -> impl Iterator<Item = &[u8; sizes::G1_LEN]> {
        use core::iter;
        iter::once(&self.q_m_g1)
            .chain(iter::once(&self.q_l_g1))
            .chain(iter::once(&self.q_r_g1))
            .chain(iter::once(&self.q_o_g1))
            .chain(iter::once(&self.q_c_g1))
            .chain(iter::once(&self.sigma_1_g1))
            .chain(iter::once(&self.sigma_2_g1))
            .chain(iter::once(&self.sigma_3_g1))
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
        assert_eq!(MIN_PROOF_LEN, 4 * G1_LEN + 4 + FINAL_EVALS * FR_LEN + G1_LEN);
        // 4·64 + 4 + 12·32 + 64 = 708.
        assert_eq!(MIN_PROOF_LEN, 708);
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

    fn sample_vk() -> HyperPlonkVerifyingKey {
        HyperPlonkVerifyingKey {
            n_public: 3,
            num_variables: 10,
            x2_g2: [0xCD; 128],
            q_m_g1: [0x11; G1_LEN],
            q_l_g1: [0x22; G1_LEN],
            q_r_g1: [0x33; G1_LEN],
            q_o_g1: [0x44; G1_LEN],
            q_c_g1: [0x55; G1_LEN],
            sigma_1_g1: [0x66; G1_LEN],
            sigma_2_g1: [0x77; G1_LEN],
            sigma_3_g1: [0x88; G1_LEN],
            k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
            k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
            k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
        }
    }

    #[test]
    fn vk_roundtrip() {
        let vk = sample_vk();
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), HyperPlonkVerifyingKey::SERIALIZED_LEN);
        // Session 18: 4 + 4 + 128 + 8·64 + 3·32 = 648 + 96 = 744 B.
        assert_eq!(bytes.len(), 744);
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

    #[test]
    fn vk_commits_iter_yields_all_eight() {
        let vk = sample_vk();
        let commits: alloc::vec::Vec<_> = vk.commits_iter().collect();
        assert_eq!(commits.len(), HyperPlonkVerifyingKey::NUM_COMMITS);
        // Order must match canonical: q_m, q_l, q_r, q_o, q_c, σ_1, σ_2, σ_3.
        assert_eq!(commits[0], &vk.q_m_g1);
        assert_eq!(commits[1], &vk.q_l_g1);
        assert_eq!(commits[2], &vk.q_r_g1);
        assert_eq!(commits[3], &vk.q_o_g1);
        assert_eq!(commits[4], &vk.q_c_g1);
        assert_eq!(commits[5], &vk.sigma_1_g1);
        assert_eq!(commits[6], &vk.sigma_2_g1);
        assert_eq!(commits[7], &vk.sigma_3_g1);
    }

    #[test]
    fn final_evals_indices_distinct_and_complete() {
        use final_evals_index::*;
        let all = [A, B, C, Z, Q_M, Q_L, Q_R, Q_O, Q_C, SIGMA_1, SIGMA_2, SIGMA_3];
        // All 12 slots filled.
        assert_eq!(all.len(), FINAL_EVALS);
        // All distinct (no index collision).
        let mut seen = [false; 12];
        for i in all {
            assert!(i < 12, "index {i} out of range");
            assert!(!seen[i], "duplicate index {i}");
            seen[i] = true;
        }
    }
}
