//! Evaluation bundle layout for Halo2-KZG proofs.
//!
//! Halo2's proof carries a flat `evaluations` byte buffer whose length
//! depends on the circuit's structure. This module defines a **scaffold
//! layout convention** that carves the flat buffer into typed slots so
//! the verifier's vanishing-identity check can access each evaluation
//! by name.
//!
//! ## Scaffold layout (session 4e-partial, arity-1)
//!
//! The single-column lookup bundle is ordered as:
//!
//! | Index range | Slot | Count |
//! |---|---|---|
//! | [0, 3) | Wire evaluations `a(ξ), b(ξ), c(ξ)` | 3 |
//! | [3, 8) | Selector evaluations `q_M, q_L, q_R, q_O, q_C` | 5 |
//! | [8, 13) | Permutation evaluations `z, z_next, σ_1, σ_2, σ_3` | 5 |
//! | [13, 16) | Lookup evaluations `input, table, m` | 3 |
//! | [16, `16+n_quotient`) | Quotient chunk evaluations `h_0(ξ) … h_{m-1}(ξ)` | `n_quotient` |
//!
//! Required `n_evals = 16 + n_quotient` for `lookup_arity = 1`.
//!
//! ## Multi-column extension (session 100, arity ≥ 2)
//!
//! When the proof header declares `lookup_arity = k > 1`, the bundle's
//! lookup section grows to carry `k` input + `k` table evaluations + 1
//! multiplicity evaluation:
//!
//! | Index range | Slot | Count |
//! |---|---|---|
//! | [0, 3) | Wire evaluations `a(ξ), b(ξ), c(ξ)` | 3 |
//! | [3, 8) | Selector evaluations `q_M, q_L, q_R, q_O, q_C` | 5 |
//! | [8, 13) | Permutation evaluations | 5 |
//! | [13, 13+k) | Multi-column input evals `input_0(ξ) … input_{k-1}(ξ)` | k |
//! | [13+k, 13+2k) | Multi-column table evals `table_0(ξ) … table_{k-1}(ξ)` | k |
//! | [13+2k, 13+2k+1) | Multiplicity eval `m(ξ)` | 1 |
//! | [13+2k+1, 13+2k+1+n_quotient) | Quotient chunks | n_quotient |
//!
//! Required `n_evals = 13 + 2k + 1 + n_quotient` for arity `k`.
//!
//! Backward compatibility: arity 1 reduces to the original 16-slot
//! layout (13 + 2·1 + 1 = 16). The single-column `LookupEvals` bundle
//! is preserved for `arity ≤ 1`; the `MultiColumnLookupEvals` bundle is
//! emitted for `arity ≥ 2`.
//!
//! ## Why a scaffold convention
//!
//! Real Halo2 circuits have variable evaluation counts depending on
//! the number of advice columns, lookups, and custom gates. Session 4f
//! will pin this against PSE `halo2_proofs::plonk::verifier::verify_proof`
//! and extend the canonical to carry column counts that drive variable
//! layouts. This scaffold convention is sufficient for structural
//! pipeline validation and unit testing without real fixtures.

use crate::{
    canonical::{sizes::FR_LEN, Halo2KzgProof},
    circuit::{LookupEvals, MultiColumnLookupEvals, PermutationEvals, SelectorEvals, WireEvals},
};
use alloc::vec::Vec;
use ark_bn254::Fr;
use mosaic_core::OnChainError;
use mosaic_zk_primitives::field::fr_from_canonical_bytes;

/// Fixed-position evaluation indices into the proof's `evaluations`
/// flat byte buffer.
pub mod idx {
    // --- Wires at [0, 3) ---
    /// Left-wire evaluation `a(ξ)`.
    pub const A: usize = 0;
    /// Right-wire evaluation `b(ξ)`.
    pub const B: usize = 1;
    /// Output-wire evaluation `c(ξ)`.
    pub const C: usize = 2;

    // --- Selectors at [3, 8) ---
    /// Multiplication selector `q_M(ξ)`.
    pub const Q_M: usize = 3;
    /// Left linear selector `q_L(ξ)`.
    pub const Q_L: usize = 4;
    /// Right linear selector `q_R(ξ)`.
    pub const Q_R: usize = 5;
    /// Output linear selector `q_O(ξ)`.
    pub const Q_O: usize = 6;
    /// Constant selector `q_C(ξ)`.
    pub const Q_C: usize = 7;

    // --- Permutation at [8, 13) ---
    /// Permutation grand-product `z(ξ)`.
    pub const Z: usize = 8;
    /// Permutation grand-product at the shifted point `z(ξ·ω)`.
    pub const Z_NEXT: usize = 9;
    /// Left-wire permutation `σ_1(ξ)`.
    pub const SIGMA_1: usize = 10;
    /// Right-wire permutation `σ_2(ξ)`.
    pub const SIGMA_2: usize = 11;
    /// Output-wire permutation `σ_3(ξ)`.
    pub const SIGMA_3: usize = 12;

    // --- Lookup at [13, 16) for arity 1; expands for arity ≥ 2. ---
    /// Lookup argument input expression `input(ξ)` (arity 1 alias).
    pub const LOOKUP_INPUT: usize = 13;
    /// Lookup table evaluation `table(ξ)` (arity 1 alias).
    pub const LOOKUP_TABLE: usize = 14;
    /// Lookup multiplicity polynomial `m(ξ)` (arity 1 position).
    pub const LOOKUP_M: usize = 15;

    /// First multi-column input slot (arity ≥ 2). Subsequent inputs at
    /// `LOOKUP_INPUT_BASE + i` for `i in 0..arity`.
    pub const LOOKUP_INPUT_BASE: usize = 13;

    /// Number of fixed-position evaluations before the quotient tail
    /// at arity 1 (16 = 13 + 2 + 1).
    pub const FIXED_SLOTS: usize = 16;

    /// Compute the fixed-slot count for a given lookup arity.
    /// `13 + 2k + 1` where 13 covers wires/selectors/permutation,
    /// 2k covers k input + k table evals, and 1 covers the m eval.
    #[must_use]
    pub const fn fixed_slots_for_arity(arity: u32) -> usize {
        13 + 2 * (arity as usize) + 1
    }
}

/// Decoded evaluation bundle — one typed struct per slot family.
#[derive(Clone, Debug)]
pub struct EvaluationBundle {
    /// Wire evaluations (a, b, c) at ξ.
    pub wires: WireEvals,
    /// Selector evaluations.
    pub selectors: SelectorEvals,
    /// Permutation grand-product + σ evaluations.
    pub permutation: PermutationEvals,
    /// Single-column lookup argument evaluations (arity-1 view of the
    /// proof's lookup data — first input/table column + m). For
    /// `arity = 1` this is the canonical lookup; for `arity ≥ 2` it
    /// holds the **first** column pair (useful for tests / fallback)
    /// and the full multi-column data is in [`Self::multi_lookup`].
    pub lookup: LookupEvals,
    /// **Session 100** — multi-column lookup data when the proof
    /// declares `lookup_arity ≥ 2`. `None` for `arity = 1` (the
    /// `lookup` field above is the canonical view in that case).
    ///
    /// When present, this is the structured multi-column eval bundle
    /// that the verifier feeds into
    /// [`crate::verify_multi_column_lookup_identity`].
    pub multi_lookup: Option<MultiColumnLookupEvals>,
    /// Quotient chunk evaluations `h_i(ξ)`. Length = `n_quotient`.
    pub quotient_chunks: Vec<Fr>,
}

impl EvaluationBundle {
    /// Decode from the proof's flat `evaluations` bytes + `n_quotient`
    /// from the header.
    ///
    /// Required:
    /// - For `lookup_arity ≤ 1`: `n_evals == FIXED_SLOTS + n_quotient`
    ///   (16 + n_quotient — the legacy single-column layout).
    /// - For `lookup_arity = k ≥ 2`: `n_evals == 13 + 2k + 1 + n_quotient`
    ///   (the multi-column layout).
    ///
    /// Returns [`OnChainError::ProofLengthMismatch`] on any size
    /// mismatch.
    pub fn from_proof(proof: &Halo2KzgProof<'_>) -> Result<Self, OnChainError> {
        let n_quotient = proof.n_quotient as usize;
        let arity = proof.lookup_arity;
        let lookup_slots = idx::fixed_slots_for_arity(arity);
        let expected_evals = lookup_slots + n_quotient;
        if proof.n_evals as usize != expected_evals {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let bytes = proof.evaluations;
        if bytes.len() != expected_evals * FR_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let fr_at = |i: usize| -> Result<Fr, OnChainError> {
            fr_from_canonical_bytes(&bytes[i * FR_LEN..(i + 1) * FR_LEN])
        };

        let wires = WireEvals {
            a: fr_at(idx::A)?,
            b: fr_at(idx::B)?,
            c: fr_at(idx::C)?,
        };
        let selectors = SelectorEvals {
            q_m: fr_at(idx::Q_M)?,
            q_l: fr_at(idx::Q_L)?,
            q_r: fr_at(idx::Q_R)?,
            q_o: fr_at(idx::Q_O)?,
            q_c: fr_at(idx::Q_C)?,
        };
        let permutation = PermutationEvals {
            z: fr_at(idx::Z)?,
            z_next: fr_at(idx::Z_NEXT)?,
            sigma_1: fr_at(idx::SIGMA_1)?,
            sigma_2: fr_at(idx::SIGMA_2)?,
            sigma_3: fr_at(idx::SIGMA_3)?,
        };

        // Decode lookup section based on arity.
        // Layout: [13, 13+arity) inputs, [13+arity, 13+2·arity) tables,
        // [13+2·arity] m_eval.
        let arity_us = arity as usize;
        let mut input_cols: Vec<Fr> = Vec::with_capacity(arity_us);
        for i in 0..arity_us {
            input_cols.push(fr_at(idx::LOOKUP_INPUT_BASE + i)?);
        }
        let mut table_cols: Vec<Fr> = Vec::with_capacity(arity_us);
        for i in 0..arity_us {
            table_cols.push(fr_at(idx::LOOKUP_INPUT_BASE + arity_us + i)?);
        }
        let m_eval = fr_at(idx::LOOKUP_INPUT_BASE + 2 * arity_us)?;

        // Always populate the legacy `lookup` field for callsites that
        // haven't been migrated to multi-column. For arity-1, this IS
        // the canonical view; for arity ≥ 2, it holds column 0.
        let lookup = LookupEvals {
            input: input_cols[0],
            table: table_cols[0],
            m: m_eval,
        };

        let multi_lookup = if arity >= 2 {
            Some(MultiColumnLookupEvals::try_new(
                input_cols,
                table_cols,
                m_eval,
            )?)
        } else {
            None
        };

        // Quotient chunks start after the lookup section.
        let quotient_base = lookup_slots;
        let mut quotient_chunks = Vec::with_capacity(n_quotient);
        for i in 0..n_quotient {
            quotient_chunks.push(fr_at(quotient_base + i)?);
        }

        Ok(Self {
            wires,
            selectors,
            permutation,
            lookup,
            multi_lookup,
            quotient_chunks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FIXED_HEADER_LEN, G1_LEN};
    use alloc::vec;
    use ark_ff::UniformRand;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use mosaic_zk_primitives::field::fr_to_canonical_bytes;

    fn build_proof_with_bundle(
        n_advice: u32,
        n_lookups: u32,
        n_quotient: u32,
        evals: &[Fr],
    ) -> Vec<u8> {
        let n_evals = evals.len() as u32;
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
        // Evaluations live after fixed_header + advice + lookup + z + quotient.
        let evals_off = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN;
        for (i, e) in evals.iter().enumerate() {
            let b = fr_to_canonical_bytes(e);
            buf[evals_off + i * FR_LEN..evals_off + (i + 1) * FR_LEN].copy_from_slice(&b);
        }
        buf
    }

    #[test]
    fn decodes_typical_bundle() {
        let mut r = StdRng::seed_from_u64(1);
        let mut evals = alloc::vec::Vec::with_capacity(19);
        for _ in 0..19 {
            evals.push(Fr::rand(&mut r));
        }
        let buf = build_proof_with_bundle(5, 1, 3, &evals);
        let proof = Halo2KzgProof::from_bytes(&buf).unwrap();
        let bundle = EvaluationBundle::from_proof(&proof).unwrap();

        assert_eq!(bundle.wires.a, evals[idx::A]);
        assert_eq!(bundle.wires.b, evals[idx::B]);
        assert_eq!(bundle.wires.c, evals[idx::C]);
        assert_eq!(bundle.selectors.q_m, evals[idx::Q_M]);
        assert_eq!(bundle.selectors.q_c, evals[idx::Q_C]);
        assert_eq!(bundle.permutation.z, evals[idx::Z]);
        assert_eq!(bundle.permutation.sigma_3, evals[idx::SIGMA_3]);
        assert_eq!(bundle.lookup.m, evals[idx::LOOKUP_M]);
        assert_eq!(bundle.quotient_chunks.len(), 3);
        assert_eq!(bundle.quotient_chunks[0], evals[idx::FIXED_SLOTS]);
        assert_eq!(bundle.quotient_chunks[2], evals[idx::FIXED_SLOTS + 2]);
    }

    #[test]
    fn decodes_minimal_bundle_n_quotient_one() {
        let evals = alloc::vec![Fr::from(1u64); 17]; // 16 + 1 quotient
        let buf = build_proof_with_bundle(1, 0, 1, &evals);
        let proof = Halo2KzgProof::from_bytes(&buf).unwrap();
        let bundle = EvaluationBundle::from_proof(&proof).unwrap();
        assert_eq!(bundle.quotient_chunks.len(), 1);
    }

    #[test]
    fn rejects_wrong_n_evals() {
        // n_evals = 18 but n_quotient = 3 → expected 19.
        let evals = alloc::vec![Fr::from(0u64); 18];
        let buf = build_proof_with_bundle(1, 0, 3, &evals);
        let proof = Halo2KzgProof::from_bytes(&buf).unwrap();
        assert!(matches!(
            EvaluationBundle::from_proof(&proof),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn rejects_n_evals_below_fixed_slots() {
        // n_evals = 10 but layout needs at least 16 (FIXED_SLOTS).
        let evals = alloc::vec![Fr::from(0u64); 10];
        let buf = build_proof_with_bundle(1, 0, 0, &evals);
        // n_quotient = 0 → expected = 16, we have 10, mismatch.
        let proof = Halo2KzgProof::from_bytes(&buf).unwrap();
        assert!(matches!(
            EvaluationBundle::from_proof(&proof),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn decodes_n_quotient_zero_edge_case() {
        // n_evals = 16, n_quotient = 0 → only fixed slots.
        let evals = alloc::vec![Fr::from(42u64); 16];
        let buf = build_proof_with_bundle(1, 0, 0, &evals);
        let proof = Halo2KzgProof::from_bytes(&buf).unwrap();
        let bundle = EvaluationBundle::from_proof(&proof).unwrap();
        assert_eq!(bundle.quotient_chunks.len(), 0);
        assert_eq!(bundle.wires.a, Fr::from(42u64));
    }
}
