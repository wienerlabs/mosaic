//! Evaluation bundle layout for Halo2-KZG proofs.
//!
//! Halo2's proof carries a flat `evaluations` byte buffer whose length
//! depends on the circuit's structure. This module defines a **scaffold
//! layout convention** that carves the flat buffer into typed slots so
//! the verifier's vanishing-identity check can access each evaluation
//! by name.
//!
//! ## Scaffold layout (session 4e-partial)
//!
//! The bundle is ordered as:
//!
//! | Index range | Slot | Count |
//! |---|---|---|
//! | [0, 3) | Wire evaluations `a(ξ), b(ξ), c(ξ)` | 3 |
//! | [3, 8) | Selector evaluations `q_M, q_L, q_R, q_O, q_C` | 5 |
//! | [8, 13) | Permutation evaluations `z, z_next, σ_1, σ_2, σ_3` | 5 |
//! | [13, 16) | Lookup evaluations `input, table, m` | 3 |
//! | [16, 16+n_quotient) | Quotient chunk evaluations `h_0(ξ) … h_{m-1}(ξ)` | `n_quotient` |
//!
//! Required `n_evals = 16 + n_quotient`. For a typical n_quotient = 3
//! circuit the bundle is 19 × 32 = 608 bytes.
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
    circuit::{LookupEvals, PermutationEvals, SelectorEvals, WireEvals},
};
use alloc::vec::Vec;
use ark_bn254::Fr;
use mosaic_core::OnChainError;
use mosaic_plonk::field::fr_from_canonical_bytes;

/// Fixed-position evaluation indices.
pub mod idx {
    // Wires at [0, 3).
    pub const A: usize = 0;
    pub const B: usize = 1;
    pub const C: usize = 2;
    // Selectors at [3, 8).
    pub const Q_M: usize = 3;
    pub const Q_L: usize = 4;
    pub const Q_R: usize = 5;
    pub const Q_O: usize = 6;
    pub const Q_C: usize = 7;
    // Permutation at [8, 13).
    pub const Z: usize = 8;
    pub const Z_NEXT: usize = 9;
    pub const SIGMA_1: usize = 10;
    pub const SIGMA_2: usize = 11;
    pub const SIGMA_3: usize = 12;
    // Lookup at [13, 16).
    pub const LOOKUP_INPUT: usize = 13;
    pub const LOOKUP_TABLE: usize = 14;
    pub const LOOKUP_M: usize = 15;
    /// Number of fixed-position evaluations before the quotient tail.
    pub const FIXED_SLOTS: usize = 16;
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
    /// Lookup argument evaluations.
    pub lookup: LookupEvals,
    /// Quotient chunk evaluations `h_i(ξ)`. Length = `n_quotient`.
    pub quotient_chunks: Vec<Fr>,
}

impl EvaluationBundle {
    /// Decode from the proof's flat `evaluations` bytes + `n_quotient`
    /// from the header.
    ///
    /// Required `n_evals == FIXED_SLOTS + n_quotient`. Returns
    /// [`OnChainError::ProofLengthMismatch`] on any size mismatch.
    pub fn from_proof(proof: &Halo2KzgProof<'_>) -> Result<Self, OnChainError> {
        let n_quotient = proof.n_quotient as usize;
        let expected_evals = idx::FIXED_SLOTS + n_quotient;
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
        let lookup = LookupEvals {
            input: fr_at(idx::LOOKUP_INPUT)?,
            table: fr_at(idx::LOOKUP_TABLE)?,
            m: fr_at(idx::LOOKUP_M)?,
        };

        let mut quotient_chunks = Vec::with_capacity(n_quotient);
        for i in 0..n_quotient {
            quotient_chunks.push(fr_at(idx::FIXED_SLOTS + i)?);
        }

        Ok(Self {
            wires,
            selectors,
            permutation,
            lookup,
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
    use mosaic_plonk::field::fr_to_canonical_bytes;

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
