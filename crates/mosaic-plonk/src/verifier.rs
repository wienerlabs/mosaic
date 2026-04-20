//! PLONK verifier skeleton.
//!
//! Phase 1 scaffolds the `ProofSystem` impl so that `mosaic-program`
//! dispatch compiles and returns a deterministic
//! `UnimplementedProofSystem` error for the PLONK arm. Full
//! cryptographic round logic is tracked by
//! [issue #1](https://github.com/wienerlabs/mosaic/issues/1).
//!
//! ## Round-by-round skeleton (planned)
//!
//! The commented blocks below lay out what each round does so a Phase-2
//! implementer can drop math in without re-reading three papers:
//!
//! ```text
//! verify(vk_bytes, proof_bytes, public_inputs_bytes):
//!     vk    = PlonkVerifyingKey::from_bytes(vk_bytes)?;
//!     proof = PlonkProof::from_bytes(proof_bytes)?;
//!     pi    = parse_public_inputs(public_inputs_bytes, vk.n_public)?;
//!
//!     // Round 1: absorb VK + public inputs + (A, B, C) commitments.
//!     transcript.absorb(b"vk",  &vk_bytes);
//!     transcript.absorb(b"pi",  &pi);
//!     transcript.absorb(b"a", proof.a); transcript.absorb(b"b", proof.b);
//!     transcript.absorb(b"c", proof.c);
//!     // Squeeze β, γ.
//!
//!     // Round 2: absorb Z commitment.
//!     transcript.absorb(b"z", proof.z);
//!     // Squeeze α.
//!
//!     // Round 3: absorb (T1, T2, T3) commitments.
//!     transcript.absorb(b"t1", proof.t1); …
//!     // Squeeze evaluation point ξ.
//!
//!     // Round 4: absorb evaluations at ξ.
//!     transcript.absorb(b"eval_a", proof.eval_a); …
//!     // Squeeze linear-combination challenge v, and u.
//!
//!     // Linearization polynomial L(X) reconstruction:
//!     //   L(X) = multi-scalar-multiplication over VK and proof commitments
//!     //        = Σ coefficients_i · Commitment_i
//!     //   coefficients are functions of α, β, γ, ξ, v, and the public
//!     //   input polynomial evaluation.
//!
//!     // KZG batched opening check:
//!     //   e(W_ξ + u·W_{ξω}, [1]_2) = e(
//!     //       ξ·W_ξ + u·ξ·ω·W_{ξω} + F - E,
//!     //       [X]_2,
//!     //   )
//!     // where F = L(X) + batched commitment, E = batched evaluations.
//!     //
//!     // Single pairing call over 2 pairs → ~24 000 CU on-chain.
//! ```

use crate::canonical::{PlonkProof, PlonkVerifyingKey};
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    OnChainError,
};

/// BN254 KZG-PLONK verifier.
///
/// Phase 1: type + trait-surface skeleton only. `verify()` returns
/// `UnimplementedProofSystem`. Do not ship as a production verifier.
#[derive(Copy, Clone, Debug, Default)]
pub struct PlonkKzgBn254;

impl PlonkKzgBn254 {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProofSystem for PlonkKzgBn254 {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::PlonkKzgBn254
    }

    fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        // Phase 1 intentionally validates byte layout (catches wire-format
        // regressions against the canonical spec) but does not perform
        // cryptographic verification. Keeps the dispatch path honest.
        let _vk = PlonkVerifyingKey::from_bytes(vk_bytes)?;
        let _proof = PlonkProof::from_bytes(proof_bytes)?;
        // TODO(mosaic-001): validate public_inputs_bytes length against
        // vk.n_public × FR_LEN and fold into the linearization MSM.
        let _ = public_inputs_bytes;
        Err(OnChainError::UnimplementedProofSystem)
    }

    fn estimated_compute_units(&self, _vk: &[u8], _proof: &[u8]) -> Option<u32> {
        // Target: ≤600 000 CU per ADR-0005. Estimate decomposition in
        // crate-level docs. Returning the budget upper bound so callers
        // requesting `set_compute_unit_limit` have a safe default even
        // before the full impl lands.
        Some(600_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{sizes, PlonkVerifyingKey};

    fn dummy_vk_bytes() -> alloc::vec::Vec<u8> {
        PlonkVerifyingKey {
            qm_g1: [0; sizes::G1_LEN], ql_g1: [0; sizes::G1_LEN],
            qr_g1: [0; sizes::G1_LEN], qo_g1: [0; sizes::G1_LEN],
            qc_g1: [0; sizes::G1_LEN],
            s1_g1: [0; sizes::G1_LEN], s2_g1: [0; sizes::G1_LEN],
            s3_g1: [0; sizes::G1_LEN],
            x2_g2: [0; sizes::G2_LEN], power: 10,
            k1: [0; sizes::FR_LEN], k2: [0; sizes::FR_LEN],
            omega: [0; sizes::FR_LEN], n_public: 1,
        }
        .to_bytes()
    }

    #[test]
    fn parses_wire_format_before_returning_unimplemented() {
        let v = PlonkKzgBn254::new();
        let vk = dummy_vk_bytes();
        let proof = alloc::vec![0u8; sizes::PROOF_LEN];
        let pi = alloc::vec![0u8; sizes::FR_LEN];
        let r = v.verify(&vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::UnimplementedProofSystem)));
    }

    #[test]
    fn rejects_wrong_proof_length_before_unimplemented() {
        // Wire-layout validation fires before the unimplemented error —
        // keeps wire-format contract enforced even in Phase 1.
        let v = PlonkKzgBn254::new();
        let vk = dummy_vk_bytes();
        let proof = alloc::vec![0u8; sizes::PROOF_LEN - 1];
        let pi = alloc::vec![0u8; sizes::FR_LEN];
        let r = v.verify(&vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_vk_length_before_unimplemented() {
        let v = PlonkKzgBn254::new();
        let vk = alloc::vec![0u8; sizes::VK_HEADER_LEN - 1];
        let proof = alloc::vec![0u8; sizes::PROOF_LEN];
        let pi = alloc::vec![0u8; sizes::FR_LEN];
        let r = v.verify(&vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn estimated_compute_units_returns_adr_target() {
        let v = PlonkKzgBn254::new();
        assert_eq!(v.estimated_compute_units(&[], &[]), Some(600_000));
    }
}
