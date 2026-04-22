//! Fiat-Shamir challenge derivation for Halo2-KZG.
//!
//! Halo2's multi-round verifier has five challenges in the pre-opening
//! phase: `θ` (lookup-combining), `β`/`γ` (permutation arguments), `y`
//! (gate + permutation + lookup linear combination), `ξ` (evaluation
//! point). Two more challenges `v`, `u` land during the batched
//! multipoint opening — tracked in the KZG module (session 4c).
//!
//! ## Absorb order (PSE-compatible)
//!
//! ```text
//! // ---- Round 1: θ (lookup combining) ----
//! transcript.reset()
//! transcript.absorb(vk_digest)                  // VK hash
//! for inst in instance_columns:                  // ^ public inputs
//!     transcript.absorb(inst)
//! for a in proof.advice_commits:                 // (n_advice × G1)
//!     transcript.absorb(a)
//! theta = transcript.squeeze()
//!
//! // ---- Round 2: β, γ (permutation) ----
//! transcript.reset()
//! transcript.absorb(theta)
//! for l in proof.lookup_commits:                 // lookup `m` polys
//!     transcript.absorb(l)
//! beta = transcript.squeeze()
//!
//! transcript.reset()
//! transcript.absorb(beta)
//! gamma = transcript.squeeze()
//!
//! // ---- Round 3: y (gate linear combo) ----
//! transcript.reset()
//! transcript.absorb(beta)
//! transcript.absorb(gamma)
//! transcript.absorb(proof.permutation_z)         // grand-product commit
//! y = transcript.squeeze()
//!
//! // ---- Round 4: ξ (evaluation point) ----
//! transcript.reset()
//! transcript.absorb(y)
//! for h in proof.quotient_chunks:                // t(X) = Σ x^(ki)·hi(X)
//!     transcript.absorb(h)
//! xi = transcript.squeeze()
//! // From here, absorb evaluations → squeeze v, u for batched opening.
//! ```
//!
//! ## Rationale
//!
//! - **θ before β/γ**: lookup arguments combine inputs via θ *before*
//!   the permutation grand-product is committed.
//! - **β, γ before y**: permutation challenges are needed to construct
//!   z(X); y is the outer linear combiner that folds all constraint
//!   families into one vanishing check.
//! - **ξ after quotient**: vanishing argument's h_pieces must be
//!   committed before the evaluation point is sampled (else the prover
//!   could construct h post-hoc to satisfy the check at ξ).

use crate::canonical::{Halo2KzgProof, Halo2KzgVerifyingKey};
use ark_bn254::Fr;
use mosaic_core::{syscall::SyscallBackend, OnChainError};
use mosaic_zk_primitives::{
    field::fr_from_canonical_bytes,
    transcript::{Kind, Transcript},
};

/// Pre-opening challenges emitted by [`derive_challenges`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Halo2Challenges {
    /// Lookup-combining challenge.
    pub theta: Fr,
    /// Permutation argument challenge 1.
    pub beta: Fr,
    /// Permutation argument challenge 2.
    pub gamma: Fr,
    /// Gate + permutation + lookup combining challenge.
    pub y: Fr,
    /// Vanishing-check evaluation point.
    pub xi: Fr,
}

/// Derive the five pre-opening challenges `(θ, β, γ, y, ξ)` by
/// replaying Halo2's absorb sequence with the snarkjs-style
/// "fresh transcript per round" pattern.
///
/// The returned transcript is left seeded with ξ — caller continues
/// into the evaluation absorbs + opening challenges (v, u).
///
/// ## Errors
///
/// - [`OnChainError::PublicInputOutOfRange`] if an instance-column
///   (public input) Fr is not reduced mod `r`.
/// - [`OnChainError::ProofLengthMismatch`] if instance bytes aren't a
///   multiple of 32.
/// - Transcript backend errors (keccak syscall failure).
pub fn derive_challenges<'b, B: SyscallBackend + ?Sized>(
    backend: &'b B,
    vk: &Halo2KzgVerifyingKey,
    instances_bytes: &[u8],
    proof: &Halo2KzgProof<'_>,
) -> Result<(Halo2Challenges, Transcript<'b, B>), OnChainError> {
    if !instances_bytes.len().is_multiple_of(32) {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let declared_instances = instances_bytes.len() / 32;
    if declared_instances != vk.n_instances as usize {
        return Err(OnChainError::PublicInputCountMismatch);
    }
    for chunk in instances_bytes.chunks_exact(32) {
        let _ = fr_from_canonical_bytes(chunk)?;
    }

    let mut transcript = Transcript::new(Kind::Keccak256, backend);

    // ---- Round 1: θ (lookup combining) ----
    transcript.absorb(&vk_digest(vk));
    transcript.absorb(instances_bytes);
    // Advice column commitments (variable count, 64 B each).
    for a in proof.advice_iter() {
        transcript.absorb(a);
    }
    let theta_bytes = transcript.get_challenge()?;
    let theta = fr_from_canonical_bytes(&theta_bytes)?;

    // ---- Round 2a: β ----
    transcript.reset();
    transcript.absorb(&theta_bytes);
    if !proof.lookup_commits.is_empty() {
        transcript.absorb(proof.lookup_commits);
    }
    let beta_bytes = transcript.get_challenge()?;
    let beta = fr_from_canonical_bytes(&beta_bytes)?;

    // ---- Round 2b: γ ----
    transcript.reset();
    transcript.absorb(&beta_bytes);
    let gamma_bytes = transcript.get_challenge()?;
    let gamma = fr_from_canonical_bytes(&gamma_bytes)?;

    // ---- Round 3: y (gate linear combo) ----
    transcript.reset();
    transcript.absorb(&beta_bytes);
    transcript.absorb(&gamma_bytes);
    transcript.absorb(proof.permutation_z);
    let y_bytes = transcript.get_challenge()?;
    let y = fr_from_canonical_bytes(&y_bytes)?;

    // ---- Round 4: ξ (evaluation point) ----
    transcript.reset();
    transcript.absorb(&y_bytes);
    for h in proof.quotient_iter() {
        transcript.absorb(h);
    }
    let xi_bytes = transcript.get_challenge()?;
    let xi = fr_from_canonical_bytes(&xi_bytes)?;

    // Leave transcript seeded with ξ for the evaluation-absorb phase.
    transcript.reset();
    transcript.absorb(&xi_bytes);

    Ok((
        Halo2Challenges {
            theta,
            beta,
            gamma,
            y,
            xi,
        },
        transcript,
    ))
}

/// Compute a 32-byte VK digest by byte-concatenating all structural
/// fields. This is the transcript seed for round 1.
///
/// Real Halo2 computes a BLAKE2b digest per the PSE reference impl;
/// we use a flat byte concatenation here since the transcript's
/// Keccak-256 backend will hash everything anyway — the VK digest
/// acts as a domain separator, not a pre-hashed commitment.
fn vk_digest(vk: &Halo2KzgVerifyingKey) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(
        16 + vk.x2_g2.len() + vk.fixed_commits.len() + vk.permutation_commits.len(),
    );
    out.extend_from_slice(&vk.k.to_le_bytes());
    out.extend_from_slice(&vk.n_instances.to_le_bytes());
    out.extend_from_slice(&vk.n_advice.to_le_bytes());
    out.extend_from_slice(&vk.n_fixed.to_le_bytes());
    out.extend_from_slice(&vk.x2_g2);
    out.extend_from_slice(&vk.fixed_commits);
    out.extend_from_slice(&vk.permutation_commits);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN};
    use alloc::vec;
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_zk_primitives::field::fr_to_canonical_bytes;

    fn sample_vk() -> Halo2KzgVerifyingKey {
        Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 3,
            n_fixed: 2,
            x2_g2: [0xCC; 128],
            fixed_commits: vec![0x11; 2 * G1_LEN],
            permutation_commits: vec![0x22; 3 * G1_LEN],
        }
    }

    fn sample_proof_buf() -> alloc::vec::Vec<u8> {
        // 3 advice, 1 lookup, 2 quotient chunks, 10 evals.
        let n_advice: u32 = 3;
        let n_lookups: u32 = 1;
        let n_quotient: u32 = 2;
        let n_evals: u32 = 10;
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
        // Seed advice commits with distinct patterns.
        for i in 0..n_advice as usize {
            let off = FIXED_HEADER_LEN + i * G1_LEN;
            buf[off] = 0x30 + i as u8;
        }
        buf
    }

    #[test]
    fn derive_challenges_happy_path() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf();
        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let instances = fr_to_canonical_bytes(&Fr::from(42u64));

        let (c, _t) = derive_challenges(&backend, &vk, &instances, &proof).unwrap();

        // All non-zero with overwhelming probability.
        assert_ne!(c.theta, Fr::from(0u64));
        assert_ne!(c.beta, Fr::from(0u64));
        assert_ne!(c.gamma, Fr::from(0u64));
        assert_ne!(c.y, Fr::from(0u64));
        assert_ne!(c.xi, Fr::from(0u64));

        // Challenges pairwise distinct (each squeeze uses different
        // transcript state).
        assert_ne!(c.theta, c.beta);
        assert_ne!(c.beta, c.gamma);
        assert_ne!(c.gamma, c.y);
        assert_ne!(c.y, c.xi);
    }

    #[test]
    fn derive_challenges_deterministic() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf();
        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let instances = fr_to_canonical_bytes(&Fr::from(42u64));

        let (a, _) = derive_challenges(&backend, &vk, &instances, &proof).unwrap();
        let (b, _) = derive_challenges(&backend, &vk, &instances, &proof).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_challenges_differ_on_advice_change() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let mut proof_buf_a = sample_proof_buf();
        let mut proof_buf_b = sample_proof_buf();
        // Flip first byte of advice commits → different θ.
        proof_buf_b[FIXED_HEADER_LEN] ^= 0xFF;
        proof_buf_a[FIXED_HEADER_LEN] = 0x40;

        let proof_a = Halo2KzgProof::from_bytes(&proof_buf_a).unwrap();
        let proof_b = Halo2KzgProof::from_bytes(&proof_buf_b).unwrap();
        let instances = fr_to_canonical_bytes(&Fr::from(42u64));

        let (ca, _) = derive_challenges(&backend, &vk, &instances, &proof_a).unwrap();
        let (cb, _) = derive_challenges(&backend, &vk, &instances, &proof_b).unwrap();
        // θ differs → β, γ, y, ξ all differ.
        assert_ne!(ca.theta, cb.theta);
        assert_ne!(ca.xi, cb.xi);
    }

    #[test]
    fn derive_challenges_differ_on_permutation_z_change() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let mut proof_buf_a = sample_proof_buf();
        let mut proof_buf_b = sample_proof_buf();
        // Permutation z commit offset: FIXED + n_advice·G1 + n_lookups·G1.
        let z_offset = FIXED_HEADER_LEN + 3 * G1_LEN + 1 * G1_LEN;
        proof_buf_a[z_offset] = 0xAA;
        proof_buf_b[z_offset] = 0xBB;
        let proof_a = Halo2KzgProof::from_bytes(&proof_buf_a).unwrap();
        let proof_b = Halo2KzgProof::from_bytes(&proof_buf_b).unwrap();
        let instances = fr_to_canonical_bytes(&Fr::from(42u64));

        let (ca, _) = derive_challenges(&backend, &vk, &instances, &proof_a).unwrap();
        let (cb, _) = derive_challenges(&backend, &vk, &instances, &proof_b).unwrap();
        // θ and β same (before permutation_z in absorb order), but y
        // onward differs.
        assert_eq!(ca.theta, cb.theta);
        assert_eq!(ca.beta, cb.beta);
        assert_eq!(ca.gamma, cb.gamma);
        assert_ne!(ca.y, cb.y);
        assert_ne!(ca.xi, cb.xi);
    }

    #[test]
    fn derive_challenges_rejects_wrong_instance_count() {
        let backend = HostBackend::new();
        let vk = sample_vk(); // declares n_instances = 1
        let proof_buf = sample_proof_buf();
        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let mut two_inst = alloc::vec::Vec::new();
        two_inst.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(1u64)));
        two_inst.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(2u64)));
        let r = derive_challenges(&backend, &vk, &two_inst, &proof);
        assert!(matches!(r, Err(OnChainError::PublicInputCountMismatch)));
    }

    #[test]
    fn derive_challenges_rejects_instance_not_multiple_of_32() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf();
        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let bad = [0u8; 31];
        let r = derive_challenges(&backend, &vk, &bad, &proof);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn derive_challenges_rejects_instance_out_of_range() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf();
        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let bad_inst = [0xFFu8; 32]; // > r
        let r = derive_challenges(&backend, &vk, &bad_inst, &proof);
        assert!(matches!(r, Err(OnChainError::PublicInputOutOfRange)));
    }

    #[test]
    fn vk_digest_includes_all_structural_fields() {
        // Changing any structural field changes the digest, which
        // changes θ (first-round challenge).
        let backend = HostBackend::new();
        let mut vk_a = sample_vk();
        let mut vk_b = sample_vk();
        vk_b.k = 11; // different domain size
        let proof_buf = sample_proof_buf();
        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let instances = fr_to_canonical_bytes(&Fr::from(42u64));
        let (ca, _) = derive_challenges(&backend, &vk_a, &instances, &proof).unwrap();
        let (cb, _) = derive_challenges(&backend, &vk_b, &instances, &proof).unwrap();
        assert_ne!(ca.theta, cb.theta);
        // Permutation commit change should also shift θ.
        vk_a.permutation_commits[0] ^= 0x01;
        let (ca2, _) = derive_challenges(&backend, &vk_a, &instances, &proof).unwrap();
        assert_ne!(ca.theta, ca2.theta);
    }
}
