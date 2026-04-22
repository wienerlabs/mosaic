//! Fiat-Shamir challenge derivation for HyperPlonk.
//!
//! The verifier squeezes three pre-sumcheck challenges, then one per
//! sumcheck round. This module handles only the pre-sumcheck
//! sequence — sumcheck-local challenge squeezing lives inside
//! [`crate::sumcheck::verify_sumcheck`].
//!
//! ## Absorb order (canonical — three rounds, transcript-per-round)
//!
//! The order is the binding contract between prover and verifier.
//! Changing it silently breaks soundness. Documented here in one
//! place so the prover can mirror it.
//!
//! This follows the snarkjs-style "fresh transcript per round" pattern
//! used by `mosaic-plonk::challenges`: each round starts with
//! `transcript.reset()`, absorbs the prior challenges + any new
//! commitments, and squeezes one challenge.
//!
//! ```text
//! // ---- Round 1: β ----
//! transcript.reset()
//! transcript.absorb(vk.x2_g2)           // 128 B
//! transcript.absorb(vk.n_public)        // 4 B LE
//! transcript.absorb(vk.num_variables)   // 4 B LE
//! for commit in vk.commits_iter():      // 8 G1 (selectors + σ)
//!     transcript.absorb(commit)
//! transcript.absorb(public_inputs)      // n × 32 B
//! transcript.absorb(proof.a)            // 64 B
//! transcript.absorb(proof.b)            // 64 B
//! transcript.absorb(proof.c)            // 64 B
//! beta = transcript.squeeze()
//!
//! // ---- Round 2: γ ----
//! transcript.reset()
//! transcript.absorb(beta)
//! gamma = transcript.squeeze()
//!
//! // ---- Round 3: α ----
//! transcript.reset()
//! transcript.absorb(beta)
//! transcript.absorb(gamma)
//! transcript.absorb(proof.z)            // 64 B grand-product commit
//! alpha = transcript.squeeze()
//! // From here, sumcheck takes over on a fresh transcript seeded
//! // with α (see `verifier::verify` orchestration).
//! ```
//!
//! ## Rationale
//!
//! - **β, γ before Z**: the prover needs β and γ to compute the
//!   permutation grand-product polynomial Z; the verifier's derivation
//!   must match, so the squeeze order puts β, γ first.
//! - **α after Z**: α combines gate and permutation zero-checks in the
//!   sumcheck; it's sampled after all polynomials visible to both
//!   parties have been committed.
//! - **Fresh transcript per round** with prior challenges re-absorbed:
//!   aligns with `mosaic-plonk` convention, gives each squeeze
//!   domain-separation without an explicit label, and makes the
//!   protocol byte-compatible with snarkjs-family transcripts.

use crate::canonical::{HyperPlonkProof, HyperPlonkVerifyingKey};
use ark_bn254::Fr;
use mosaic_core::{syscall::SyscallBackend, OnChainError};
use mosaic_zk_primitives::{
    field::fr_from_canonical_bytes,
    transcript::{Kind, Transcript},
};

/// Pre-sumcheck challenges emitted by [`derive_challenges`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PreSumcheckChallenges {
    /// Permutation argument challenge 1.
    pub beta: Fr,
    /// Permutation argument challenge 2.
    pub gamma: Fr,
    /// Gate + permutation combining challenge used as the zero-check
    /// sumcheck's linear combiner.
    pub alpha: Fr,
}

/// Derive the three pre-sumcheck challenges `(β, γ, α)` with the
/// snarkjs-style "fresh transcript per round" pattern.
///
/// The returned transcript is left in the "seeded with α" state — the
/// caller feeds it into the sumcheck verifier so sumcheck-round
/// absorbs continue from that seed.
///
/// ## Errors
///
/// - [`OnChainError::PublicInputOutOfRange`] if any public input Fr is
///   not reduced mod `r`.
/// - [`OnChainError::PublicInputCountMismatch`] if the public-input
///   byte count disagrees with `vk.n_public`.
/// - [`OnChainError::ProofLengthMismatch`] if the public-input buffer
///   length is not a multiple of 32 bytes.
/// - Transcript backend errors (keccak syscall failure).
pub fn derive_challenges<'b, B: SyscallBackend + ?Sized>(
    backend: &'b B,
    vk: &HyperPlonkVerifyingKey,
    public_inputs_bytes: &[u8],
    proof: &HyperPlonkProof<'_>,
) -> Result<(PreSumcheckChallenges, Transcript<'b, B>), OnChainError> {
    // Public-input byte buffer must be a whole number of Fr elements.
    if !public_inputs_bytes.len().is_multiple_of(32) {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let declared_pi = public_inputs_bytes.len() / 32;
    if declared_pi != vk.n_public as usize {
        return Err(OnChainError::PublicInputCountMismatch);
    }

    // Validate every public-input Fr is in range (consensus-critical;
    // out-of-range values would produce divergent challenges on
    // different clients).
    for chunk in public_inputs_bytes.chunks_exact(32) {
        let _ = fr_from_canonical_bytes(chunk)?;
    }

    let mut transcript = Transcript::new(Kind::Keccak256, backend);

    // ---- Round 1: β ----
    transcript.absorb(&vk.x2_g2);
    transcript.absorb(&vk.n_public.to_le_bytes());
    transcript.absorb(&vk.num_variables.to_le_bytes());
    for commit in vk.commits_iter() {
        transcript.absorb(commit);
    }
    transcript.absorb(public_inputs_bytes);
    transcript.absorb(proof.a);
    transcript.absorb(proof.b);
    transcript.absorb(proof.c);
    let beta_bytes = transcript.get_challenge()?;
    let beta = fr_from_canonical_bytes(&beta_bytes)?;

    // ---- Round 2: γ ----
    transcript.reset();
    transcript.absorb(&beta_bytes);
    let gamma_bytes = transcript.get_challenge()?;
    let gamma = fr_from_canonical_bytes(&gamma_bytes)?;

    // ---- Round 3: α ----
    transcript.reset();
    transcript.absorb(&beta_bytes);
    transcript.absorb(&gamma_bytes);
    transcript.absorb(proof.z);
    let alpha_bytes = transcript.get_challenge()?;
    let alpha = fr_from_canonical_bytes(&alpha_bytes)?;

    // Leave the transcript seeded for sumcheck: reset + absorb α.
    transcript.reset();
    transcript.absorb(&alpha_bytes);

    Ok((PreSumcheckChallenges { beta, gamma, alpha }, transcript))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN, SUMCHECK_POLY_LEN};
    use crate::canonical::HyperPlonkVerifyingKey;
    use alloc::vec;
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_zk_primitives::field::fr_to_canonical_bytes;

    fn sample_vk() -> HyperPlonkVerifyingKey {
        HyperPlonkVerifyingKey {
            n_public: 1,
            num_variables: 4,
            x2_g2: [0x11; 128],
            q_m_g1: [0x21; G1_LEN],
            q_l_g1: [0x22; G1_LEN],
            q_r_g1: [0x23; G1_LEN],
            q_o_g1: [0x24; G1_LEN],
            q_c_g1: [0x25; G1_LEN],
            sigma_1_g1: [0x31; G1_LEN],
            sigma_2_g1: [0x32; G1_LEN],
            sigma_3_g1: [0x33; G1_LEN],
        }
    }

    fn sample_proof_buf(rounds: u32) -> alloc::vec::Vec<u8> {
        let polys_len = (rounds as usize) * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + 12 * FR_LEN + G1_LEN;
        let mut buf = vec![0u8; total];
        // Set A/B/C/Z commits to recognizable patterns.
        for (i, byte) in buf[0..G1_LEN].iter_mut().enumerate() {
            *byte = 0x41 + (i % 16) as u8; // A commit
        }
        buf[G1_LEN..2 * G1_LEN].copy_from_slice(&[0x42; G1_LEN]);
        buf[2 * G1_LEN..3 * G1_LEN].copy_from_slice(&[0x43; G1_LEN]);
        buf[3 * G1_LEN..4 * G1_LEN].copy_from_slice(&[0x5A; G1_LEN]);
        buf[256..260].copy_from_slice(&rounds.to_le_bytes());
        buf
    }

    #[test]
    fn derive_challenges_happy_path() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf(4);
        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        let pi_bytes = fr_to_canonical_bytes(&Fr::from(7u64));

        let (chals, _t) = derive_challenges(&backend, &vk, &pi_bytes, &proof).unwrap();
        // Challenges are non-trivial (mod-r reduction keeps them non-zero
        // almost always for random inputs).
        assert_ne!(chals.beta, Fr::from(0u64));
        assert_ne!(chals.gamma, Fr::from(0u64));
        assert_ne!(chals.alpha, Fr::from(0u64));
        // β ≠ γ and γ ≠ α with overwhelming probability.
        assert_ne!(chals.beta, chals.gamma);
        assert_ne!(chals.gamma, chals.alpha);
    }

    #[test]
    fn derive_challenges_deterministic() {
        // Same inputs → same challenges (soundness-critical determinism).
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf(4);
        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        let pi_bytes = fr_to_canonical_bytes(&Fr::from(7u64));

        let (chals_a, _) = derive_challenges(&backend, &vk, &pi_bytes, &proof).unwrap();
        let (chals_b, _) = derive_challenges(&backend, &vk, &pi_bytes, &proof).unwrap();
        assert_eq!(chals_a, chals_b);
    }

    #[test]
    fn derive_challenges_differ_on_vk_change() {
        let backend = HostBackend::new();
        let mut vk_a = sample_vk();
        let mut vk_b = sample_vk();
        vk_b.q_m_g1[0] ^= 0x01; // flip one byte of Q_M commitment.

        let proof_buf = sample_proof_buf(4);
        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        let pi_bytes = fr_to_canonical_bytes(&Fr::from(7u64));

        let (chals_a, _) = derive_challenges(&backend, &vk_a, &pi_bytes, &proof).unwrap();
        let (chals_b, _) = derive_challenges(&backend, &vk_b, &pi_bytes, &proof).unwrap();
        assert_ne!(chals_a.alpha, chals_b.alpha);

        // Sanity: they also differ even for just the first squeeze (β).
        vk_a.x2_g2[0] ^= 0x02;
        let (chals_c, _) = derive_challenges(&backend, &vk_a, &pi_bytes, &proof).unwrap();
        assert_ne!(chals_a.beta, chals_c.beta);
    }

    #[test]
    fn derive_challenges_differ_on_public_input_change() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf(4);
        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();

        let pi_a = fr_to_canonical_bytes(&Fr::from(7u64));
        let pi_b = fr_to_canonical_bytes(&Fr::from(8u64));

        let (chals_a, _) = derive_challenges(&backend, &vk, &pi_a, &proof).unwrap();
        let (chals_b, _) = derive_challenges(&backend, &vk, &pi_b, &proof).unwrap();
        assert_ne!(chals_a.beta, chals_b.beta);
    }

    #[test]
    fn derive_challenges_rejects_wrong_pi_count() {
        let backend = HostBackend::new();
        let vk = sample_vk(); // declares n_public = 1
        let proof_buf = sample_proof_buf(4);
        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();

        // Two Fr elements when only one is declared.
        let pi_a = fr_to_canonical_bytes(&Fr::from(1u64));
        let pi_b = fr_to_canonical_bytes(&Fr::from(2u64));
        let mut pi_both = alloc::vec::Vec::new();
        pi_both.extend_from_slice(&pi_a);
        pi_both.extend_from_slice(&pi_b);

        let r = derive_challenges(&backend, &vk, &pi_both, &proof);
        assert!(matches!(r, Err(OnChainError::PublicInputCountMismatch)));
    }

    #[test]
    fn derive_challenges_rejects_pi_not_multiple_of_32() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf(4);
        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        // 31 bytes — not a whole Fr.
        let bad_pi = [0u8; 31];
        let r = derive_challenges(&backend, &vk, &bad_pi, &proof);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn derive_challenges_rejects_pi_out_of_range() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_buf(4);
        let proof = HyperPlonkProof::from_bytes(&proof_buf).unwrap();
        // All 0xFF is > r → must reject.
        let bad_pi = [0xFFu8; 32];
        let r = derive_challenges(&backend, &vk, &bad_pi, &proof);
        assert!(matches!(r, Err(OnChainError::PublicInputOutOfRange)));
    }
}
