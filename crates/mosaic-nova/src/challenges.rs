//! Fiat-Shamir challenge derivation for Nova / `HyperNova` / `ProtoStar`.
//!
//! Folding verification at the final accumulator uses a small transcript:
//!
//! - `r` — folding challenge (used during accumulation; re-derived here
//!   to cross-check the folded commitment aggregation).
//! - `ξ` — evaluation point for the Spartan-wrapped Hadamard check.
//! - `ν` — batch KZG opening challenge.
//!
//! ## Absorb order
//!
//! ```text
//! // ---- Round 1: r (folding challenge) ----
//! transcript.reset()
//! transcript.absorb(vk.cs_digest)                // 32 B
//! transcript.absorb(vk.variant_byte + flags)     // ~8 B
//! transcript.absorb(vk.a_comm ‖ b_comm ‖ c_comm) // 3 × 64 B
//! transcript.absorb(public_inputs)               // n × 32 B
//! transcript.absorb(proof.e_comm)                // 64 B
//! transcript.absorb(proof.w_comm)                // 64 B
//! transcript.absorb(proof.t_comm)                // 64 B
//! r = transcript.squeeze()
//!
//! // ---- Round 2: ξ (evaluation point) ----
//! transcript.reset()
//! transcript.absorb(r)
//! transcript.absorb(proof.u)                     // folding scalar Fr
//! for aux in proof.aux_iter():                   // HyperNova extras
//!     transcript.absorb(aux)
//! xi = transcript.squeeze()
//!
//! // ---- Round 3: ν (batch opening) ----
//! transcript.reset()
//! transcript.absorb(xi)
//! transcript.absorb(proof.w_xi)
//! transcript.absorb(proof.w_xiw)
//! nu = transcript.squeeze()
//! ```
//!
//! ## Rationale
//!
//! - **r first**: the accumulator commitments `E, W, T` are the
//!   inputs the folding challenge reduces — absorb-then-squeeze.
//! - **ξ after r + u + aux**: evaluation point depends on the fold
//!   scalar `u` and any `HyperNova` higher-degree aux commits.
//! - **ν last**: opening batch is the final challenge before the
//!   pairing check.

use crate::canonical::{NovaFoldingProof, NovaFoldingVerifyingKey};
use ark_bn254::Fr;
use mosaic_core::{syscall::SyscallBackend, OnChainError};
use mosaic_zk_primitives::{
    field::fr_from_canonical_bytes,
    transcript::{Kind, Transcript},
};

/// Three-challenge bundle emitted by [`derive_challenges`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NovaChallenges {
    /// Folding challenge — weighs the cross-term when reconstructing
    /// the folded commitment from `U_1 + r·U_2 + r²·T`.
    pub r: Fr,
    /// Evaluation point for the Spartan-wrapped Hadamard check.
    pub xi: Fr,
    /// Batch KZG opening challenge.
    pub nu: Fr,
}

/// Derive the three challenges `(r, ξ, ν)` from VK + proof + public
/// inputs using the snarkjs-style "fresh transcript per round" pattern.
///
/// ## Errors
///
/// - [`OnChainError::PublicInputOutOfRange`] if a public-input Fr is
///   not reduced mod `r`.
/// - [`OnChainError::PublicInputCountMismatch`] if the public-input
///   buffer length disagrees with `vk.n_public`.
/// - [`OnChainError::ProofLengthMismatch`] if the public-input buffer
///   length is not a multiple of 32 bytes.
/// - Transcript backend errors.
pub fn derive_challenges<'b, B: SyscallBackend + ?Sized>(
    backend: &'b B,
    vk: &NovaFoldingVerifyingKey,
    public_inputs_bytes: &[u8],
    proof: &NovaFoldingProof<'_>,
) -> Result<(NovaChallenges, Transcript<'b, B>), OnChainError> {
    if !public_inputs_bytes.len().is_multiple_of(32) {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let declared_pi = public_inputs_bytes.len() / 32;
    if declared_pi != vk.n_public as usize {
        return Err(OnChainError::PublicInputCountMismatch);
    }
    for chunk in public_inputs_bytes.chunks_exact(32) {
        let _ = fr_from_canonical_bytes(chunk)?;
    }

    let mut transcript = Transcript::new(Kind::Keccak256, backend);

    // ---- Round 1: r (folding challenge) ----
    transcript.absorb(&vk.cs_digest);
    transcript.absorb(&[vk.variant as u8]);
    transcript.absorb(&vk.n_public.to_le_bytes());
    transcript.absorb(&vk.n_constraints.to_le_bytes());
    transcript.absorb(&vk.x2_g2);
    transcript.absorb(&vk.a_comm);
    transcript.absorb(&vk.b_comm);
    transcript.absorb(&vk.c_comm);
    transcript.absorb(public_inputs_bytes);
    transcript.absorb(proof.e_comm);
    transcript.absorb(proof.w_comm);
    transcript.absorb(proof.t_comm);
    let r_bytes = transcript.get_challenge()?;
    let r = fr_from_canonical_bytes(&r_bytes)?;

    // ---- Round 2: ξ ----
    transcript.reset();
    transcript.absorb(&r_bytes);
    transcript.absorb(proof.u);
    for aux in proof.aux_iter() {
        transcript.absorb(aux);
    }
    let xi_bytes = transcript.get_challenge()?;
    let xi = fr_from_canonical_bytes(&xi_bytes)?;

    // ---- Round 3: ν ----
    transcript.reset();
    transcript.absorb(&xi_bytes);
    transcript.absorb(proof.w_xi);
    transcript.absorb(proof.w_xiw);
    let nu_bytes = transcript.get_challenge()?;
    let nu = fr_from_canonical_bytes(&nu_bytes)?;

    // Leave transcript seeded with ν for downstream KZG steps.
    transcript.reset();
    transcript.absorb(&nu_bytes);

    Ok((NovaChallenges { r, xi, nu }, transcript))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{sizes, FoldingVariant};
    use alloc::vec;
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_zk_primitives::field::fr_to_canonical_bytes;

    fn sample_vk() -> NovaFoldingVerifyingKey {
        NovaFoldingVerifyingKey {
            variant: FoldingVariant::Nova,
            n_public: 2,
            n_constraints: 1024,
            x2_g2: [0xCC; sizes::G2_LEN],
            a_comm: [0x11; sizes::G1_LEN],
            b_comm: [0x22; sizes::G1_LEN],
            c_comm: [0x33; sizes::G1_LEN],
            cs_digest: [0xAA; 32],
        }
    }

    fn sample_proof_bytes(num_aux: u8, n_public: u16) -> alloc::vec::Vec<u8> {
        let aux_len = (num_aux as usize) * sizes::G1_LEN;
        let pi_len = (n_public as usize) * sizes::FR_LEN;
        let total = sizes::FIXED_HEADER_LEN
            + sizes::FIXED_COMMITS_LEN
            + sizes::SCALAR_LEN
            + 4 * sizes::G1_LEN // session-15-nova base commits
            + sizes::HADAMARD_EVALS_LEN
            + sizes::W_EVAL_LEN
            + aux_len
            + pi_len
            + sizes::OPENING_LEN;
        let mut buf = vec![0u8; total];
        buf[0] = FoldingVariant::Nova as u8;
        buf[1] = num_aux;
        buf[2..4].copy_from_slice(&n_public.to_le_bytes());
        buf
    }

    #[test]
    fn derive_challenges_happy_path() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_bytes(0, 2);
        let proof = NovaFoldingProof::from_bytes(&proof_buf).unwrap();
        let mut pi = alloc::vec::Vec::new();
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(1u64)));
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(2u64)));

        let (c, _) = derive_challenges(&backend, &vk, &pi, &proof).unwrap();

        assert_ne!(c.r, Fr::from(0u64));
        assert_ne!(c.xi, Fr::from(0u64));
        assert_ne!(c.nu, Fr::from(0u64));
        assert_ne!(c.r, c.xi);
        assert_ne!(c.xi, c.nu);
    }

    #[test]
    fn derive_challenges_deterministic() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_bytes(0, 2);
        let proof = NovaFoldingProof::from_bytes(&proof_buf).unwrap();
        let mut pi = alloc::vec::Vec::new();
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(1u64)));
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(2u64)));

        let (a, _) = derive_challenges(&backend, &vk, &pi, &proof).unwrap();
        let (b, _) = derive_challenges(&backend, &vk, &pi, &proof).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_challenges_differ_on_variant_change() {
        let backend = HostBackend::new();
        let mut vk_a = sample_vk();
        let mut vk_b = sample_vk();
        vk_b.variant = FoldingVariant::HyperNova;

        let proof_buf = sample_proof_bytes(0, 2);
        let proof = NovaFoldingProof::from_bytes(&proof_buf).unwrap();
        let mut pi = alloc::vec::Vec::new();
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(1u64)));
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(2u64)));

        let (ca, _) = derive_challenges(&backend, &vk_a, &pi, &proof).unwrap();
        let (cb, _) = derive_challenges(&backend, &vk_b, &pi, &proof).unwrap();
        // Variant byte goes into round-1 absorb → r differs.
        assert_ne!(ca.r, cb.r);

        vk_a.cs_digest[0] ^= 0xAA;
        let (cc, _) = derive_challenges(&backend, &vk_a, &pi, &proof).unwrap();
        assert_ne!(ca.r, cc.r);
    }

    #[test]
    fn derive_challenges_differ_on_aux_commits() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let mut proof_a = sample_proof_bytes(2, 2);
        let mut proof_b = sample_proof_bytes(2, 2);
        // Tamper with aux commit bytes (after E/W/T/u + 4·G1 base
        // commits + hadamard_evals + w_eval).
        let aux_off = sizes::FIXED_HEADER_LEN
            + sizes::FIXED_COMMITS_LEN
            + sizes::SCALAR_LEN
            + 4 * sizes::G1_LEN
            + sizes::HADAMARD_EVALS_LEN
            + sizes::W_EVAL_LEN;
        proof_a[aux_off] = 0xAA;
        proof_b[aux_off] = 0xBB;
        let parsed_a = NovaFoldingProof::from_bytes(&proof_a).unwrap();
        let parsed_b = NovaFoldingProof::from_bytes(&proof_b).unwrap();
        let mut pi = alloc::vec::Vec::new();
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(1u64)));
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(2u64)));

        let (ca, _) = derive_challenges(&backend, &vk, &pi, &parsed_a).unwrap();
        let (cb, _) = derive_challenges(&backend, &vk, &pi, &parsed_b).unwrap();
        // r absorbs E/W/T but NOT aux (aux comes after in round 2 for ξ),
        // so r should be equal; ξ, ν differ.
        assert_eq!(ca.r, cb.r);
        assert_ne!(ca.xi, cb.xi);
        assert_ne!(ca.nu, cb.nu);
    }

    #[test]
    fn derive_challenges_rejects_wrong_pi_count() {
        let backend = HostBackend::new();
        let vk = sample_vk(); // n_public = 2
        let proof_buf = sample_proof_bytes(0, 2);
        let proof = NovaFoldingProof::from_bytes(&proof_buf).unwrap();
        // Only 1 PI element.
        let pi = fr_to_canonical_bytes(&Fr::from(1u64));
        let r = derive_challenges(&backend, &vk, &pi, &proof);
        assert!(matches!(r, Err(OnChainError::PublicInputCountMismatch)));
    }

    #[test]
    fn derive_challenges_rejects_pi_out_of_range() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_bytes(0, 2);
        let proof = NovaFoldingProof::from_bytes(&proof_buf).unwrap();
        let mut pi = alloc::vec::Vec::new();
        pi.extend_from_slice(&[0xFFu8; 32]); // > r
        pi.extend_from_slice(&fr_to_canonical_bytes(&Fr::from(1u64)));
        let r = derive_challenges(&backend, &vk, &pi, &proof);
        assert!(matches!(r, Err(OnChainError::PublicInputOutOfRange)));
    }
}
