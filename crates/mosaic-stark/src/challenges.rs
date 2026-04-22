//! Fiat-Shamir challenge derivation for FRI-STARK.
//!
//! Unlike the BN254 verifiers, FRI-STARK transcripts are hash-based —
//! traditionally SHA-256 (Winterfell) or BLAKE3 (Plonky3). This
//! module uses SHA-256 via the Solana syscall so the same absorb
//! order + reduction produces identical challenges on-chain and in
//! host-side differential tests.
//!
//! ## Challenge sequence (simplified scaffold)
//!
//! Real FRI verifiers emit a long chain of challenges — per-layer
//! fold randomness, constraint combining, PoW nonce seed, per-query
//! indices. This scaffold emits the three "summary" challenges
//! needed for structural checks:
//!
//! ```text
//! alpha       — constraint combining (gate + boundary linear combo)
//! z           — out-of-domain evaluation point
//! query_seed  — seed for deriving N query indices
//! ```
//!
//! Full per-layer fold challenges + per-query indices are derived
//! on-demand in session 6c where the FRI-layer check loop lives.
//!
//! ## Absorb order
//!
//! ```text
//! // ---- Round 1: alpha ----
//! transcript.absorb(vk.air_hash)
//! transcript.absorb(vk.field_id + trace_shape)
//! transcript.absorb(public_inputs)
//! transcript.absorb(proof.trace_commitment)     // 32 B
//! alpha = transcript.squeeze()
//!
//! // ---- Round 2: z ----
//! transcript.absorb(alpha)
//! transcript.absorb(proof.constraint_commitment) // 32 B
//! z = transcript.squeeze()
//!
//! // ---- Round 3: query_seed ----
//! transcript.absorb(z)
//! for layer_root in proof.fri_layer_iter():     // num_fri_layers × 32 B
//!     transcript.absorb(layer_root)
//! transcript.absorb(proof.ood_evals)
//! transcript.absorb(proof.fri_final_poly)
//! query_seed = transcript.squeeze()
//! ```
//!
//! Challenges squeeze as 32-byte hashes — we reduce them to Fr-range
//! in the BN254 sense (mod `r`). For real Goldilocks/BabyBear FRI the
//! reduction would be mod those primes; session 6b addresses that.

use crate::canonical::{sizes::DIGEST_LEN, FriStarkProof, FriStarkVerifyingKey};
use alloc::vec::Vec;
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// Three-challenge scaffold bundle — the minimal set needed to route
/// through the verifier structure. Full FRI-STARK challenge chain
/// lands in session 6c.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StarkChallenges {
    /// Constraint-combining challenge.
    pub alpha: [u8; DIGEST_LEN],
    /// Out-of-domain evaluation point.
    pub z: [u8; DIGEST_LEN],
    /// Seed for deriving `num_queries` indices via sequential hashing.
    pub query_seed: [u8; DIGEST_LEN],
}

/// Derive the three scaffold challenges via SHA-256 transcript.
///
/// Uses an accumulator-then-hash pattern matching Winterfell's
/// transcript: each round's absorbs feed into one sha256 call that
/// produces the challenge.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if proof is malformed.
/// - [`OnChainError::Sha256SyscallFailed`] on hash failure.
pub fn derive_challenges<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &FriStarkVerifyingKey,
    public_inputs_bytes: &[u8],
    proof: &FriStarkProof<'_>,
) -> Result<StarkChallenges, OnChainError> {
    // ---- Round 1: alpha ----
    let mut r1_acc: Vec<u8> = Vec::with_capacity(
        32 + 16 + public_inputs_bytes.len() + DIGEST_LEN,
    );
    r1_acc.extend_from_slice(&vk.air_hash);
    r1_acc.push(vk.field_id as u8);
    r1_acc.push(vk.log_blowup);
    r1_acc.extend_from_slice(&vk.trace_log_height.to_le_bytes());
    r1_acc.extend_from_slice(&vk.trace_width.to_le_bytes());
    r1_acc.extend_from_slice(public_inputs_bytes);
    r1_acc.extend_from_slice(proof.trace_commitment);
    let alpha = backend.sha256(&[&r1_acc])?;

    // ---- Round 2: z ----
    let r2_acc = [&alpha[..], proof.constraint_commitment].concat();
    let z = backend.sha256(&[&r2_acc])?;

    // ---- Round 3: query_seed ----
    let mut r3_acc: Vec<u8> = Vec::with_capacity(
        DIGEST_LEN
            + proof.fri_layer_commits.len()
            + proof.ood_evals.len()
            + proof.fri_final_poly.len(),
    );
    r3_acc.extend_from_slice(&z);
    r3_acc.extend_from_slice(proof.fri_layer_commits);
    r3_acc.extend_from_slice(proof.ood_evals);
    r3_acc.extend_from_slice(proof.fri_final_poly);
    let query_seed = backend.sha256(&[&r3_acc])?;

    Ok(StarkChallenges {
        alpha,
        z,
        query_seed,
    })
}

/// Verify a proof-of-work grinding: `sha256(query_seed ‖ pow_nonce)`
/// must have at least `pow_bits` leading zero bits.
///
/// PoW grinding raises the bar for a malicious prover to brute-force
/// a favorable `query_seed` — instead of searching over transcripts
/// until the query indices happen to line up with a lucky tampered
/// bundle, they also have to find a nonce whose hash clears the
/// grinding target. Each extra bit doubles the expected work.
///
/// ## Errors
///
/// - [`OnChainError::Sha256SyscallFailed`] on hash failure.
/// - [`OnChainError::VerificationFailed`] if the hash doesn't clear
///   `pow_bits` leading zeros.
pub fn verify_pow<B: SyscallBackend + ?Sized>(
    backend: &B,
    query_seed: &[u8; DIGEST_LEN],
    pow_nonce: u64,
    pow_bits: u8,
) -> Result<(), OnChainError> {
    // Hash the seed+nonce. `sha256(query_seed ‖ nonce_le)`.
    let nonce_bytes = pow_nonce.to_le_bytes();
    let hash = backend.sha256(&[query_seed, &nonce_bytes])?;
    if !has_leading_zero_bits(&hash, pow_bits) {
        return Err(OnChainError::VerificationFailed);
    }
    Ok(())
}

/// Test whether `digest` has at least `n_bits` leading zero bits
/// (MSB-first).
///
/// Kept public for tests; the on-chain verifier calls it via
/// `verify_pow`.
#[must_use]
pub fn has_leading_zero_bits(digest: &[u8; DIGEST_LEN], n_bits: u8) -> bool {
    let full_bytes = (n_bits / 8) as usize;
    let rem_bits = n_bits % 8;
    if digest.len() < full_bytes {
        return false;
    }
    for b in &digest[..full_bytes] {
        if *b != 0 {
            return false;
        }
    }
    if rem_bits == 0 {
        return true;
    }
    // Top `rem_bits` of the next byte must be zero.
    let next = digest[full_bytes];
    let mask: u8 = 0xFFu8 << (8 - rem_bits);
    (next & mask) == 0
}

/// Derive `n_queries` pseudo-random indices in `[0, domain_size)` by
/// hashing `(seed ‖ counter)` and reducing mod `domain_size`.
///
/// `domain_size` must be a power of two (standard for STARK
/// evaluation domains); this lets us use bitmask reduction instead
/// of modular reduction, which is simpler on-chain.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if `domain_size` is zero
///   or not a power of two.
/// - [`OnChainError::Sha256SyscallFailed`] on hash failure.
pub fn derive_query_indices<B: SyscallBackend + ?Sized>(
    backend: &B,
    seed: &[u8; DIGEST_LEN],
    n_queries: u16,
    domain_size: u64,
) -> Result<Vec<u64>, OnChainError> {
    if domain_size == 0 || !domain_size.is_power_of_two() {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let mask = domain_size - 1;
    let mut out = Vec::with_capacity(n_queries as usize);
    for i in 0..n_queries {
        let counter = i.to_le_bytes();
        let hash = backend.sha256(&[seed, &counter])?;
        // Take the first 8 bytes of the hash as a u64, then mask.
        let raw = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]);
        out.push(raw & mask);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{sizes, StarkFieldId};
    use alloc::vec;
    use mosaic_core::syscall::host::HostBackend;

    fn sample_vk() -> FriStarkVerifyingKey {
        FriStarkVerifyingKey {
            field_id: StarkFieldId::Goldilocks,
            trace_width: 32,
            trace_log_height: 16,
            log_blowup: 1,
            air_hash: [0xAA; 32],
        }
    }

    fn sample_proof_bytes(num_fri: u8, num_q: u16) -> alloc::vec::Vec<u8> {
        let ood_bytes = 10 * sizes::DIGEST_LEN; // dummy content length
        let final_bytes = 4 * sizes::DIGEST_LEN;
        let query_bytes = (num_q as usize) * 64;
        let total = sizes::FIXED_HEADER_LEN
            + 2 * sizes::DIGEST_LEN
            + (num_fri as usize) * sizes::DIGEST_LEN
            + 4 + ood_bytes
            + 4 + final_bytes
            + 4 + query_bytes
            + sizes::POW_NONCE_LEN;
        let mut buf = vec![0u8; total];
        buf[0] = StarkFieldId::Goldilocks as u8;
        buf[1] = 1;
        buf[2] = num_fri;
        buf[4..6].copy_from_slice(&num_q.to_le_bytes());
        buf[6..8].copy_from_slice(&16u16.to_le_bytes());
        buf[8..12].copy_from_slice(&32u32.to_le_bytes());
        let mut off = sizes::FIXED_HEADER_LEN + 2 * sizes::DIGEST_LEN
            + (num_fri as usize) * sizes::DIGEST_LEN;
        buf[off..off + 4].copy_from_slice(&(ood_bytes as u32).to_le_bytes());
        off += 4 + ood_bytes;
        buf[off..off + 4].copy_from_slice(&(final_bytes as u32).to_le_bytes());
        off += 4 + final_bytes;
        buf[off..off + 4].copy_from_slice(&(query_bytes as u32).to_le_bytes());
        buf
    }

    #[test]
    fn derive_challenges_happy_path() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_bytes(16, 80);
        let proof = FriStarkProof::from_bytes(&proof_buf).unwrap();
        let pi = [0u8; 32];

        let c = derive_challenges(&backend, &vk, &pi, &proof).unwrap();
        // All three challenges are 32-byte hashes; pairwise distinct
        // with overwhelming probability.
        assert_ne!(c.alpha, c.z);
        assert_ne!(c.z, c.query_seed);
        assert_ne!(c.alpha, c.query_seed);
    }

    #[test]
    fn derive_challenges_deterministic() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let proof_buf = sample_proof_bytes(8, 40);
        let proof = FriStarkProof::from_bytes(&proof_buf).unwrap();
        let pi = [0u8; 32];
        let a = derive_challenges(&backend, &vk, &pi, &proof).unwrap();
        let b = derive_challenges(&backend, &vk, &pi, &proof).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_challenges_differ_on_air_hash_change() {
        let backend = HostBackend::new();
        let mut vk_a = sample_vk();
        let mut vk_b = sample_vk();
        vk_b.air_hash[0] ^= 0xFF;
        let proof_buf = sample_proof_bytes(4, 10);
        let proof = FriStarkProof::from_bytes(&proof_buf).unwrap();
        let pi = [0u8; 32];
        let ca = derive_challenges(&backend, &vk_a, &pi, &proof).unwrap();
        let cb = derive_challenges(&backend, &vk_b, &pi, &proof).unwrap();
        // air_hash goes into round 1 → alpha differs → z, query_seed
        // also differ (domino effect).
        assert_ne!(ca.alpha, cb.alpha);
        assert_ne!(ca.z, cb.z);
        assert_ne!(ca.query_seed, cb.query_seed);

        vk_a.trace_width = 64;
        let cc = derive_challenges(&backend, &vk_a, &pi, &proof).unwrap();
        assert_ne!(ca.alpha, cc.alpha);
    }

    #[test]
    fn derive_challenges_differ_on_fri_layer_change() {
        let backend = HostBackend::new();
        let vk = sample_vk();
        let mut buf_a = sample_proof_bytes(4, 10);
        let mut buf_b = sample_proof_bytes(4, 10);
        // Tamper with a FRI layer commit byte.
        let layer_off = sizes::FIXED_HEADER_LEN + 2 * sizes::DIGEST_LEN;
        buf_a[layer_off] = 0xAA;
        buf_b[layer_off] = 0xBB;
        let pa = FriStarkProof::from_bytes(&buf_a).unwrap();
        let pb = FriStarkProof::from_bytes(&buf_b).unwrap();
        let pi = [0u8; 32];
        let ca = derive_challenges(&backend, &vk, &pi, &pa).unwrap();
        let cb = derive_challenges(&backend, &vk, &pi, &pb).unwrap();
        // FRI layer roots are absorbed in round 3 → alpha, z equal;
        // query_seed differs.
        assert_eq!(ca.alpha, cb.alpha);
        assert_eq!(ca.z, cb.z);
        assert_ne!(ca.query_seed, cb.query_seed);
    }

    // ---- derive_query_indices ----

    #[test]
    fn query_indices_within_domain() {
        let backend = HostBackend::new();
        let seed = [0x42u8; DIGEST_LEN];
        let indices = derive_query_indices(&backend, &seed, 100, 1 << 16).unwrap();
        assert_eq!(indices.len(), 100);
        for i in indices {
            assert!(i < (1 << 16), "index {i} out of domain");
        }
    }

    #[test]
    fn query_indices_deterministic() {
        let backend = HostBackend::new();
        let seed = [0x42u8; DIGEST_LEN];
        let a = derive_query_indices(&backend, &seed, 20, 1024).unwrap();
        let b = derive_query_indices(&backend, &seed, 20, 1024).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn query_indices_differ_on_seed_change() {
        let backend = HostBackend::new();
        let seed_a = [0x42u8; DIGEST_LEN];
        let seed_b = [0x43u8; DIGEST_LEN];
        let a = derive_query_indices(&backend, &seed_a, 10, 1024).unwrap();
        let b = derive_query_indices(&backend, &seed_b, 10, 1024).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn query_indices_rejects_non_power_of_two() {
        let backend = HostBackend::new();
        let seed = [0u8; DIGEST_LEN];
        let r = derive_query_indices(&backend, &seed, 10, 1000); // not a power of 2
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn query_indices_rejects_zero_domain() {
        let backend = HostBackend::new();
        let seed = [0u8; DIGEST_LEN];
        let r = derive_query_indices(&backend, &seed, 10, 0);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    // ---- verify_pow ----

    #[test]
    fn pow_zero_bits_accepts_any_nonce() {
        // pow_bits = 0 means no grinding required; trivially accepts.
        let backend = HostBackend::new();
        let seed = [0x42u8; DIGEST_LEN];
        assert!(verify_pow(&backend, &seed, 0, 0).is_ok());
        assert!(verify_pow(&backend, &seed, 12345, 0).is_ok());
    }

    #[test]
    fn pow_rejects_random_nonce_at_nonzero_bits() {
        // Random seed + nonce 0; expected hash is uniformly random, so
        // with overwhelming probability it has fewer than 8 leading
        // zero bits.
        let backend = HostBackend::new();
        let seed = [0x42u8; DIGEST_LEN];
        let r = verify_pow(&backend, &seed, 0, 8);
        assert!(
            matches!(r, Err(OnChainError::VerificationFailed)),
            "random hash should rarely have 8 leading zero bits, got {r:?}",
        );
    }

    #[test]
    fn pow_accepts_after_search() {
        // Brute-force a nonce whose hash has ≥4 leading zeros (1/16
        // probability → expect a hit in ~16 attempts).
        let backend = HostBackend::new();
        let seed = [0x42u8; DIGEST_LEN];
        let mut found = None;
        for nonce in 0..10_000u64 {
            if verify_pow(&backend, &seed, nonce, 4).is_ok() {
                found = Some(nonce);
                break;
            }
        }
        assert!(found.is_some(), "brute-forcing 4 leading zero bits should succeed within 10k nonces");
    }

    // ---- has_leading_zero_bits unit tests ----

    #[test]
    fn leading_zero_bits_all_zero_bytes() {
        let zeros = [0u8; DIGEST_LEN];
        for n in 0..=255u8 {
            let expected = (n as usize) <= DIGEST_LEN * 8;
            assert_eq!(has_leading_zero_bits(&zeros, n), expected, "n={n}");
        }
    }

    #[test]
    fn leading_zero_bits_partial_byte() {
        // 0b0001_0000 → top 3 bits are zero.
        let mut digest = [0u8; DIGEST_LEN];
        digest[0] = 0b0001_0000;
        assert!(has_leading_zero_bits(&digest, 3));
        assert!(!has_leading_zero_bits(&digest, 4));
    }

    #[test]
    fn leading_zero_bits_one_full_zero_byte() {
        // First byte zero, second byte 0xFF → exactly 8 leading zeros.
        let mut digest = [0xFFu8; DIGEST_LEN];
        digest[0] = 0;
        assert!(has_leading_zero_bits(&digest, 8));
        assert!(!has_leading_zero_bits(&digest, 9));
    }
}
