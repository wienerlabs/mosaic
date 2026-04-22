//! FRI-STARK verifier scaffold.
//!
//! Phase-2 freeze ships wire-format validation + a `ProofSystem` impl
//! returning `UnimplementedProofSystem`. Phase 3 lands the hash-based
//! verification body: trace/constraint Merkle checks, FRI low-degree
//! test across layers, out-of-domain quotient consistency, and the PoW
//! grinding check.
//!
//! ## Phase-3 round plan (for the implementer)
//!
//! ```text
//! verify(vk_bytes, proof_bytes, public_inputs_bytes):
//!     vk    = FriStarkVerifyingKey::from_bytes(vk_bytes)?;    // done
//!     proof = FriStarkProof::from_bytes(proof_bytes)?;        // done
//!     assert_eq!(vk.field_id, proof.field_id);
//!     assert_eq!(vk.trace_width, proof.trace_width);
//!
//!     // ---- Phase 3 work starts here ----
//!
//!     // Seed transcript from VK + public inputs + trace commitment.
//!     let mut t = ShaTranscript::new(vk.air_hash);
//!     t.absorb(public_inputs_bytes);
//!     t.absorb(proof.trace_commitment);
//!
//!     // Constraint composition challenges.
//!     let alpha = t.squeeze();                        // linear combiner
//!     t.absorb(proof.constraint_commitment);
//!
//!     // FRI commit phase — absorb each layer root, squeeze beta.
//!     let betas: Vec<Fr> = proof.fri_layer_iter()
//!         .map(|root| { t.absorb(root); t.squeeze() })
//!         .collect();
//!
//!     // Out-of-domain evaluations consistency check:
//!     //   constraint(z) ?= sum_i alpha^i · quotient_i(z)
//!     // where z is squeezed out-of-domain after FRI commits.
//!     let z = t.squeeze();
//!     for eval in proof.ood_evals_iter() { t.absorb(eval); }
//!     verify_ood_quotient_consistency(&vk, &proof, alpha, z)?;
//!
//!     // Query phase — expand PoW nonce, then N_queries random indices.
//!     verify_pow(&t, proof.pow_bits, proof.pow_nonce)?;
//!     for _ in 0..proof.num_queries {
//!         let idx = t.squeeze_query_index(proof.trace_log_height + proof.log_blowup);
//!         verify_fri_query_path(&vk, &proof, idx, &betas)?;
//!         verify_trace_auth_path(&vk, &proof, idx)?;
//!         verify_constraint_auth_path(&vk, &proof, idx)?;
//!     }
//!
//!     // Final FRI layer — constant polynomial check.
//!     verify_fri_final_poly(&proof, &betas)?;
//!
//!     Ok(())
//! ```
//!
//! ## SBF-specific implementation notes
//!
//! - `#[inline(never)]` every FRI layer helper. The inner loops touch
//!   dozens of 32-byte digests; without outlining, stack frames easily
//!   exceed the 4 KB cap.
//! - Prefer `solana_keccak::hashv` (multi-input) over per-absorb hashes
//!   — one syscall dispatch amortizes across the whole absorb payload.
//! - Goldilocks Fr arithmetic can be implemented in pure Rust (no
//!   arkworks dependency) — single 64-bit modulus, no Montgomery form.
//! - Merkle auth path decoding should walk a packed byte buffer rather
//!   than `Vec<Vec<u8>>` to avoid per-node heap churn.
//!
//! ## Proof delivery
//!
//! Real proofs (30 KB+) exceed the 1232 B per-tx Solana limit. The
//! `mosaic-chunked` protocol is the expected delivery path:
//!
//! 1. Client `InitializeSession` with expected total size + proof hash.
//! 2. Multiple `AppendChunk` writes accumulate bytes + rolling SHA-256.
//! 3. `CommitAndVerify` reassembles the buffer and invokes
//!    `mosaic-program::dispatch_verify` with `ProofSystemId::FriStark`.

use crate::{
    canonical::{FriStarkProof, FriStarkVerifyingKey},
    challenges::{derive_challenges, derive_layer_betas, derive_query_indices, verify_pow},
    fri::verify_fold_chain,
    goldilocks::{eval_poly_le_bytes, Goldilocks},
    merkle::verify_path,
};
use alloc::vec::Vec;
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};

/// FRI-STARK verifier. Phase-3 scaffold.
///
/// Generic over the syscall backend so host-side oracle (arkworks / host
/// hashes) and on-chain (`solana_program::hash`) implementations share
/// the same algorithm body.
pub struct FriStark<'a, B: SyscallBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: SyscallBackend + ?Sized> FriStark<'a, B> {
    /// Construct against an existing backend.
    #[must_use]
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    /// Verify a FRI-STARK proof.
    ///
    /// Session-6 implementation: structural pipeline. Full Hadamard
    /// FRI-layer fold verification + trace/constraint Merkle opening
    /// lands in session 7 against Plonky3/Winterfell fixtures.
    ///
    /// ## Current pipeline
    ///
    /// ```text
    /// parse VK + proof + cross-check field/trace shape
    ///   ↓
    /// derive_challenges (α, z, query_seed) via SHA-256 transcript
    ///   ↓
    /// derive_query_indices (num_queries indices in trace domain)
    ///   ↓
    /// Ok(())
    /// ```
    ///
    /// ## Scaffold caveat
    ///
    /// The Merkle path verifier (`merkle::verify_path`) is built and
    /// unit-tested but not yet wired because the canonical
    /// `query_responses` field is a flat byte buffer — real FRI-STARK
    /// needs a structured layout (per-query leaf + path + neighbor).
    /// Session 7 extends canonical for that and calls the Merkle
    /// verifier per query index.
    ///
    /// ## Errors
    ///
    /// - `VerifyingKeyLengthMismatch` / `ProofLengthMismatch` — wire.
    /// - `VerifyingKeyProofMismatch` — field or trace shape disagree.
    /// - `Sha256SyscallFailed` — hash failure in challenge derivation.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        let vk = FriStarkVerifyingKey::from_bytes(vk_bytes)?;
        let proof = FriStarkProof::from_bytes(proof_bytes)?;

        if vk.field_id != proof.field_id
            || vk.trace_width != proof.trace_width
            || vk.trace_log_height != proof.trace_log_height
            || vk.log_blowup != proof.log_blowup
        {
            return Err(OnChainError::VerifyingKeyProofMismatch);
        }

        // Derive the three scaffold challenges via SHA-256 transcript.
        let challenges = derive_challenges(self.backend, &vk, public_inputs_bytes, &proof)?;

        // Derive per-query indices — domain size is 2^(trace_log_height
        // + log_blowup).
        let domain_log = proof.trace_log_height as u32 + proof.log_blowup as u32;
        if domain_log >= 64 {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let domain_size: u64 = 1u64 << domain_log;
        let indices = derive_query_indices(
            self.backend,
            &challenges.query_seed,
            proof.num_queries,
            domain_size,
        )?;

        // Session 7: per-query Merkle path verification against the
        // trace commitment. The proof's `query_responses` buffer is
        // parsed as (leaf, auth_path) pairs; each path is walked via
        // SHA-256 and compared to `proof.trace_commitment`. A single
        // tampered path yields `OnChainError::VerificationFailed`.
        //
        // Scaffold caveat: this only validates the trace commitment
        // side. Constraint-commitment paths + FRI-layer consistency
        // checks remain session 8 work (needs structured layout
        // extensions for constraint query responses + per-layer
        // opening bundles).
        let iter = proof
            .query_response_iter()
            .ok_or(OnChainError::ProofLengthMismatch)?;
        for ((t_leaf, t_path, c_leaf, c_path), idx) in iter.zip(indices.iter().copied()) {
            // Trace commitment path.
            verify_path(self.backend, t_leaf, t_path, idx, proof.trace_commitment)?;
            // Constraint commitment path (session 8 addition — second
            // soundness gate closes the composition-polynomial side).
            verify_path(self.backend, c_leaf, c_path, idx, proof.constraint_commitment)?;
        }

        // Proof-of-work grinding check (session 9). Rejects proofs
        // whose pow_nonce doesn't clear `pow_bits` leading zeros on
        // `sha256(query_seed ‖ nonce)` — forces a malicious prover
        // to exponentially increase brute-force work before they can
        // search for a favorable query_seed.
        verify_pow(
            self.backend,
            &challenges.query_seed,
            proof.pow_nonce,
            proof.pow_bits,
        )?;

        // FRI fold-chain verification (session 13b + 14a). For each
        // query, walk the layer openings, ensure the fold relation
        // holds at every step, and check the computed final value
        // matches the evaluation of `fri_final_poly` at that query's
        // final_x. Multi-coefficient final polynomial support
        // (session 14a) replaces the single-scalar scaffold from 13b.
        // Skipped when num_fri_layers = 0.
        if proof.num_fri_layers > 0 {
            // 1. Derive per-layer β challenges from the transcript.
            let beta_u64s = derive_layer_betas(
                self.backend,
                &challenges.query_seed,
                proof.fri_layer_commits,
                proof.num_fri_layers,
            )?;
            let betas: Vec<Goldilocks> =
                beta_u64s.iter().map(|&b| Goldilocks::new(b)).collect();

            // 2. Parse VK's domain generator ω.
            let omega = Goldilocks::from_bytes_le(&vk.omega_g)?;

            // 3. Parse per-query per-layer opening bundle.
            let opening_iter = proof
                .fri_layer_opening_iter()
                .ok_or(OnChainError::ProofLengthMismatch)?;
            let openings: Vec<(Goldilocks, Goldilocks)> = opening_iter
                .map(|(f_x_bytes, f_neg_x_bytes)| {
                    let f_x_arr: [u8; 8] = f_x_bytes.try_into().unwrap();
                    let f_neg_x_arr: [u8; 8] = f_neg_x_bytes.try_into().unwrap();
                    let f_x = Goldilocks::from_bytes_le(&f_x_arr)?;
                    let f_neg_x = Goldilocks::from_bytes_le(&f_neg_x_arr)?;
                    Ok::<_, OnChainError>((f_x, f_neg_x))
                })
                .collect::<Result<_, _>>()?;

            // 4. For each query:
            //    a. Walk the fold chain → (final_x, computed_final).
            //    b. Evaluate `fri_final_poly` at final_x →
            //       expected_final.
            //    c. Compare; mismatch → VerificationFailed.
            //
            //    Session 14a upgrade: instead of one shared
            //    `final_layer_value` scalar, each query can have a
            //    distinct expected value because the final polynomial
            //    has non-zero degree. This matches Plonky3/Winterfell
            //    semantics.
            let n_layers = proof.num_fri_layers as usize;
            for (q_idx, &global_idx) in indices.iter().enumerate() {
                let x_0 = omega.pow(global_idx);
                let start = q_idx * n_layers;
                let end = start + n_layers;
                let layer_evals = &openings[start..end];
                let (final_x, computed_final) =
                    verify_fold_chain(layer_evals, &betas, x_0)?;
                let expected_final =
                    eval_poly_le_bytes(proof.fri_final_poly, final_x)?;
                if computed_final != expected_final {
                    return Err(OnChainError::VerificationFailed);
                }
            }
        }

        Ok(())
    }
}

impl<B: SyscallBackend + ?Sized + Send + Sync + 'static> ProofSystem for FriStark<'_, B> {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::FriStark
    }

    fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        Self::verify(self, vk_bytes, proof_bytes, public_inputs_bytes)
    }

    fn estimated_compute_units(&self, _vk: &[u8], _proof: &[u8]) -> Option<u32> {
        // ADR-0005 budget: ≤14M CU (max-compute tier). Phase-3
        // implementation will return a tight per-proof estimate based
        // on num_queries × (fri_layers + 2 auth paths); for now return
        // the upper bound so callers can size compute_unit_limit safely.
        Some(14_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{sizes, StarkFieldId};
    use alloc::vec;

    struct MockBackend;
    impl SyscallBackend for MockBackend {
        fn alt_bn128_group_op(
            &self,
            _op: mosaic_core::syscall::AltBn128Op,
            _endianness: mosaic_core::syscall::InputEndianness,
            _input: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, OnChainError> {
            Err(OnChainError::UnsupportedOperation)
        }
        fn alt_bn128_compression(
            &self,
            _op: mosaic_core::syscall::AltBn128Compress,
            _input: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, OnChainError> {
            Err(OnChainError::UnsupportedOperation)
        }
        fn poseidon(
            &self,
            _params: mosaic_core::syscall::PoseidonParameters,
            _endianness: mosaic_core::syscall::InputEndianness,
            _inputs: &[&[u8]],
        ) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::UnimplementedProofSystem)
        }
        fn sha256(&self, _inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::Sha256SyscallFailed)
        }
        fn keccak256(&self, _inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::Keccak256SyscallFailed)
        }
    }

    /// Build a proof with the session-8 structured query layout.
    ///
    /// `log_h` + `log_blowup` determines the Merkle depth: each query
    /// response is **two** `(leaf, auth_path)` pairs concatenated —
    /// one for the trace commitment, one for the constraint
    /// commitment. Per-query total: `2 · (1 + depth) · 32 B`.
    ///
    /// For deterministic tests, all leaves and path nodes are filled
    /// with `leaf_fill` so callers can construct trees whose root is
    /// known analytically.
    fn proof_bytes(
        field: StarkFieldId,
        num_fri: u8,
        num_q: u16,
        log_h: u16,
        width: u32,
        log_blowup: u8,
        leaf_fill: u8,
    ) -> Vec<u8> {
        use crate::canonical::FRI_LAYER_OPENING_LEN;
        let ood_bytes = 10 * field.field_elem_bytes();
        let final_bytes = 4 * field.field_elem_bytes();
        let depth = (log_h as usize) + (log_blowup as usize);
        let per_query = 2 * (sizes::DIGEST_LEN + depth * sizes::DIGEST_LEN);
        let query_bytes = (num_q as usize) * per_query;
        let fri_openings_bytes =
            (num_q as usize) * (num_fri as usize) * FRI_LAYER_OPENING_LEN;
        let total = sizes::FIXED_HEADER_LEN
            + 2 * sizes::DIGEST_LEN
            + (num_fri as usize) * sizes::DIGEST_LEN
            + 4 + ood_bytes + 4 + final_bytes + 4 + query_bytes
            + 4 + fri_openings_bytes
            + 8 // final_layer_value
            + sizes::POW_NONCE_LEN;
        let mut buf = vec![0u8; total];
        buf[0] = field as u8;
        buf[1] = log_blowup;
        buf[2] = num_fri;
        buf[4..6].copy_from_slice(&num_q.to_le_bytes());
        buf[6..8].copy_from_slice(&log_h.to_le_bytes());
        buf[8..12].copy_from_slice(&width.to_le_bytes());
        let mut off = sizes::FIXED_HEADER_LEN
            + 2 * sizes::DIGEST_LEN
            + (num_fri as usize) * sizes::DIGEST_LEN;
        buf[off..off + 4].copy_from_slice(&(ood_bytes as u32).to_le_bytes());
        off += 4 + ood_bytes;
        buf[off..off + 4].copy_from_slice(&(final_bytes as u32).to_le_bytes());
        off += 4 + final_bytes;
        buf[off..off + 4].copy_from_slice(&(query_bytes as u32).to_le_bytes());
        off += 4;
        // Fill query_responses with the leaf_fill pattern so every
        // 32-byte chunk is a consistent leaf/sibling digest.
        for byte in buf[off..off + query_bytes].iter_mut() {
            *byte = leaf_fill;
        }
        off += query_bytes;
        buf[off..off + 4].copy_from_slice(&(fri_openings_bytes as u32).to_le_bytes());
        // fri_openings buffer + final_layer_value remain zero (default
        // behavior when num_fri = 0 is to skip the fold-chain check).
        buf
    }

    fn matching_vk(
        field: StarkFieldId,
        log_h: u16,
        width: u32,
        log_blowup: u8,
    ) -> Vec<u8> {
        FriStarkVerifyingKey {
            field_id: field,
            trace_width: width,
            trace_log_height: log_h,
            log_blowup,
            air_hash: [0; 32],
            omega_g: [0u8; 8],
        }
        .to_bytes()
    }

    /// Session-8 happy path: depth-0 Merkle trees (1 leaf each → leaf
    /// == root) for BOTH trace and constraint commitments. With both
    /// commits set to `leaf_fill` and query_responses filled with
    /// `leaf_fill`, every (trace_path, constraint_path) pair trivially
    /// verifies.
    #[test]
    fn full_pipeline_accepts_depth_zero_merkle_both_commits() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 0, 32, 0);
        let mut proof = proof_bytes(StarkFieldId::Goldilocks, 0, 4, 0, 32, 0, 0xAB);
        // Both commitments at offset FIXED_HEADER (trace) and
        // FIXED_HEADER + DIGEST_LEN (constraint).
        let trace_off = sizes::FIXED_HEADER_LEN;
        let constraint_off = trace_off + sizes::DIGEST_LEN;
        for byte in proof[trace_off..trace_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xAB;
        }
        for byte in proof[constraint_off..constraint_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xAB;
        }
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(r.is_ok(), "depth-0 dual Merkle check should pass, got {r:?}");
    }

    /// Session-8 trace-side soundness: trace_commitment mismatches
    /// the query leaves → first path check fails → `VerificationFailed`.
    #[test]
    fn rejects_mismatched_trace_merkle_leaf() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 0, 32, 0);
        let mut proof = proof_bytes(StarkFieldId::Goldilocks, 0, 4, 0, 32, 0, 0xAB);
        // Constraint commitment matches (0xAB), trace doesn't.
        let trace_off = sizes::FIXED_HEADER_LEN;
        let constraint_off = trace_off + sizes::DIGEST_LEN;
        for byte in proof[trace_off..trace_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xCD;
        }
        for byte in proof[constraint_off..constraint_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xAB;
        }
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(
            matches!(r, Err(OnChainError::VerificationFailed)),
            "mismatched trace leaf should fail Merkle, got {r:?}",
        );
    }

    /// Session-8 constraint-side soundness: trace check passes but
    /// constraint_commitment mismatches → second path check fails
    /// → `VerificationFailed`. Confirms the constraint commitment
    /// is actually being verified, not just parsed.
    #[test]
    fn rejects_mismatched_constraint_merkle_leaf() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 0, 32, 0);
        let mut proof = proof_bytes(StarkFieldId::Goldilocks, 0, 4, 0, 32, 0, 0xAB);
        // Trace commitment matches (0xAB), constraint doesn't.
        let trace_off = sizes::FIXED_HEADER_LEN;
        let constraint_off = trace_off + sizes::DIGEST_LEN;
        for byte in proof[trace_off..trace_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xAB;
        }
        for byte in proof[constraint_off..constraint_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xCD;
        }
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(
            matches!(r, Err(OnChainError::VerificationFailed)),
            "mismatched constraint leaf should fail Merkle, got {r:?}",
        );
    }

    /// Session-13b FRI fold happy path. Zero-filled layer openings +
    /// zero final_layer_value → fold chain produces 0 regardless of
    /// β and x, matches claimed final. Exercises the new
    /// `derive_layer_betas` + `verify_fold_chain` wire-up end-to-end.
    #[test]
    fn full_pipeline_accepts_fri_fold_chain() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = FriStark::new(&backend);
        // depth = 0 (log_h=0, log_blowup=0) → trivial Merkle; num_fri=1
        // so the new FRI fold-chain path runs.
        let mut vk_bytes = matching_vk(StarkFieldId::Goldilocks, 0, 32, 0);
        // Set ω to 7 (non-zero Goldilocks; pow(7, 0) = 1 so x_0 ≠ 0).
        let vk_omega_off = 40;
        vk_bytes[vk_omega_off..vk_omega_off + 8].copy_from_slice(&7u64.to_le_bytes());

        let mut proof = proof_bytes(StarkFieldId::Goldilocks, 1, 1, 0, 32, 0, 0xAB);
        // Set both commitments to match the leaf_fill pattern (session 8).
        let trace_off = sizes::FIXED_HEADER_LEN;
        let constraint_off = trace_off + sizes::DIGEST_LEN;
        for byte in proof[trace_off..trace_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xAB;
        }
        for byte in proof[constraint_off..constraint_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xAB;
        }
        // fri_layer_openings + final_layer_value left at all-zero →
        // fold chain produces 0 regardless of β, matches claimed 0.

        let r = FriStark::verify(&v, &vk_bytes, &proof, &[]);
        assert!(r.is_ok(), "FRI fold chain with zero openings should pass, got {r:?}");
    }

    /// Session-14a: tampered `fri_final_poly` coefficient. Poly
    /// evaluates to 1 at any final_x; fold chain produces 0 → mismatch
    /// → `VerificationFailed`. Demonstrates the multi-coefficient
    /// path rejects tampered final-polynomial evaluations.
    #[test]
    fn rejects_tampered_fri_final_poly() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = FriStark::new(&backend);
        let mut vk_bytes = matching_vk(StarkFieldId::Goldilocks, 0, 32, 0);
        vk_bytes[40..48].copy_from_slice(&7u64.to_le_bytes());

        let mut proof = proof_bytes(StarkFieldId::Goldilocks, 1, 1, 0, 32, 0, 0xAB);
        let trace_off = sizes::FIXED_HEADER_LEN;
        let constraint_off = trace_off + sizes::DIGEST_LEN;
        for byte in proof[trace_off..trace_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xAB;
        }
        for byte in proof[constraint_off..constraint_off + sizes::DIGEST_LEN].iter_mut() {
            *byte = 0xAB;
        }

        // Tamper with fri_final_poly's constant coefficient (c_0 = 1).
        // Layout order: FIXED_HEADER + 2·DIGEST + num_fri·DIGEST +
        //   len_prefix_4 + ood_bytes_(10·8=80) + len_prefix_4 + c_0 (first byte).
        let fri_layer_off = sizes::FIXED_HEADER_LEN + 2 * sizes::DIGEST_LEN
            + 1 * sizes::DIGEST_LEN; // num_fri = 1
        let ood_prefix_off = fri_layer_off;
        let ood_len = 10 * StarkFieldId::Goldilocks.field_elem_bytes(); // 80
        let final_prefix_off = ood_prefix_off + 4 + ood_len;
        let final_poly_off = final_prefix_off + 4;
        // c_0 = 1 (LE first byte).
        proof[final_poly_off] = 1;

        let r = FriStark::verify(&v, &vk_bytes, &proof, &[]);
        assert!(
            matches!(r, Err(OnChainError::VerificationFailed)),
            "tampered fri_final_poly coefficient should fail, got {r:?}",
        );
    }

    /// Session-7 length guard: query_responses buffer that doesn't
    /// match the structured `num_queries × (1 + depth) × DIGEST_LEN`
    /// shape is rejected up-front.
    #[test]
    fn rejects_malformed_query_responses_length() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 0, 32, 0);
        // Build a valid proof then shift n_queries to claim one extra
        // query without adding its 32 bytes of response → length
        // guard fires.
        let mut proof = proof_bytes(StarkFieldId::Goldilocks, 0, 4, 0, 32, 0, 0xAB);
        // Bump num_queries header from 4 to 5.
        proof[4..6].copy_from_slice(&5u16.to_le_bytes());
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(
            matches!(r, Err(OnChainError::ProofLengthMismatch)),
            "num_queries/buffer mismatch should fail length check, got {r:?}",
        );
    }

    #[test]
    fn rejects_vk_proof_field_mismatch() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        // VK says Goldilocks, proof says BabyBear.
        let vk = matching_vk(StarkFieldId::Goldilocks, 10, 8, 1);
        let proof = proof_bytes(StarkFieldId::BabyBear, 4, 10, 10, 8, 1, 0);
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyProofMismatch)));
    }

    #[test]
    fn rejects_vk_proof_trace_width_mismatch() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 16, 32, 1);
        let proof = proof_bytes(StarkFieldId::Goldilocks, 8, 40, 16, 64, 1, 0); // width 64 ≠ 32
        let r = FriStark::verify(&v, &vk, &proof, &[]);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyProofMismatch)));
    }

    #[test]
    fn rejects_wrong_vk_length() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        let bad_vk = vec![0u8; FriStarkVerifyingKey::SERIALIZED_LEN - 1];
        let proof = proof_bytes(StarkFieldId::Goldilocks, 4, 10, 10, 4, 1, 0);
        let r = FriStark::verify(&v, &bad_vk, &proof, &[]);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_proof_length() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        let vk = matching_vk(StarkFieldId::Goldilocks, 16, 32, 1);
        let bad_proof = vec![0u8; 8]; // way too short
        let r = FriStark::verify(&v, &vk, &bad_proof, &[]);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn estimated_cu_returns_adr_cap() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        assert_eq!(
            ProofSystem::estimated_compute_units(&v, &[], &[]),
            Some(14_000_000),
        );
    }

    #[test]
    fn proof_system_id_is_fri_stark() {
        let backend = MockBackend;
        let v = FriStark::new(&backend);
        assert_eq!(v.proof_system_id(), ProofSystemId::FriStark);
    }

    #[allow(dead_code)]
    fn boxed(v: FriStark<'static, MockBackend>) -> alloc::boxed::Box<dyn ProofSystem> {
        alloc::boxed::Box::new(v)
    }
}
