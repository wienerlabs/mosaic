//! Halo2-KZG verifier scaffold.
//!
//! Phase-2 freeze ships wire-format validation + a `ProofSystem` impl
//! returning `UnimplementedProofSystem`. Phase 3 lands the custom-gate
//! evaluation, lookup argument, permutation grand-product, quotient
//! aggregation, linearization MSM, and final KZG pairing check.
//!
//! ## Phase-3 round plan (for the implementer)
//!
//! ```text
//! verify(vk_bytes, proof_bytes, public_inputs_bytes):
//!     vk    = Halo2KzgVerifyingKey::from_bytes(vk_bytes)?;    // done
//!     proof = Halo2KzgProof::from_bytes(proof_bytes)?;        // done
//!
//!     // ---- Phase 3 work starts here ----
//!
//!     // Round 1: absorb VK + instance columns + advice commitments.
//!     transcript.absorb_vk(&vk);
//!     transcript.absorb_public_inputs(pi);
//!     for a in proof.advice_iter() { transcript.absorb_g1(a); }
//!     let theta = transcript.squeeze();  // lookup combine challenge
//!
//!     // Round 2: lookup `m` polynomials — one per lookup argument.
//!     for l in proof.lookup_commits.chunks_exact(G1_LEN) {
//!         transcript.absorb_g1(l);
//!     }
//!     let (beta, gamma) = (transcript.squeeze(), transcript.squeeze());
//!
//!     // Round 3: permutation grand-product.
//!     transcript.absorb_g1(proof.permutation_z);
//!     let y = transcript.squeeze();  // gate linear combination
//!
//!     // Round 4: vanishing H chunks.
//!     for h in proof.quotient_iter() { transcript.absorb_g1(h); }
//!     let xi = transcript.squeeze();  // evaluation point
//!
//!     // Round 5: evaluations at xi — gate, permutation, lookup, instance.
//!     for e in proof.evaluations_iter() { transcript.absorb_fr(e); }
//!
//!     // Check vanishing identity:
//!     //   t(ξ) · Z_H(ξ) ?= gate(ξ) + y · perm(ξ) + y² · lookup(ξ)
//!     verify_vanishing_identity(&proof, &vk, theta, beta, gamma, y, xi)?;
//!
//!     // Round 6: batched multipoint KZG opening at {ξ, ξω}.
//!     let v = transcript.squeeze();  // batch challenge
//!     transcript.absorb_g1(proof.w_xi);
//!     transcript.absorb_g1(proof.w_xiw);
//!     let u = transcript.squeeze();  // second batch challenge
//!
//!     verify_kzg_multipoint_opening(
//!         &vk, &proof, xi, v, u,
//!         /* evaluated commitments */,
//!     )?;
//!
//!     Ok(())
//! ```
//!
//! Shared primitives reused from `mosaic_plonk`:
//! - `mosaic_zk_primitives::fr` — Fr byte range ops
//! - `mosaic_zk_primitives::field` — arkworks Fr arithmetic
//! - `mosaic_zk_primitives::msm` — G1 MSM primitive
//! - `mosaic_zk_primitives::transcript` — Keccak-256 round transcript
//! - `mosaic_zk_primitives::g1_consts` — G1/G2 generator bytes for pairing

use crate::{
    bundle::{idx, EvaluationBundle},
    canonical::{Halo2KzgProof, Halo2KzgVerifyingKey},
    challenges::derive_challenges,
    circuit::combined_expr,
    kzg::verify_two_point_opening_multipoly,
    vanishing::{compute_t_from_chunks, compute_z_h, vanishing_identity_holds},
};
use alloc::vec::Vec;
use ark_bn254::Fr;
use mosaic_zk_primitives::field::{fr_from_canonical_bytes, fr_to_canonical_bytes};
use mosaic_zk_primitives::transcript::derive_fr_challenge;
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::SyscallBackend,
    OnChainError,
};

/// Halo2-KZG verifier over BN254 (Privacy Scaling Explorations fork).
/// Phase-3 scaffold.
pub struct Halo2KzgBn254<'a, B: SyscallBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: SyscallBackend + ?Sized> Halo2KzgBn254<'a, B> {
    /// Construct against an existing backend.
    #[must_use]
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    /// Verify a Halo2-KZG proof.
    ///
    /// Session-4d implementation: full pipeline from parse through
    /// KZG scaffold opening. Returns `Ok(())` on success.
    ///
    /// ## Scaffold caveat
    ///
    /// The vanishing-identity check uses scaffold circuit evaluators
    /// (`circuit.rs`) and the KZG opening uses a **single-commitment**
    /// scaffold (`kzg.rs::verify_opening_scaffold`) — not Halo2's
    /// full two-point batched multipoint opening over all committed
    /// polys. Both are structurally correct (transcript + MSM +
    /// pairing run end-to-end) but not cryptographically equivalent
    /// to Espresso/PSE's reference verifier. Session 4e pins these
    /// against real fixtures.
    ///
    /// ## Errors
    ///
    /// - `VerifyingKeyLengthMismatch` / `ProofLengthMismatch` — wire.
    /// - `PublicInputCountMismatch` / `PublicInputOutOfRange` —
    ///   instance column validation.
    /// - `PairingCheckFailed` — KZG scaffold opening failed.
    /// - `InvalidPointEncoding` — malformed G1 commitment.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        // 1. Parse + basic cross-checks.
        let vk = Halo2KzgVerifyingKey::from_bytes(vk_bytes)?;
        let proof = Halo2KzgProof::from_bytes(proof_bytes)?;
        if vk.n_advice != proof.n_advice {
            return Err(OnChainError::VerifyingKeyProofMismatch);
        }

        // 2. Derive challenges (θ, β, γ, y, ξ) from transcript.
        let (challenges, _transcript) =
            derive_challenges(self.backend, &vk, public_inputs_bytes, &proof)?;

        // 3. Parse the evaluation bundle per the scaffold layout.
        //    Enforces `n_evals == 16 + n_quotient` and positions each
        //    wire/selector/perm/lookup/quotient evaluation.
        let bundle = EvaluationBundle::from_proof(&proof)?;

        // 4. Vanishing-identity check at ξ.
        //    LHS: t(ξ) · Z_H(ξ) where t(ξ) comes from quotient chunks.
        //    RHS: gate_expr + y·perm_expr + y²·lookup_expr.
        let t_xi = compute_t_from_chunks(&bundle.quotient_chunks, &challenges.xi, vk.k)?;
        let z_h_xi = compute_z_h(&challenges.xi, vk.k)?;
        let combined = combined_expr(
            &bundle.wires,
            &bundle.selectors,
            &bundle.permutation,
            &bundle.lookup,
            &challenges.theta,
            &challenges.beta,
            &challenges.gamma,
            &challenges.y,
            &challenges.xi,
        )?;
        // Split gate / perm / lookup back out for identity check: we
        // passed them through `combined_expr` already, which computes
        // `gate + y·perm + y²·lookup`. Compare LHS = t·Z_H to that
        // combined RHS.
        let lhs = t_xi * z_h_xi;
        if lhs != combined {
            // Note: using the pairing helper with split inputs gives
            // the same result but we'd duplicate the arithmetic. Keep
            // the direct comparison for clarity. `vanishing_identity_holds`
            // is available for callers who have pre-split terms.
            let _ = vanishing_identity_holds; // keep the primitive public.
            return Err(OnChainError::SumcheckFailed);
        }

        // 5. Session-17: multi-poly two-point batched KZG opening.
        //    The evolutionary upgrade over session-16 batches every
        //    committed polynomial via a `v` challenge before the
        //    two-point (ξ, ξω) reduction's second `u` challenge.
        //
        //    Tampering with any advice / lookup / quotient commit or
        //    its paired evaluation now propagates into the batched
        //    pairing → PairingCheckFailed (structurally matches PSE
        //    `halo2_proofs::plonk::verify_proof`).
        let omega = fr_from_canonical_bytes(&vk.omega_fr)?;
        let xi_omega = challenges.xi * omega;

        // Canonical commit/eval ordering at ξ (matches the bundle
        // layout that the vanishing identity consumed). Session 20:
        // VK-side preprocessed commits (selectors + σ polynomials)
        // now join the proof-side commits in the batched MSM.
        use crate::canonical::sizes::G1_LEN;
        let n_fixed = vk.fixed_commits.len() / G1_LEN;
        let n_permutation = vk.permutation_commits.len() / G1_LEN;
        let commits_xi = collect_commits_at_xi(&proof, &vk)?;
        let evals_xi = collect_evals_at_xi(
            &bundle,
            proof.n_advice as usize,
            proof.n_lookups as usize,
            n_fixed,
            n_permutation,
        );

        // At ξω only the permutation grand-product shifts.
        let commits_xi_omega: [&[u8]; 1] = [proof.permutation_z];
        let evals_xi_omega: [Fr; 1] = [bundle.permutation.z_next];

        // `v` = multi-poly batching challenge; `u` = two-point
        // batching challenge. Both derived via domain-separated
        // keccak so tampering with any ingredient re-rolls them.
        let v = derive_fr_challenge(
            self.backend,
            b"mosaic-halo2/v",
            &[&fr_to_canonical_bytes(&challenges.xi), proof.evaluations],
        )?;

        let u = derive_fr_challenge(
            self.backend,
            b"mosaic-halo2/u",
            &[
                &fr_to_canonical_bytes(&challenges.xi),
                &vk.omega_fr,
                proof.w_xi,
                proof.w_xiw,
            ],
        )?;

        verify_two_point_opening_multipoly(
            self.backend,
            &vk,
            &commits_xi,
            &evals_xi,
            &commits_xi_omega,
            &evals_xi_omega,
            proof.w_xi,
            proof.w_xiw,
            &challenges.xi,
            &xi_omega,
            &v,
            &u,
        )?;

        Ok(())
    }
}


/// Commit ordering at ξ (scaffold): advice + lookup + `permutation_z` + quotient.
/// Fixed selector commits + permutation σ commits live in the VK and are
/// paired only structurally; they aren't batched at the proof-side MSM
/// until VK-side commit bytes are wired through.
fn collect_commits_at_xi<'a>(
    proof: &'a Halo2KzgProof<'a>,
    vk: &'a Halo2KzgVerifyingKey,
) -> Result<Vec<&'a [u8]>, OnChainError> {
    use crate::canonical::sizes::G1_LEN;
    let fixed_count = vk.fixed_commits.len() / G1_LEN;
    let perm_count = vk.permutation_commits.len() / G1_LEN;
    let mut out: Vec<&'a [u8]> = Vec::with_capacity(
        proof.n_advice as usize
            + proof.n_lookups as usize
            + 1
            + proof.n_quotient as usize
            + fixed_count
            + perm_count,
    );
    // Proof-side commits first (advice + lookup + permutation_z +
    // quotient chunks). This ordering keeps the pre-session-20 MSM
    // behavior unchanged for VKs with empty fixed / permutation
    // commit sets (e.g. the minimal test VKs).
    for a in proof.advice_iter() {
        out.push(a);
    }
    for l in proof.lookup_commits.chunks_exact(G1_LEN) {
        out.push(l);
    }
    out.push(proof.permutation_z);
    for h in proof.quotient_iter() {
        out.push(h);
    }
    // Session 20: VK-side preprocessed commits (fixed selectors +
    // permutation σ polynomials) now also enter the multi-poly MSM.
    // Real PSE Halo2 treats these the same as proof-side commits
    // for the batched opening; only the commitment bytes live in
    // the VK instead of the proof.
    for f in vk.fixed_commits.chunks_exact(G1_LEN) {
        out.push(f);
    }
    for s in vk.permutation_commits.chunks_exact(G1_LEN) {
        out.push(s);
    }
    Ok(out)
}

/// Evaluation ordering at ξ paired 1:1 to `collect_commits_at_xi`:
/// - advice[i] ↔ wires A/B/C (clamped to `min(i, 2)`; extra advice
///   columns reuse the last wire evaluation as a scaffold placeholder
///   — real Halo2 has a matching per-column eval)
/// - lookup commits ↔ `LOOKUP_M` evaluation repeated per lookup
///   (scaffold: bundle carries one combined `lookup_m` eval)
/// - `permutation_z` ↔ Z
/// - quotient chunks ↔ `FIXED_SLOTS+i` quotient evaluations
/// - `fixed_commits` (session 20) ↔ selectors `Q_M/Q_L/Q_R/Q_O/Q_C`
///   in order; extra fixed commits reuse `Q_C` as scaffold placeholder
/// - `permutation_commits` (session 20) ↔ `SIGMA_1/SIGMA_2/SIGMA_3` in
///   order; extra σ commits reuse `SIGMA_3` as scaffold placeholder
fn collect_evals_at_xi(
    bundle: &EvaluationBundle,
    n_advice: usize,
    n_lookups: usize,
    n_fixed: usize,
    n_permutation: usize,
) -> Vec<Fr> {
    let wire_evals = [bundle.wires.a, bundle.wires.b, bundle.wires.c];
    let selector_evals = [
        bundle.selectors.q_m,
        bundle.selectors.q_l,
        bundle.selectors.q_r,
        bundle.selectors.q_o,
        bundle.selectors.q_c,
    ];
    let sigma_evals = [
        bundle.permutation.sigma_1,
        bundle.permutation.sigma_2,
        bundle.permutation.sigma_3,
    ];
    let mut out = Vec::with_capacity(
        n_advice
            + n_lookups
            + 1
            + bundle.quotient_chunks.len()
            + n_fixed
            + n_permutation,
    );
    for i in 0..n_advice {
        out.push(wire_evals[i.min(idx::C)]);
    }
    for _ in 0..n_lookups {
        out.push(bundle.lookup.m);
    }
    out.push(bundle.permutation.z);
    for q in &bundle.quotient_chunks {
        out.push(*q);
    }
    for i in 0..n_fixed {
        out.push(selector_evals[i.min(selector_evals.len() - 1)]);
    }
    for i in 0..n_permutation {
        out.push(sigma_evals[i.min(sigma_evals.len() - 1)]);
    }
    out
}

impl<B: SyscallBackend + ?Sized + Send + Sync + 'static> ProofSystem for Halo2KzgBn254<'_, B> {
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::Halo2KzgBn254
    }

    fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        Self::verify(self, vk_bytes, proof_bytes, public_inputs_bytes)
    }

    fn estimated_compute_units(&self, vk: &[u8], proof: &[u8]) -> Option<u32> {
        // Session 29: parse VK + proof to derive a proof-shape-aware
        // estimate. Decomposition (ADR-0005 algorithmic model):
        //   base (parse + vanishing + pairing) ≈ 90 000 CU
        //   per commit in the multi-poly MSM    ≈  4 000 CU
        //   per Fr evaluation in y_batched      ≈    250 CU
        // Commits counted: advice + lookup + permutation_z + quotient
        // (proof-side) + vk.fixed_commits + vk.permutation_commits
        // (VK-side, session 20). Evals: proof.n_evals.
        //
        // Clamped to the ADR-0005 hard cap (700 000) on the high end
        // and a conservative floor (120 000) on the low end to give
        // callers meaningful headroom. Real per-proof CU drops in
        // when fixture-driven bpf-bench targets land.
        use crate::canonical::sizes::G1_LEN;
        let vk_parsed = Halo2KzgVerifyingKey::from_bytes(vk).ok()?;
        let proof_parsed = Halo2KzgProof::from_bytes(proof).ok()?;
        let n_fixed = (vk_parsed.fixed_commits.len() / G1_LEN) as u32;
        let n_perm = (vk_parsed.permutation_commits.len() / G1_LEN) as u32;
        let commit_count = proof_parsed
            .n_advice
            .saturating_add(proof_parsed.n_lookups)
            .saturating_add(1) // permutation_z
            .saturating_add(proof_parsed.n_quotient)
            .saturating_add(n_fixed)
            .saturating_add(n_perm);
        let base = 90_000_u32;
        let per_commit = 4_000_u32;
        let per_eval = 250_u32;
        let est = base
            .saturating_add(per_commit.saturating_mul(commit_count))
            .saturating_add(per_eval.saturating_mul(proof_parsed.n_evals));
        Some(est.clamp(120_000, 700_000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN};
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

    fn dummy_vk_bytes() -> alloc::vec::Vec<u8> {
        Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            // Real G2 generator — pairing syscall rejects (0,0,0,0).
            x2_g2: mosaic_zk_primitives::g1_consts::g2_generator_bytes(),
            omega_fr: [0u8; 32],
            fixed_commits: vec![0; 2 * G1_LEN],
            permutation_commits: vec![0; 5 * G1_LEN],
        }
        .to_bytes()
    }

    /// Build a proof where the evaluation bundle satisfies the
    /// vanishing identity `t(ξ)·Z_H(ξ) = 0 = combined_expr` trivially:
    ///
    /// - Wires/selectors/perm all zero → gate_expr = 0, perm_expr = 0.
    /// - Lookup: `m = 1, input = 0, table = 0` → `1/θ - 1/θ = 0`.
    /// - Quotient chunks all zero → t(ξ) = 0.
    ///
    /// With n_quotient = 3, bundle layout requires n_evals = 19
    /// (FIXED_SLOTS 16 + 3 quotient chunks).
    ///
    /// Session-17: `n_lookups = 0` keeps the multi-poly batched opening
    /// skip-lookup-commits invariant from kicking in on the all-zero
    /// proof. The vanishing identity still reads `LOOKUP_M = 1` from
    /// the evaluation bundle (lookup_expr → 0 with m=1 & input=table=0),
    /// so gate+perm+lookup combined_expr stays at 0 on the RHS.
    fn dummy_proof_bytes_typical() -> alloc::vec::Vec<u8> {
        use mosaic_zk_primitives::field::fr_to_canonical_bytes;
        let n_advice: u32 = 5;
        let n_lookups: u32 = 0;
        let n_quotient: u32 = 3;
        let n_evals: u32 = 19; // 16 + 3
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = alloc::vec![0u8; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());

        // Evaluations offset.
        let evals_off = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN;
        // Set lookup.m = 1 so lookup_expr evaluates to zero.
        let m_off = evals_off + crate::bundle::idx::LOOKUP_M * FR_LEN;
        let one_bytes = fr_to_canonical_bytes(&ark_bn254::Fr::from(1u64));
        buf[m_off..m_off + FR_LEN].copy_from_slice(&one_bytes);
        // All other evaluations stay zero; quotient chunks zero →
        // t(ξ) = 0; identity 0 = 0 holds.
        buf
    }

    /// Full pipeline with real host backend: parse → challenges →
    /// vanishing identity check → KZG scaffold opening.
    /// Constructed bundle satisfies the identity trivially.
    #[test]
    fn full_pipeline_zero_proof_accepts() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = Halo2KzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let proof = dummy_proof_bytes_typical();
        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(r.is_ok(), "identity-satisfying bundle should pass, got {r:?}");
    }

    /// Session-20 dedicated tamper test: swap the first 64 bytes of
    /// `vk.fixed_commits` (the `q_M` selector commitment) from zero
    /// to the G1 generator. The session-17 multi-poly MSM batched
    /// only proof-side commits; session 20 folds in the VK's
    /// preprocessed (selector + σ) commits too. A tampered VK
    /// selector commit now breaks the batched pairing identity, same
    /// as a proof-side tamper would.
    #[test]
    fn multipoly_rejects_tampered_vk_selector_commit() {
        use mosaic_zk_primitives::g1_consts::g1_generator_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = Halo2KzgBn254::new(&backend);

        // Build a VK with the tampered q_M selector commit. Start
        // from the zero-commit default, then overwrite the first
        // fixed slot (corresponds to q_M in the selector ordering).
        let mut vk_struct = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: mosaic_zk_primitives::g1_consts::g2_generator_bytes(),
            omega_fr: [0u8; 32],
            fixed_commits: vec![0; 2 * G1_LEN],
            permutation_commits: vec![0; 5 * G1_LEN],
        };
        vk_struct.fixed_commits[..G1_LEN].copy_from_slice(&g1_generator_bytes());
        let vk = vk_struct.to_bytes();

        let proof = dummy_proof_bytes_typical();
        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "tampered VK selector commit should fail multi-poly \
             batched pairing, got {r:?}",
        );
    }

    /// Session-20 companion: swap the first `permutation_commits`
    /// entry (the `σ_1` commitment) to the G1 generator. The σ
    /// polynomials are the VK's permutation argument data — any
    /// tampering of them must be caught by the batched opening.
    #[test]
    fn multipoly_rejects_tampered_vk_permutation_commit() {
        use mosaic_zk_primitives::g1_consts::g1_generator_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = Halo2KzgBn254::new(&backend);

        let mut vk_struct = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: mosaic_zk_primitives::g1_consts::g2_generator_bytes(),
            omega_fr: [0u8; 32],
            fixed_commits: vec![0; 2 * G1_LEN],
            permutation_commits: vec![0; 5 * G1_LEN],
        };
        vk_struct.permutation_commits[..G1_LEN]
            .copy_from_slice(&g1_generator_bytes());
        let vk = vk_struct.to_bytes();

        let proof = dummy_proof_bytes_typical();
        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "tampered VK permutation-σ commit should fail multi-poly \
             batched pairing, got {r:?}",
        );
    }

    /// Session-17 dedicated tamper test: swap `advice_commits[0]`
    /// from the all-zero baseline to the G1 generator. Unlike the
    /// session-16 `two_point_rejects_tampered_z_next_eval` test
    /// which exercises only the permutation-z evaluation, this path
    /// verifies the new multi-poly MSM actually batches all commits
    /// — a valid-on-curve but non-zero advice commit with zero
    /// opening evaluation must propagate through the v-weighted MSM
    /// into the batched pairing identity.
    #[test]
    fn multipoly_rejects_tampered_advice_commit() {
        use mosaic_zk_primitives::g1_consts::g1_generator_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = Halo2KzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let mut proof = dummy_proof_bytes_typical();

        // Replace advice[0] with the G1 generator (valid-on-curve,
        // non-zero). With zero evaluations across the bundle, the
        // v-weighted MSM produces a non-zero `C_ξ_batched` while
        // `y_ξ_batched = 0` — the two-point opening check fails.
        let advice0_off = FIXED_HEADER_LEN;
        proof[advice0_off..advice0_off + G1_LEN]
            .copy_from_slice(&g1_generator_bytes());

        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "tampered advice commit should fail multi-poly batched \
             pairing, got {r:?}",
        );
    }

    /// Session-17 companion: flip the wire evaluation `a(ξ)`. With
    /// zero commits + v-batched MSM, a non-zero wire eval makes
    /// `y_ξ_batched = v^0·a + v^1·b + v^2·c = v^0·(tampered) ≠ 0`,
    /// again breaking the batched opening.
    #[test]
    fn multipoly_rejects_tampered_wire_a_evaluation() {
        use mosaic_zk_primitives::field::fr_to_canonical_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = Halo2KzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let mut proof = dummy_proof_bytes_typical();

        // Evaluations start after fixed + advice + lookup + perm_z + quotient.
        // n_advice=5, n_lookups=0, n_quotient=3 → evals_off = 16 + 5·64 + 0 + 64 + 3·64 = 592.
        let evals_off = FIXED_HEADER_LEN
            + 5 * G1_LEN
            + 0 * G1_LEN
            + G1_LEN
            + 3 * G1_LEN;
        let a_off = evals_off + idx::A * FR_LEN;
        // Set a(ξ) = 1 while leaving commits zero — breaks the opening.
        proof[a_off..a_off + FR_LEN]
            .copy_from_slice(&fr_to_canonical_bytes(&Fr::from(1u64)));

        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "tampered wire-a evaluation should fail multi-poly batched \
             pairing, got {r:?}",
        );
    }

    /// Tampered gate: set q_c = 1 → gate_expr = 1 ≠ 0 =
    /// t(ξ)·Z_H(ξ). Identity fails.
    #[test]
    fn rejects_tampered_gate_coefficient() {
        use mosaic_zk_primitives::field::fr_to_canonical_bytes;
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let v = Halo2KzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let mut proof = dummy_proof_bytes_typical();

        // Locate q_c slot inside the evaluation bundle.
        let evals_off = FIXED_HEADER_LEN
            + 5 * G1_LEN // advice
            + 1 * G1_LEN // lookup
            + G1_LEN     // permutation z
            + 3 * G1_LEN; // quotient chunks
        let q_c_off = evals_off + crate::bundle::idx::Q_C * FR_LEN;
        let one = fr_to_canonical_bytes(&ark_bn254::Fr::from(1u64));
        proof[q_c_off..q_c_off + FR_LEN].copy_from_slice(&one);

        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &proof, &pi);
        assert!(
            matches!(r, Err(OnChainError::SumcheckFailed)),
            "tampered q_c should fail vanishing identity, got {r:?}",
        );
    }

    #[test]
    fn rejects_wrong_vk_length_before_unimplemented() {
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        let bad_vk = alloc::vec![0u8; Halo2KzgVerifyingKey::FIXED_LEN - 1];
        let proof = dummy_proof_bytes_typical();
        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &bad_vk, &proof, &pi);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn rejects_wrong_proof_length_before_unimplemented() {
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let bad_proof = alloc::vec![0u8; 32]; // way too short
        let pi = [0u8; FR_LEN];
        let r = Halo2KzgBn254::verify(&v, &vk, &bad_proof, &pi);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn estimated_cu_returns_none_for_unparseable_input() {
        // Session 29: estimator parses VK + proof to derive a shape-
        // aware estimate. Empty inputs fail canonical parsing → None.
        // Callers sizing compute_unit_limit should either supply real
        // bytes or fall back to the ADR-0005 hard cap (700 000).
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        assert_eq!(
            ProofSystem::estimated_compute_units(&v, &[], &[]),
            None,
        );
    }

    #[test]
    fn estimated_cu_clamps_within_session29_bounds() {
        // For a realistic proof shape, the estimator must land in
        // the [120_000, 700_000] clamp range.
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        let vk = dummy_vk_bytes();
        let proof = dummy_proof_bytes_typical();
        let est = ProofSystem::estimated_compute_units(&v, &vk, &proof);
        let n = est.expect("parseable inputs should yield Some estimate");
        assert!(
            (120_000..=700_000).contains(&n),
            "estimate {n} out of [120_000, 700_000] clamp range"
        );
    }

    #[test]
    fn proof_system_id_is_halo2() {
        let backend = MockBackend;
        let v = Halo2KzgBn254::new(&backend);
        assert_eq!(v.proof_system_id(), ProofSystemId::Halo2KzgBn254);
    }

    /// Object-safety smoke test: this must compile.
    #[allow(dead_code)]
    fn boxed(v: Halo2KzgBn254<'static, MockBackend>) -> alloc::boxed::Box<dyn ProofSystem> {
        alloc::boxed::Box::new(v)
    }
}
