//! PLONK Fiat-Shamir challenge derivation — rounds 1-6.
//!
//! Produces the six challenges the verifier needs, following the snarkjs
//! 0.7.x PLONK absorb ordering (canonical reference:
//! `snarkjs/src/plonk_verify.js::calculatechallenges`):
//!
//! | Round | Challenge | Fresh transcript absorbs |
//! |---|---|---|
//! | 2a    | β         | Qm, Ql, Qr, Qo, Qc, S1, S2, S3; public inputs; proof A, B, C |
//! | 2b    | γ         | β |
//! | 3     | α         | β, γ, proof.Z |
//! | 4     | ξ         | α, proof.T1, proof.T2, proof.T3 |
//! | 5     | v         | ξ, eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw |
//! | 6     | u         | proof.W_xi, proof.W_xiw |
//!
//! Round 6 intentionally does **not** absorb v — snarkjs's u challenge
//! depends only on the two opening-proof commitments. This was a subtle
//! pre-fix bug caught by cross-referencing the snarkjs source.
//!
//! gnark PLONK uses slightly different ordering; a future
//! `mosaic-serde::gnark` adapter will route through a configurable
//! transcript rather than forking this module.

use crate::{
    canonical::{sizes::G1_LEN, PlonkProof, PlonkVerifyingKey},
    fr,
    transcript::{Kind, Transcript},
};
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// All six Fiat-Shamir challenges for a single PLONK proof, as 32-byte
/// big-endian Fr elements.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RoundChallenges {
    /// Permutation argument β.
    pub beta: [u8; 32],
    /// Permutation argument γ.
    pub gamma: [u8; 32],
    /// Quotient separation α.
    pub alpha: [u8; 32],
    /// Evaluation point ξ.
    pub xi: [u8; 32],
    /// Linearization batch v (= v_1; higher powers computed on demand).
    pub v: [u8; 32],
    /// Opening batch u.
    pub u: [u8; 32],
}

impl RoundChallenges {
    /// Derive all six challenges from VK + proof + public inputs using
    /// the snarkjs-compatible absorb ordering.
    ///
    /// `public_inputs_bytes` must be `vk.n_public * 32` big-endian Fr
    /// elements concatenated.
    pub fn derive<B: SyscallBackend + ?Sized>(
        backend: &B,
        vk: &PlonkVerifyingKey,
        proof: &PlonkProof<'_>,
        public_inputs_bytes: &[u8],
    ) -> Result<Self, OnChainError> {
        let expected_pi_len = (vk.n_public as usize)
            .checked_mul(32)
            .ok_or(OnChainError::PublicInputCountMismatch)?;
        if public_inputs_bytes.len() != expected_pi_len {
            return Err(OnChainError::PublicInputCountMismatch);
        }
        for chunk in public_inputs_bytes.chunks_exact(32) {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(chunk);
            if !fr::lt_r(&buf) {
                return Err(OnChainError::PublicInputOutOfRange);
            }
        }

        let mut transcript = Transcript::new(Kind::Keccak256, backend);

        // ---------- Round 2a: β ----------
        transcript.absorb_g1(&vk.qm_g1)?;
        transcript.absorb_g1(&vk.ql_g1)?;
        transcript.absorb_g1(&vk.qr_g1)?;
        transcript.absorb_g1(&vk.qo_g1)?;
        transcript.absorb_g1(&vk.qc_g1)?;
        transcript.absorb_g1(&vk.s1_g1)?;
        transcript.absorb_g1(&vk.s2_g1)?;
        transcript.absorb_g1(&vk.s3_g1)?;
        transcript.absorb(public_inputs_bytes);
        transcript.absorb_g1(proof.a)?;
        transcript.absorb_g1(proof.b)?;
        transcript.absorb_g1(proof.c)?;
        let beta = transcript.get_challenge()?;

        // ---------- Round 2b: γ ----------
        transcript.reset();
        transcript.absorb_fr(&beta)?;
        let gamma = transcript.get_challenge()?;

        // ---------- Round 3: α ----------
        transcript.reset();
        transcript.absorb_fr(&beta)?;
        transcript.absorb_fr(&gamma)?;
        transcript.absorb_g1(proof.z)?;
        let alpha = transcript.get_challenge()?;

        // ---------- Round 4: ξ ----------
        transcript.reset();
        transcript.absorb_fr(&alpha)?;
        transcript.absorb_g1(proof.t1)?;
        transcript.absorb_g1(proof.t2)?;
        transcript.absorb_g1(proof.t3)?;
        let xi = transcript.get_challenge()?;

        // ---------- Round 5: v ----------
        transcript.reset();
        transcript.absorb_fr(&xi)?;
        transcript.absorb_fr(proof.eval_a)?;
        transcript.absorb_fr(proof.eval_b)?;
        transcript.absorb_fr(proof.eval_c)?;
        transcript.absorb_fr(proof.eval_s1)?;
        transcript.absorb_fr(proof.eval_s2)?;
        transcript.absorb_fr(proof.eval_zw)?;
        let v = transcript.get_challenge()?;

        // ---------- Round 6: u ----------
        // SUBTLE: snarkjs's u transcript does NOT absorb v. Only the two
        // opening-proof commitments. Getting this wrong produces challenges
        // that verify nothing (the pairing fails on valid proofs).
        transcript.reset();
        transcript.absorb_g1(proof.w_xi)?;
        transcript.absorb_g1(proof.w_xiw)?;
        let u = transcript.get_challenge()?;

        debug_assert_eq!(G1_LEN, 64);
        Ok(Self {
            beta,
            gamma,
            alpha,
            xi,
            v,
            u,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::{FR_LEN, G2_LEN, PROOF_LEN};

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
        fn keccak256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            use tiny_keccak::{Hasher, Keccak};
            let mut h = Keccak::v256();
            for i in inputs {
                h.update(i);
            }
            let mut out = [0u8; 32];
            h.finalize(&mut out);
            Ok(out)
        }
    }

    fn zero_vk(n_public: u32) -> PlonkVerifyingKey {
        PlonkVerifyingKey {
            qm_g1: [0; G1_LEN],
            ql_g1: [0; G1_LEN],
            qr_g1: [0; G1_LEN],
            qo_g1: [0; G1_LEN],
            qc_g1: [0; G1_LEN],
            s1_g1: [0; G1_LEN],
            s2_g1: [0; G1_LEN],
            s3_g1: [0; G1_LEN],
            x2_g2: [0; G2_LEN],
            power: 10,
            k1: [0; FR_LEN],
            k2: [0; FR_LEN],
            omega: [0; FR_LEN],
            n_public,
        }
    }

    #[test]
    fn derive_is_deterministic() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
        let pi = [0u8; FR_LEN];

        let c1 = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
        let c2 = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn derive_changes_with_public_inputs() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();

        let mut pi1 = [0u8; FR_LEN];
        pi1[FR_LEN - 1] = 1;
        let mut pi2 = [0u8; FR_LEN];
        pi2[FR_LEN - 1] = 2;

        let c1 = RoundChallenges::derive(&backend, &vk, &proof, &pi1).unwrap();
        let c2 = RoundChallenges::derive(&backend, &vk, &proof, &pi2).unwrap();
        assert_ne!(c1.beta, c2.beta);
    }

    #[test]
    fn derive_rejects_wrong_public_input_count() {
        let backend = MockBackend;
        let vk = zero_vk(2);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
        let bad_pi = [0u8; FR_LEN];
        assert!(matches!(
            RoundChallenges::derive(&backend, &vk, &proof, &bad_pi),
            Err(OnChainError::PublicInputCountMismatch),
        ));
    }

    #[test]
    fn derive_rejects_out_of_range_public_input() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
        let bad_pi = fr::BN254_FR_MODULUS_BE;
        assert!(matches!(
            RoundChallenges::derive(&backend, &vk, &proof, &bad_pi),
            Err(OnChainError::PublicInputOutOfRange),
        ));
    }

    #[test]
    fn all_challenges_in_fr_range() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let proof_bytes = [0x11u8; PROOF_LEN];
        let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
        let pi = [0u8; FR_LEN];

        let c = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
        for challenge in [c.beta, c.gamma, c.alpha, c.xi, c.v, c.u] {
            assert!(fr::lt_r(&challenge));
        }
    }

    #[test]
    fn different_proofs_produce_different_challenges() {
        let backend = MockBackend;
        let vk = zero_vk(1);
        let pi = [0u8; FR_LEN];

        let proof_a_bytes = [0x11u8; PROOF_LEN];
        let proof_a = PlonkProof::from_bytes(&proof_a_bytes).unwrap();
        let c_a = RoundChallenges::derive(&backend, &vk, &proof_a, &pi).unwrap();

        let proof_b_bytes = [0x22u8; PROOF_LEN];
        let proof_b = PlonkProof::from_bytes(&proof_b_bytes).unwrap();
        let c_b = RoundChallenges::derive(&backend, &vk, &proof_b, &pi).unwrap();

        assert_ne!(c_a.beta, c_b.beta);
        assert_ne!(c_a.u, c_b.u);
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 39 — proptest coverage for KZG-PLONK Fiat-Shamir.
    //
    // PLONK's 6-round absorb sequence (snarkjs 0.7.x compatible):
    //
    //   Round 2a: β  ← (vk: 8 commits, public inputs, proof.A, B, C)
    //   Round 2b: γ  ← (β)
    //   Round 3:  α  ← (β, γ, proof.Z)
    //   Round 4:  ξ  ← (α, proof.T1, T2, T3)
    //   Round 5:  v  ← (ξ, proof.eval_a, b, c, s1, s2, zw)
    //   Round 6:  u  ← (proof.W_xi, W_xiw)            *not* v
    //
    // The "u absorbs only the two opening commitments" rule is a subtle
    // snarkjs-compatibility bit (documented in the module header) — the
    // proptests below pin it explicitly so a future "transcript fix"
    // that adds v back to u's seed would surface as a property failure.
    //
    // Granular cascade properties per round:
    //
    //   - ABC mutation         ⇒ β, γ, α, ξ, v shift; u stable
    //   - Z mutation           ⇒ α, ξ, v shift; β, γ, u stable
    //   - T1/T2/T3 mutation    ⇒ ξ, v shift; β, γ, α, u stable
    //   - Eval (5 evals + zw)  ⇒ v shift only; β, γ, α, ξ, u stable
    //   - W_xi / W_xiw         ⇒ u shift only; everything else stable
    //   - PI change            ⇒ β, γ, α, ξ, v cascade; u stable
    //
    // Each property is a single inline `match` over a small selector
    // index — the alternative (a closure returning `&mut [u8]`) hits
    // borrow-check lifetime grief on `[u8; G1_LEN]` arrays, same
    // pattern documented in session 38's HyperPlonk vk_selector test.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    /// Build a proof buffer with a chosen non-trivial fill pattern that
    /// is reduced mod `r` per Fr slot — this matters because the
    /// challenge derivation calls `transcript.absorb_fr` on the proof's
    /// six eval slots, and that helper rejects out-of-range Fr.
    /// Using `0x11`-pattern bytes keeps every Fr slot inside the field.
    fn nontrivial_proof_buf() -> [u8; PROOF_LEN] {
        [0x11u8; PROOF_LEN]
    }

    /// Offsets for proof fields inside the canonical 768 B layout.
    const A_OFF: usize = 0;
    const B_OFF: usize = G1_LEN;
    const C_OFF: usize = 2 * G1_LEN;
    const Z_OFF: usize = 3 * G1_LEN;
    const T1_OFF: usize = 4 * G1_LEN;
    const T2_OFF: usize = 5 * G1_LEN;
    const T3_OFF: usize = 6 * G1_LEN;
    const W_XI_OFF: usize = 7 * G1_LEN;
    const W_XIW_OFF: usize = 8 * G1_LEN;
    const EVAL_A_OFF: usize = 9 * G1_LEN;
    // 5 more eval slots follow, each FR_LEN apart (see canonical layout).

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Determinism over random PI bytes (with high byte zeroed to
        /// stay in Fr range). Generalizes `derive_is_deterministic`.
        #[test]
        fn proptest_derive_is_deterministic(
            pi_bytes in proptest::collection::vec(any::<u8>(), FR_LEN..=FR_LEN),
        ) {
            let backend = MockBackend;
            let vk = zero_vk(1);
            let proof_bytes = nontrivial_proof_buf();
            let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
            let mut pi = [0u8; FR_LEN];
            pi.copy_from_slice(&pi_bytes);
            pi[0] = 0; // force high byte to 0 → guaranteed < r
            let c1 = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
            let c2 = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
            prop_assert_eq!(c1, c2);
        }

        /// All six challenges are in Fr range and pairwise distinct
        /// with overwhelming probability — pins both range invariant
        /// and non-degeneracy. Catches a future transcript bug that
        /// would emit duplicate challenges across rounds.
        #[test]
        fn proptest_all_challenges_in_range_and_distinct(
            pi_byte in any::<u8>(),
        ) {
            let backend = MockBackend;
            let vk = zero_vk(1);
            let proof_bytes = nontrivial_proof_buf();
            let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
            let mut pi = [0u8; FR_LEN];
            pi[FR_LEN - 1] = pi_byte;
            let c = RoundChallenges::derive(&backend, &vk, &proof, &pi).unwrap();
            for ch in [c.beta, c.gamma, c.alpha, c.xi, c.v, c.u] {
                prop_assert!(fr::lt_r(&ch));
            }
            let xs = [c.beta, c.gamma, c.alpha, c.xi, c.v, c.u];
            for i in 0..xs.len() {
                for j in (i + 1)..xs.len() {
                    prop_assert_ne!(xs[i], xs[j]);
                }
            }
        }

        /// ABC commit mutation: round-2a absorb. Cascades through
        /// rounds 2a→2b→3→4→5; round 6 (`u`) is unaffected because it
        /// absorbs only `W_xi` and `W_xiw`.
        #[test]
        fn proptest_abc_mutation_cascades_through_v_not_u(
            commit_select in 0u8..3, // 0 = A, 1 = B, 2 = C
            byte_idx in 0usize..G1_LEN,
            new_val in 1u8..=u8::MAX,
        ) {
            let backend = MockBackend;
            let vk = zero_vk(1);
            let pi = [0u8; FR_LEN];
            let mut buf_a = nontrivial_proof_buf();
            let mut buf_b = nontrivial_proof_buf();
            let off = (commit_select as usize) * G1_LEN + byte_idx;
            buf_a[off] = 0x55;
            buf_b[off] = new_val;
            prop_assume!(buf_a[off] != buf_b[off]);
            let p_a = PlonkProof::from_bytes(&buf_a).unwrap();
            let p_b = PlonkProof::from_bytes(&buf_b).unwrap();
            let ca = RoundChallenges::derive(&backend, &vk, &p_a, &pi).unwrap();
            let cb = RoundChallenges::derive(&backend, &vk, &p_b, &pi).unwrap();
            prop_assert_ne!(ca.beta, cb.beta);
            prop_assert_ne!(ca.gamma, cb.gamma);
            prop_assert_ne!(ca.alpha, cb.alpha);
            prop_assert_ne!(ca.xi, cb.xi);
            prop_assert_ne!(ca.v, cb.v);
            // u depends only on W_xi/W_xiw (round 6) which we did not
            // touch, so it stays equal across the mutation.
            prop_assert_eq!(ca.u, cb.u);
        }

        /// Z commit mutation: round-3 absorb. β, γ stable (squeezed
        /// in 2a/2b before Z appears); α, ξ, v cascade; u stable.
        #[test]
        fn proptest_z_mutation_alpha_xi_v_only(
            byte_idx in 0usize..G1_LEN,
            new_val in 1u8..=u8::MAX,
        ) {
            let backend = MockBackend;
            let vk = zero_vk(1);
            let pi = [0u8; FR_LEN];
            let mut buf_a = nontrivial_proof_buf();
            let mut buf_b = nontrivial_proof_buf();
            buf_a[Z_OFF + byte_idx] = 0x55;
            buf_b[Z_OFF + byte_idx] = new_val;
            prop_assume!(buf_a[Z_OFF + byte_idx] != buf_b[Z_OFF + byte_idx]);
            let p_a = PlonkProof::from_bytes(&buf_a).unwrap();
            let p_b = PlonkProof::from_bytes(&buf_b).unwrap();
            let ca = RoundChallenges::derive(&backend, &vk, &p_a, &pi).unwrap();
            let cb = RoundChallenges::derive(&backend, &vk, &p_b, &pi).unwrap();
            prop_assert_eq!(ca.beta, cb.beta);
            prop_assert_eq!(ca.gamma, cb.gamma);
            prop_assert_ne!(ca.alpha, cb.alpha);
            prop_assert_ne!(ca.xi, cb.xi);
            prop_assert_ne!(ca.v, cb.v);
            prop_assert_eq!(ca.u, cb.u);
        }

        /// Quotient T1/T2/T3 mutation: round-4 absorb. β, γ, α stable;
        /// ξ, v cascade; u stable.
        #[test]
        fn proptest_quotient_t_mutation_xi_v_only(
            t_select in 0u8..3, // 0 = T1, 1 = T2, 2 = T3
            byte_idx in 0usize..G1_LEN,
            new_val in 1u8..=u8::MAX,
        ) {
            let backend = MockBackend;
            let vk = zero_vk(1);
            let pi = [0u8; FR_LEN];
            let base = match t_select {
                0 => T1_OFF,
                1 => T2_OFF,
                _ => T3_OFF,
            };
            let off = base + byte_idx;
            let mut buf_a = nontrivial_proof_buf();
            let mut buf_b = nontrivial_proof_buf();
            buf_a[off] = 0x55;
            buf_b[off] = new_val;
            prop_assume!(buf_a[off] != buf_b[off]);
            let p_a = PlonkProof::from_bytes(&buf_a).unwrap();
            let p_b = PlonkProof::from_bytes(&buf_b).unwrap();
            let ca = RoundChallenges::derive(&backend, &vk, &p_a, &pi).unwrap();
            let cb = RoundChallenges::derive(&backend, &vk, &p_b, &pi).unwrap();
            prop_assert_eq!(ca.beta, cb.beta);
            prop_assert_eq!(ca.gamma, cb.gamma);
            prop_assert_eq!(ca.alpha, cb.alpha);
            prop_assert_ne!(ca.xi, cb.xi);
            prop_assert_ne!(ca.v, cb.v);
            prop_assert_eq!(ca.u, cb.u);
        }

        /// Evaluation slot mutation: round-5 absorb. Only v shifts;
        /// β, γ, α, ξ stable (squeezed before round 5); u stable.
        ///
        /// We restrict the chosen byte to slot positions that, when
        /// flipped, leave the resulting Fr in range — staying inside
        /// the lower 248 bits keeps the value < r. Specifically we only
        /// perturb the *last* byte of the chosen slot (offset
        /// `slot_off + FR_LEN - 1`), which keeps the BE Fr's high byte
        /// at 0x11 (the un-tampered nontrivial fill) and well below the
        /// modulus' high byte.
        #[test]
        fn proptest_eval_mutation_v_only(
            eval_select in 0u8..6,
            new_val in 1u8..=u8::MAX,
        ) {
            let backend = MockBackend;
            let vk = zero_vk(1);
            let pi = [0u8; FR_LEN];
            let slot_off = EVAL_A_OFF + (eval_select as usize) * FR_LEN;
            let off = slot_off + FR_LEN - 1; // low byte (BE) → safe in-range
            let mut buf_a = nontrivial_proof_buf();
            let mut buf_b = nontrivial_proof_buf();
            buf_a[off] = 0x55;
            buf_b[off] = new_val;
            prop_assume!(buf_a[off] != buf_b[off]);
            let p_a = PlonkProof::from_bytes(&buf_a).unwrap();
            let p_b = PlonkProof::from_bytes(&buf_b).unwrap();
            let ca = RoundChallenges::derive(&backend, &vk, &p_a, &pi).unwrap();
            let cb = RoundChallenges::derive(&backend, &vk, &p_b, &pi).unwrap();
            prop_assert_eq!(ca.beta, cb.beta);
            prop_assert_eq!(ca.gamma, cb.gamma);
            prop_assert_eq!(ca.alpha, cb.alpha);
            prop_assert_eq!(ca.xi, cb.xi);
            prop_assert_ne!(ca.v, cb.v);
            prop_assert_eq!(ca.u, cb.u);
        }

        /// Opening witness mutation (`W_xi` or `W_xiw`): round-6
        /// absorb, the only round that produces u. Only u shifts;
        /// every other challenge is stable. This is the audit-grade
        /// pin on the snarkjs-compatibility bit "u does NOT absorb v".
        #[test]
        fn proptest_opening_witness_mutation_u_only(
            witness_select in 0u8..2, // 0 = W_xi, 1 = W_xiw
            byte_idx in 0usize..G1_LEN,
            new_val in 1u8..=u8::MAX,
        ) {
            let backend = MockBackend;
            let vk = zero_vk(1);
            let pi = [0u8; FR_LEN];
            let base = if witness_select == 0 { W_XI_OFF } else { W_XIW_OFF };
            let off = base + byte_idx;
            let mut buf_a = nontrivial_proof_buf();
            let mut buf_b = nontrivial_proof_buf();
            buf_a[off] = 0x55;
            buf_b[off] = new_val;
            prop_assume!(buf_a[off] != buf_b[off]);
            let p_a = PlonkProof::from_bytes(&buf_a).unwrap();
            let p_b = PlonkProof::from_bytes(&buf_b).unwrap();
            let ca = RoundChallenges::derive(&backend, &vk, &p_a, &pi).unwrap();
            let cb = RoundChallenges::derive(&backend, &vk, &p_b, &pi).unwrap();
            prop_assert_eq!(ca.beta, cb.beta);
            prop_assert_eq!(ca.gamma, cb.gamma);
            prop_assert_eq!(ca.alpha, cb.alpha);
            prop_assert_eq!(ca.xi, cb.xi);
            prop_assert_eq!(ca.v, cb.v);
            prop_assert_ne!(ca.u, cb.u);
        }

        /// Public input change: round-2a absorb. β, γ, α, ξ, v cascade;
        /// u stable (round 6 doesn't see PI).
        #[test]
        fn proptest_public_input_change_cascades(
            pi_a_byte in any::<u8>(),
            delta in 1u8..=u8::MAX,
        ) {
            let backend = MockBackend;
            let vk = zero_vk(1);
            let proof_bytes = nontrivial_proof_buf();
            let proof = PlonkProof::from_bytes(&proof_bytes).unwrap();
            let mut pi_a = [0u8; FR_LEN];
            pi_a[FR_LEN - 1] = pi_a_byte;
            let mut pi_b = [0u8; FR_LEN];
            pi_b[FR_LEN - 1] = pi_a_byte.wrapping_add(delta);
            prop_assume!(pi_a[FR_LEN - 1] != pi_b[FR_LEN - 1]);
            let ca = RoundChallenges::derive(&backend, &vk, &proof, &pi_a).unwrap();
            let cb = RoundChallenges::derive(&backend, &vk, &proof, &pi_b).unwrap();
            prop_assert_ne!(ca.beta, cb.beta);
            prop_assert_ne!(ca.gamma, cb.gamma);
            prop_assert_ne!(ca.alpha, cb.alpha);
            prop_assert_ne!(ca.xi, cb.xi);
            prop_assert_ne!(ca.v, cb.v);
            prop_assert_eq!(ca.u, cb.u);
        }
    }
}
