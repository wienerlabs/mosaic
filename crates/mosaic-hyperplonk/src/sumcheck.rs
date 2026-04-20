//! Sumcheck protocol verifier.
//!
//! The sumcheck protocol reduces a claim of the form
//!
//! ```text
//! Σ_{x ∈ {0,1}^n} f(x) == C_0
//! ```
//!
//! to a single polynomial-evaluation claim at a random point
//! `(ξ_0, ..., ξ_{n-1}) ∈ F^n`. This is HyperPlonk's core workhorse:
//! the zero-check over the combined gate + permutation polynomial
//! becomes `n = log₂(domain)` sumcheck rounds.
//!
//! ## Round protocol
//!
//! For each round `r ∈ 0..n`:
//!
//! 1. Prover sends round polynomial `p_r(X)` (degree `d` in `X`). For
//!    the HyperPlonk zero-check variant, `d = 2` (one factor each of
//!    degree 1 from the gate and permutation terms).
//! 2. Verifier checks `p_r(0) + p_r(1) == C_r` where `C_r` is the
//!    running claim.
//! 3. Verifier squeezes challenge `ξ_r` from the transcript after
//!    absorbing `p_r`.
//! 4. Updates the claim: `C_{r+1} := p_r(ξ_r)`.
//!
//! After `n` rounds, `C_n` is the claimed value of the multilinear
//! extension at `(ξ_0, ..., ξ_{n-1})`. The outer verifier closes the
//! proof by checking `C_n` against a direct MLE evaluation using the
//! committed polynomial openings.
//!
//! ## Wire format
//!
//! Each round polynomial is encoded as three 32-byte BE Fr elements
//! `c_0 ‖ c_1 ‖ c_2` representing `p(X) = c_0 + c_1·X + c_2·X²`.
//! This matches the scaffold's [`crate::canonical::sizes::SUMCHECK_POLY_LEN`]
//! = 96 bytes.
//!
//! ## Why a separate module
//!
//! Sumcheck is a reusable primitive. HyperPlonk uses it; Spartan,
//! Jellyfish PLONK, and Halo2-with-IPA all use variants of the same
//! protocol. Keeping sumcheck isolated from the outer verifier means
//! we can test soundness independently and eventually move it into
//! `mosaic-zk-primitives` as part of the shared primitive crate.

use crate::canonical::sizes::{FR_LEN, SUMCHECK_POLY_LEN};
use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use mosaic_core::{syscall::SyscallBackend, OnChainError};
use mosaic_plonk::{
    field::{fr_from_canonical_bytes, fr_to_canonical_bytes},
    transcript::Transcript,
};

/// Degree-2 univariate round polynomial `p(X) = c_0 + c_1·X + c_2·X²`.
///
/// HyperPlonk's zero-check sumcheck sends degree-2 polynomials per
/// round because the combined gate + permutation polynomial is
/// degree 2 in the sumcheck variable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RoundPolynomial {
    /// Coefficients [c_0, c_1, c_2].
    pub coeffs: [Fr; 3],
}

impl RoundPolynomial {
    /// Parse a 96-byte round polynomial (three big-endian Fr values).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() != SUMCHECK_POLY_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let c0 = fr_from_canonical_bytes(&bytes[0..FR_LEN])?;
        let c1 = fr_from_canonical_bytes(&bytes[FR_LEN..2 * FR_LEN])?;
        let c2 = fr_from_canonical_bytes(&bytes[2 * FR_LEN..3 * FR_LEN])?;
        Ok(Self { coeffs: [c0, c1, c2] })
    }

    /// Evaluate `p(0) = c_0`.
    #[must_use]
    pub fn eval_at_zero(&self) -> Fr {
        self.coeffs[0]
    }

    /// Evaluate `p(1) = c_0 + c_1 + c_2`.
    #[must_use]
    pub fn eval_at_one(&self) -> Fr {
        self.coeffs[0] + self.coeffs[1] + self.coeffs[2]
    }

    /// Sum of evaluations at the boolean hypercube endpoints:
    /// `p(0) + p(1) = 2c_0 + c_1 + c_2`.
    ///
    /// This is the value the sumcheck identity requires each round:
    /// `p_r(0) + p_r(1) == C_r` (previous claim).
    #[must_use]
    pub fn evals_sum_on_boolean_cube(&self) -> Fr {
        self.eval_at_zero() + self.eval_at_one()
    }

    /// Evaluate `p(x) = c_0 + c_1·x + c_2·x²` at an arbitrary point
    /// using Horner's rule: `((c_2 · x) + c_1) · x + c_0`.
    #[must_use]
    pub fn eval_at(&self, x: &Fr) -> Fr {
        let mut acc = self.coeffs[2];
        acc *= x;
        acc += self.coeffs[1];
        acc *= x;
        acc += self.coeffs[0];
        acc
    }
}

/// Outcome of a successful sumcheck verification.
#[derive(Clone, Debug)]
pub struct SumcheckOutput {
    /// Final claim after `n` rounds — what the prover alleges the MLE
    /// evaluates to at `(ξ_0, ..., ξ_{n-1})`. The outer verifier closes
    /// the proof by cross-checking this against committed-polynomial
    /// openings at the challenge point.
    pub final_claim: Fr,
    /// The `n` sumcheck challenges, one per round. These form the
    /// evaluation point in the boolean hypercube's multilinear-
    /// extension domain.
    pub challenges: Vec<Fr>,
}

/// Verify a sumcheck-protocol transcript.
///
/// `round_polys_bytes` concatenates `num_rounds` round polynomials,
/// each of size [`SUMCHECK_POLY_LEN`] (96 B). The transcript must
/// already be seeded with whatever commitments / public inputs the
/// outer verifier absorbed before sumcheck begins — this function
/// only absorbs round polynomials and squeezes per-round challenges.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] — round-poly buffer length
///   doesn't match `num_rounds × SUMCHECK_POLY_LEN`, or an individual
///   Fr is malformed.
/// - [`OnChainError::SumcheckFailed`] — a round's `p_r(0) + p_r(1)`
///   did not equal the running claim.
/// - [`OnChainError::Keccak256SyscallFailed`] / similar — transcript
///   backend errors.
pub fn verify_sumcheck<B: SyscallBackend + ?Sized>(
    transcript: &mut Transcript<'_, B>,
    initial_claim: &Fr,
    round_polys_bytes: &[u8],
    num_rounds: u32,
) -> Result<SumcheckOutput, OnChainError> {
    let num_rounds_usize = num_rounds as usize;
    let expected_len = num_rounds_usize
        .checked_mul(SUMCHECK_POLY_LEN)
        .ok_or(OnChainError::ProofLengthMismatch)?;
    if round_polys_bytes.len() != expected_len {
        return Err(OnChainError::ProofLengthMismatch);
    }

    let mut current_claim = *initial_claim;
    let mut challenges: Vec<Fr> = Vec::with_capacity(num_rounds_usize);

    for r in 0..num_rounds_usize {
        let start = r * SUMCHECK_POLY_LEN;
        let end = start + SUMCHECK_POLY_LEN;
        let bytes = &round_polys_bytes[start..end];

        let p = RoundPolynomial::from_bytes(bytes)?;

        // Round identity: p_r(0) + p_r(1) == current claim.
        if p.evals_sum_on_boolean_cube() != current_claim {
            return Err(OnChainError::SumcheckFailed);
        }

        // Absorb the round polynomial bytes and squeeze the next
        // challenge. Absorbing the raw bytes (not reserialized
        // coefficients) keeps the transcript byte-stable vs the
        // prover's transcript.
        transcript.absorb(bytes);
        let xi_bytes = transcript.get_challenge()?;
        let xi = fr_from_canonical_bytes(&xi_bytes)?;

        // New claim: p_r(ξ_r).
        current_claim = p.eval_at(&xi);
        challenges.push(xi);
    }

    Ok(SumcheckOutput {
        final_claim: current_claim,
        challenges,
    })
}

/// Encode a degree-2 round polynomial back to canonical bytes.
/// Primarily useful for test fixture construction where we compute
/// round polys arithmetically then encode for the verifier input.
#[must_use]
pub fn encode_round_polynomial(p: &RoundPolynomial) -> [u8; SUMCHECK_POLY_LEN] {
    let mut out = [0u8; SUMCHECK_POLY_LEN];
    let c0_bytes = fr_to_canonical_bytes(&p.coeffs[0]);
    let c1_bytes = fr_to_canonical_bytes(&p.coeffs[1]);
    let c2_bytes = fr_to_canonical_bytes(&p.coeffs[2]);
    out[0..FR_LEN].copy_from_slice(&c0_bytes);
    out[FR_LEN..2 * FR_LEN].copy_from_slice(&c1_bytes);
    out[2 * FR_LEN..3 * FR_LEN].copy_from_slice(&c2_bytes);
    out
}

/// Zero-polynomial helper — encodes `p(X) = 0 + 0·X + 0·X² = 0` to
/// canonical bytes. Useful for transcripts where a round contributes
/// nothing (e.g. the trivial sumcheck on a zero polynomial).
#[must_use]
pub const fn zero_round_polynomial_bytes() -> [u8; SUMCHECK_POLY_LEN] {
    [0u8; SUMCHECK_POLY_LEN]
}

/// Construct the `Fr::zero()` claim — useful as the initial claim for
/// zero-check sumchecks (HyperPlonk's gate constraint combined with
/// permutation argument should sum to zero on the boolean cube).
#[must_use]
pub fn zero_claim() -> Fr {
    Fr::zero()
}

/// Construct `Fr::one()`.
#[must_use]
pub fn one_claim() -> Fr {
    Fr::one()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, UniformRand};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_plonk::transcript::Kind;

    fn seeded_rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    fn mk_transcript(backend: &HostBackend) -> Transcript<'_, HostBackend> {
        Transcript::new(Kind::Keccak256, backend)
    }

    // ---- RoundPolynomial unit tests ----

    #[test]
    fn round_poly_from_bytes_roundtrip() {
        let mut rng = seeded_rng(1);
        let c0 = Fr::rand(&mut rng);
        let c1 = Fr::rand(&mut rng);
        let c2 = Fr::rand(&mut rng);
        let original = RoundPolynomial { coeffs: [c0, c1, c2] };
        let bytes = encode_round_polynomial(&original);
        let decoded = RoundPolynomial::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_poly_rejects_wrong_length() {
        let short = [0u8; SUMCHECK_POLY_LEN - 1];
        assert!(matches!(
            RoundPolynomial::from_bytes(&short),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn round_poly_eval_matches_arkworks() {
        // p(X) = 7 + 3X + 5X^2
        let p = RoundPolynomial {
            coeffs: [Fr::from(7u64), Fr::from(3u64), Fr::from(5u64)],
        };
        assert_eq!(p.eval_at_zero(), Fr::from(7u64));
        // p(1) = 7 + 3 + 5 = 15
        assert_eq!(p.eval_at_one(), Fr::from(15u64));
        // p(0) + p(1) = 7 + 15 = 22
        assert_eq!(p.evals_sum_on_boolean_cube(), Fr::from(22u64));
        // p(2) = 7 + 6 + 20 = 33
        assert_eq!(p.eval_at(&Fr::from(2u64)), Fr::from(33u64));
        // p(10) = 7 + 30 + 500 = 537
        assert_eq!(p.eval_at(&Fr::from(10u64)), Fr::from(537u64));
    }

    #[test]
    fn round_poly_eval_at_uses_horner_correctly() {
        let mut rng = seeded_rng(2);
        for _ in 0..5 {
            let c0 = Fr::rand(&mut rng);
            let c1 = Fr::rand(&mut rng);
            let c2 = Fr::rand(&mut rng);
            let x = Fr::rand(&mut rng);
            let p = RoundPolynomial { coeffs: [c0, c1, c2] };
            // Reference: c0 + c1*x + c2*x^2
            let expected = c0 + c1 * x + c2 * x * x;
            assert_eq!(p.eval_at(&x), expected);
        }
    }

    // ---- verify_sumcheck happy-path tests ----

    /// Construct a honest sumcheck transcript.
    ///
    /// Given target initial claim `C_0`, for each round we emit a
    /// round polynomial whose `p(0) + p(1) = C_r` and whose evaluation
    /// at the squeezed challenge `ξ_r` becomes the next claim.
    ///
    /// Because the verifier's challenge depends on absorb history,
    /// we have to build the transcript interactively: emit round r's
    /// polynomial choosing arbitrary shape that sums to C_r on the
    /// cube, then read back what the verifier would squeeze and use
    /// that to derive the next claim.
    ///
    /// Shape picked: `p_r(X) = (C_r / 2) + 0·X + 0·X²` — a constant
    /// polynomial (degree 0) trivially satisfies `p(0) + p(1) = C_r`
    /// when `c_0 = C_r / 2`.
    fn build_honest_sumcheck(
        backend: &HostBackend,
        initial_claim: Fr,
        num_rounds: usize,
    ) -> (alloc::vec::Vec<u8>, Fr, alloc::vec::Vec<Fr>) {
        let two_inv = Fr::from(2u64).inverse().unwrap();
        let mut polys_bytes = alloc::vec::Vec::with_capacity(num_rounds * SUMCHECK_POLY_LEN);
        let mut transcript = mk_transcript(backend);
        let mut current = initial_claim;
        let mut challenges = alloc::vec::Vec::with_capacity(num_rounds);

        for _ in 0..num_rounds {
            // Constant polynomial: c_0 = current / 2, so p(0)+p(1) = current.
            let p = RoundPolynomial {
                coeffs: [current * two_inv, Fr::zero(), Fr::zero()],
            };
            let p_bytes = encode_round_polynomial(&p);
            polys_bytes.extend_from_slice(&p_bytes);

            // Replay what the verifier would do: absorb these bytes, squeeze.
            transcript.absorb(&p_bytes);
            let xi_bytes = transcript.get_challenge().unwrap();
            let xi = fr_from_canonical_bytes(&xi_bytes).unwrap();

            // Next claim: for a constant polynomial, p(ξ) = c_0 = current/2.
            // So the next claim is current/2.
            current = p.eval_at(&xi);
            challenges.push(xi);
        }
        (polys_bytes, current, challenges)
    }

    #[test]
    fn verify_sumcheck_accepts_honest_transcript() {
        let backend = HostBackend::new();
        let initial_claim = Fr::from(42u64);
        let (polys, expected_final, expected_challenges) =
            build_honest_sumcheck(&backend, initial_claim, 10);

        let mut transcript = mk_transcript(&backend);
        let out = verify_sumcheck(&mut transcript, &initial_claim, &polys, 10).unwrap();
        assert_eq!(out.final_claim, expected_final);
        assert_eq!(out.challenges.len(), 10);
        assert_eq!(out.challenges, expected_challenges);
    }

    #[test]
    fn verify_sumcheck_accepts_zero_claim_with_zero_polys() {
        // Trivial sumcheck: initial claim zero, all round polys zero.
        let backend = HostBackend::new();
        let mut polys = alloc::vec::Vec::with_capacity(5 * SUMCHECK_POLY_LEN);
        for _ in 0..5 {
            polys.extend_from_slice(&zero_round_polynomial_bytes());
        }
        let mut transcript = mk_transcript(&backend);
        let out =
            verify_sumcheck(&mut transcript, &zero_claim(), &polys, 5).unwrap();
        assert_eq!(out.final_claim, Fr::zero());
        assert_eq!(out.challenges.len(), 5);
    }

    #[test]
    fn verify_sumcheck_accepts_zero_rounds() {
        let backend = HostBackend::new();
        let mut transcript = mk_transcript(&backend);
        let claim = Fr::from(123u64);
        let out = verify_sumcheck(&mut transcript, &claim, &[], 0).unwrap();
        assert_eq!(out.final_claim, claim);
        assert!(out.challenges.is_empty());
    }

    // ---- verify_sumcheck rejection tests ----

    #[test]
    fn verify_sumcheck_rejects_tampered_first_round() {
        let backend = HostBackend::new();
        let initial_claim = Fr::from(100u64);
        let (mut polys, _, _) = build_honest_sumcheck(&backend, initial_claim, 3);
        // Flip one byte in the first round polynomial.
        polys[5] ^= 0xFF;
        let mut transcript = mk_transcript(&backend);
        let r = verify_sumcheck(&mut transcript, &initial_claim, &polys, 3);
        assert!(
            matches!(r, Err(OnChainError::SumcheckFailed))
                || matches!(r, Err(OnChainError::PublicInputOutOfRange)),
            "expected sumcheck failure or Fr range error, got {r:?}",
        );
    }

    #[test]
    fn verify_sumcheck_rejects_tampered_middle_round() {
        let backend = HostBackend::new();
        let initial_claim = Fr::from(100u64);
        let (mut polys, _, _) = build_honest_sumcheck(&backend, initial_claim, 5);
        // Tamper with round 2's polynomial (offset 2 * SUMCHECK_POLY_LEN).
        let tamper_offset = 2 * SUMCHECK_POLY_LEN + 5;
        polys[tamper_offset] ^= 0xAA;
        let mut transcript = mk_transcript(&backend);
        let r = verify_sumcheck(&mut transcript, &initial_claim, &polys, 5);
        assert!(
            matches!(r, Err(OnChainError::SumcheckFailed))
                || matches!(r, Err(OnChainError::PublicInputOutOfRange)),
        );
    }

    #[test]
    fn verify_sumcheck_rejects_wrong_initial_claim() {
        let backend = HostBackend::new();
        let (polys, _, _) = build_honest_sumcheck(&backend, Fr::from(42u64), 4);
        let mut transcript = mk_transcript(&backend);
        // Pass a different initial claim than the one the prover built for.
        let wrong_claim = Fr::from(43u64);
        let r = verify_sumcheck(&mut transcript, &wrong_claim, &polys, 4);
        assert!(matches!(r, Err(OnChainError::SumcheckFailed)));
    }

    #[test]
    fn verify_sumcheck_rejects_poly_buffer_wrong_length() {
        let backend = HostBackend::new();
        let mut transcript = mk_transcript(&backend);
        // Claim 3 rounds but only 2 polynomials in the buffer.
        let short_polys = alloc::vec![0u8; 2 * SUMCHECK_POLY_LEN];
        let r = verify_sumcheck(&mut transcript, &Fr::zero(), &short_polys, 3);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn verify_sumcheck_rejects_trailing_bytes_in_poly_buffer() {
        let backend = HostBackend::new();
        let mut transcript = mk_transcript(&backend);
        // 2 rounds worth of bytes + 1 extra byte.
        let mut polys = alloc::vec![0u8; 2 * SUMCHECK_POLY_LEN];
        polys.push(0xFF);
        let r = verify_sumcheck(&mut transcript, &Fr::zero(), &polys, 2);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    /// Non-constant honest transcript: build degree-2 round polys
    /// whose `p(0) + p(1)` matches the running claim, then verify.
    #[test]
    fn verify_sumcheck_accepts_nonconstant_honest_transcript() {
        let backend = HostBackend::new();
        let initial_claim = Fr::from(200u64);
        let mut rng = seeded_rng(7);

        // Interactive construction: for each round, pick random c_1, c_2,
        // then solve c_0 = (current_claim - c_1 - c_2) / 2 to satisfy the
        // identity p(0) + p(1) = 2c_0 + c_1 + c_2 == current_claim.
        let num_rounds = 6;
        let two_inv = Fr::from(2u64).inverse().unwrap();
        let mut polys = alloc::vec::Vec::with_capacity(num_rounds * SUMCHECK_POLY_LEN);
        let mut transcript_prover = mk_transcript(&backend);
        let mut current = initial_claim;

        for _ in 0..num_rounds {
            let c1 = Fr::rand(&mut rng);
            let c2 = Fr::rand(&mut rng);
            let c0 = (current - c1 - c2) * two_inv;
            let p = RoundPolynomial { coeffs: [c0, c1, c2] };
            // Sanity: p(0) + p(1) should equal current.
            debug_assert_eq!(p.evals_sum_on_boolean_cube(), current);

            let p_bytes = encode_round_polynomial(&p);
            polys.extend_from_slice(&p_bytes);

            transcript_prover.absorb(&p_bytes);
            let xi_bytes = transcript_prover.get_challenge().unwrap();
            let xi = fr_from_canonical_bytes(&xi_bytes).unwrap();
            current = p.eval_at(&xi);
        }

        let expected_final = current;

        // Now verify against a fresh transcript.
        let mut transcript_v = mk_transcript(&backend);
        let out =
            verify_sumcheck(&mut transcript_v, &initial_claim, &polys, num_rounds as u32).unwrap();
        assert_eq!(out.final_claim, expected_final);
        assert_eq!(out.challenges.len(), num_rounds);
    }

    /// Soundness witness: verify that if a malicious prover claims
    /// initial_claim = X but actually sums to Y (X ≠ Y), the first
    /// round identity check must catch the discrepancy.
    #[test]
    fn verify_sumcheck_catches_claim_mismatch_in_round_zero() {
        let backend = HostBackend::new();
        // Build polys that honestly sum to 100.
        let (polys, _, _) = build_honest_sumcheck(&backend, Fr::from(100u64), 5);
        // But verifier is told the initial claim is 200 — must fail
        // at round 0's identity (2*c_0 == 100 ≠ 200).
        let mut transcript = mk_transcript(&backend);
        let r = verify_sumcheck(&mut transcript, &Fr::from(200u64), &polys, 5);
        assert!(matches!(r, Err(OnChainError::SumcheckFailed)));
    }
}
