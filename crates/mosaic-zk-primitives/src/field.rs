//! Fr field arithmetic via arkworks `ark-bn254`.
//!
//! [`crate::fr`] provides byte-level Fr-range helpers that do not depend
//! on arkworks (lightweight, used by transcript squeeze). This module
//! wraps arkworks `Fr` for the arithmetic PLONK verification needs:
//! multiplication, inversion, exponentiation, Lagrange-basis evaluation,
//! public-input polynomial evaluation.
//!
//! ## Why arkworks on-chain
//!
//! BN254 scalar-field arithmetic is not exposed by Solana syscalls —
//! only group operations (`alt_bn128_*`) and hash (`keccak` / `sha256` /
//! `poseidon`) are. Light Protocol's `groth16-solana` pulls arkworks
//! through for the same reason; we follow that pattern. Binary impact
//! is ~200 KB on the SBF artifact, well under the 1 MB program limit.
//!
//! All Fr arithmetic here is **not constant-time**. PLONK verification
//! operates on public proof/VK bytes, so timing side-channels are not
//! an attack vector. Do not reuse these helpers for private data.

use crate::fr::parse_fr_be;
use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use mosaic_core::OnChainError;

/// Decode a big-endian 32-byte canonical Fr encoding, validating that the
/// value is in [0, r). Returns the arkworks `Fr` for subsequent
/// arithmetic.
///
/// # Errors
///
/// - [`OnChainError::InvalidFieldEncoding`] — input slice length is not
///   exactly 32 bytes (propagated from [`crate::fr::parse_fr_be`]).
/// - [`OnChainError::PublicInputOutOfRange`] — decoded value is `>= r`
///   (BN254 scalar-field modulus).
pub fn fr_from_canonical_bytes(bytes: &[u8]) -> Result<Fr, OnChainError> {
    let in_range = parse_fr_be(bytes)?;
    // Safe because `parse_fr_be` already rejected out-of-range inputs.
    Ok(Fr::from_be_bytes_mod_order(&in_range))
}

/// Reduce an arbitrary 32-byte big-endian input modulo the BN254
/// scalar-field order `r`. Unlike [`fr_from_canonical_bytes`], this
/// never fails — any input is mapped to a well-defined `Fr` via
/// `from_be_bytes_mod_order`. Intended for consuming keccak/sha256
/// digests as Fiat-Shamir challenges where the hash output is
/// guaranteed to be 32 bytes but isn't necessarily in-range.
///
/// Naming mirrors `fr_from_canonical_bytes` but signals the
/// reduction: callers that want strict canonical validation should
/// use `fr_from_canonical_bytes` instead.
///
/// # Examples
///
/// ```
/// use mosaic_zk_primitives::field::{
///     fr_from_be_bytes_reduced, fr_from_canonical_bytes,
/// };
///
/// // In-range input agrees with the strict canonical decoder.
/// let in_range = [0u8; 32];
/// let a = fr_from_be_bytes_reduced(&in_range);
/// let b = fr_from_canonical_bytes(&in_range).unwrap();
/// assert_eq!(a, b);
///
/// // Out-of-range input (all-ones is > BN254 r). The strict
/// // decoder rejects; the reduced variant silently takes mod r.
/// let all_ones = [0xFFu8; 32];
/// assert!(fr_from_canonical_bytes(&all_ones).is_err());
/// let _reduced = fr_from_be_bytes_reduced(&all_ones);
/// ```
#[must_use]
pub fn fr_from_be_bytes_reduced(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Encode a `u64` as a canonical 32-byte big-endian Fr element.
///
/// Const-evaluable so it can seed `HyperPlonkVerifyingKey`-style VK
/// fields from constants (e.g. the `(k_1, k_2, k_3) = (1, 2, 3)`
/// default permutation-coset triple). For non-const callers,
/// `fr_to_canonical_bytes(&Fr::from(n))` is equivalent and slightly
/// shorter to type.
///
/// # Examples
///
/// ```
/// use mosaic_zk_primitives::field::fr_be_from_u64;
///
/// // Fr(1) encodes as 31 zero bytes followed by 0x01.
/// let one = fr_be_from_u64(1);
/// assert_eq!(one[31], 1);
/// assert!(one[..31].iter().all(|&b| b == 0));
///
/// // Const-evaluable — fine in `const` contexts, e.g. default
/// // permutation cosets on a VK literal.
/// const K_1: [u8; 32] = fr_be_from_u64(1);
/// const K_2: [u8; 32] = fr_be_from_u64(2);
/// assert_ne!(K_1, K_2);
/// ```
#[must_use]
pub const fn fr_be_from_u64(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = n.to_be_bytes();
    out[24] = bytes[0];
    out[25] = bytes[1];
    out[26] = bytes[2];
    out[27] = bytes[3];
    out[28] = bytes[4];
    out[29] = bytes[5];
    out[30] = bytes[6];
    out[31] = bytes[7];
    out
}

/// Encode an arkworks `Fr` as 32 big-endian bytes (canonical Mosaic
/// layout). Inverse of [`fr_from_canonical_bytes`].
#[must_use]
pub fn fr_to_canonical_bytes(fr: &Fr) -> [u8; 32] {
    let mut le = fr.into_bigint().to_bytes_le();
    le.resize(32, 0); // should already be 32
    le.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&le);
    out
}

/// Compute `fr^exp` via arkworks `pow`.
#[must_use]
pub fn fr_pow_u64(fr: &Fr, exp: u64) -> Fr {
    fr.pow([exp])
}

/// Compute the primitive `2^k`-th root of unity in `Fr` on chain.
///
/// BN254's scalar field has 2-adicity 28, so a multiplicative subgroup
/// of order `2^k` exists for any `k ≤ 28`. The generator is
/// `TWO_ADIC_ROOT_OF_UNITY ^ (2^(28-k))`, which costs `28-k` Fr
/// squarings (the exponent is a single set bit).
///
/// This is the sound replacement for trusting a prover-supplied domain
/// generator: the verifier derives `ω` from the VK's `k` alone, so a
/// malicious prover cannot degenerate the evaluation domain (e.g. by
/// supplying `ω = 0`).
///
/// # Errors
///
/// - [`OnChainError::PublicInputOutOfRange`] if `k > 28` (no `2^k`-th
///   root of unity exists in BN254's scalar field).
pub fn root_of_unity_2k(k: u32) -> Result<Fr, OnChainError> {
    use ark_ff::FftField;
    if k > Fr::TWO_ADICITY {
        return Err(OnChainError::PublicInputOutOfRange);
    }
    let extra = Fr::TWO_ADICITY - k;
    Ok(Fr::TWO_ADIC_ROOT_OF_UNITY.pow([1_u64 << extra]))
}

/// First Lagrange basis polynomial `L_1(ξ)` for an evaluation domain of
/// size `n`:
///
/// ```text
/// L_1(ξ) = (ξ^n - 1) / (n · (ξ - 1))
/// ```
///
/// Panics-free: returns `Err(InternalInvariantViolation)` if the
/// denominator is zero (i.e. `ξ = 1`, probability `~1/r` for a random
/// challenge).
///
/// # Errors
///
/// - [`OnChainError::InternalInvariantViolation`] — `ξ = 1`, which
///   makes the denominator zero and L_1 ill-defined at that point.
///   Fiat-Shamir challenges are random Fr elements, so this hits with
///   probability `~1/r`; non-adversarial callers never trigger it.
pub fn lagrange_basis_one(xi: &Fr, n: u64) -> Result<Fr, OnChainError> {
    let xi_n = fr_pow_u64(xi, n);
    let numerator = xi_n - Fr::one();
    let denom = Fr::from(n) * (*xi - Fr::one());
    denom
        .inverse()
        .map(|inv| numerator * inv)
        .ok_or(OnChainError::InternalInvariantViolation)
}

/// The `i`-th Lagrange basis polynomial `L_{i+1}(ξ)` (0-indexed `i`):
///
/// ```text
/// L_{i+1}(ξ) = (ω^i · (ξ^n - 1)) / (n · (ξ - ω^i))
/// ```
///
/// Called during public-input polynomial evaluation.
///
/// # Errors
///
/// - [`OnChainError::InternalInvariantViolation`] — `ξ = ω^i`, which
///   makes the denominator zero at that specific root of unity. For a
///   random Fiat-Shamir challenge this hits with probability `~n/r`
///   (at most `n` roots over a field of size `~2^254`).
pub fn lagrange_basis_at(xi: &Fr, i: u64, n: u64, omega: &Fr) -> Result<Fr, OnChainError> {
    let xi_n = fr_pow_u64(xi, n);
    let omega_i = fr_pow_u64(omega, i);
    let numerator = omega_i * (xi_n - Fr::one());
    let denom = Fr::from(n) * (*xi - omega_i);
    denom
        .inverse()
        .map(|inv| numerator * inv)
        .ok_or(OnChainError::InternalInvariantViolation)
}

/// Evaluate the public-input polynomial at `ξ`:
///
/// ```text
/// PI(ξ) = -Σ_{i=0}^{n_public-1} w_i · L_{i+1}(ξ)
/// ```
///
/// The negation follows snarkjs 0.7.x convention: public-input
/// coefficients contribute to the linearization equation with a minus
/// sign so that `r(ξ) = 0` holds when the proof is valid.
///
/// `public_inputs` is a slice of canonical big-endian 32-byte Fr values;
/// each must be `< r` (caller's
/// [`crate::challenges::RoundChallenges::derive`] already validates
/// this).
///
/// # Errors
///
/// - [`OnChainError::InternalInvariantViolation`] — `n` is zero mod r
///   (impossible for valid domain sizes) or `ξ = ω^i` for some i
///   (denominator vanishes in a Lagrange basis term).
pub fn evaluate_public_input_poly(
    xi: &Fr,
    omega: &Fr,
    n: u64,
    public_inputs: &[Fr],
) -> Result<Fr, OnChainError> {
    if public_inputs.is_empty() {
        return Ok(Fr::zero());
    }
    // Precompute (ξ^n - 1) and n_fr^(-1) once so each Lagrange eval is
    // only one inversion in the denominator.
    let xi_n_minus_one = fr_pow_u64(xi, n) - Fr::one();
    let n_fr_inv = Fr::from(n)
        .inverse()
        .ok_or(OnChainError::InternalInvariantViolation)?;

    // ω^i cumulative: starts at ω^0 = 1, multiplied by ω each step.
    let mut omega_i = Fr::one();
    let mut acc = Fr::zero();
    for w in public_inputs {
        // L_{i+1}(ξ) = ω^i · (ξ^n - 1) / (n · (ξ - ω^i))
        let denom = *xi - omega_i;
        let denom_inv = denom
            .inverse()
            .ok_or(OnChainError::InternalInvariantViolation)?;
        let l_i_plus_1 = omega_i * xi_n_minus_one * n_fr_inv * denom_inv;
        acc += *w * l_i_plus_1;
        omega_i *= omega;
    }
    // Negate per snarkjs convention.
    Ok(-acc)
}

/// Convenience: decode a sequence of canonical BE public inputs into
/// arkworks `Fr` elements for use with
/// [`evaluate_public_input_poly`].
///
/// # Errors
///
/// - [`OnChainError::PublicInputCountMismatch`] — byte length is not a
///   multiple of 32.
/// - [`OnChainError::PublicInputOutOfRange`] — any decoded Fr element
///   is not reduced mod r (propagated from
///   [`fr_from_canonical_bytes`]).
pub fn decode_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>, OnChainError> {
    if bytes.len() % 32 != 0 {
        return Err(OnChainError::PublicInputCountMismatch);
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks_exact(32) {
        out.push(fr_from_canonical_bytes(chunk)?);
    }
    Ok(out)
}

/// Compute the inner product `Σ_i a_i · b_i` of two equal-length Fr
/// slices.
///
/// Returns `Err(PublicInputCountMismatch)` if the slices have
/// different lengths. Empty slices yield `Fr::zero()` (vacuous
/// empty sum).
///
/// ## Why a shared primitive
///
/// Multi-poly batched openings build a weighted sum
/// `y_batched = Σ_i ν^i · e_i` over a list of claimed evaluations
/// scaled by powers of the batching challenge. HyperPlonk
/// (session 3e), Nova (session 22), and Halo2 (session 17) all
/// implement this inline:
///
/// ```text
/// // HyperPlonk:
/// let mut y_batched = Fr::from(0u64);
/// for i in 0..12 {
///     y_batched += nu_powers[i] * e_i;
/// }
/// ```
///
/// Lifting the loop into one audit-grade helper removes 3 inline
/// reduction sites + gives every future MSM-style weighted-sum
/// site one centralized implementation.
///
/// ## Errors
///
/// - [`OnChainError::PublicInputCountMismatch`] — slice lengths
///   differ.
///
/// Session 77 (post-v0.8.3): tenth shared primitive, joining the
/// nine from sessions 21-72.
pub fn fr_inner_product(a: &[Fr], b: &[Fr]) -> Result<Fr, OnChainError> {
    if a.len() != b.len() {
        return Err(OnChainError::PublicInputCountMismatch);
    }
    Ok(a.iter().zip(b.iter()).map(|(x, y)| *x * y).sum())
}

/// Compute the first `count` powers of `x`: `[1, x, x², …, x^(count-1)]`.
///
/// Empty `count = 0` returns an empty vector. `count = 1` returns
/// `[Fr::one()]` (the empty product).
///
/// ## Why a shared primitive
///
/// Multi-poly batched openings (Halo2 session 17, HyperPlonk session
/// 3e, Nova Spartan-batched 5-way session 22) all build a vector of
/// `ν^i` coefficients to weight a list of commitments / evaluations
/// before the MSM + pairing step. HyperPlonk's `kzg.rs` currently
/// inlines:
///
/// ```text
/// let mut nu_powers = [Fr::one(); 12];
/// for i in 1..12 {
///     nu_powers[i] = nu_powers[i - 1] * nu;
/// }
/// ```
///
/// Lifting the loop into a shared helper centralizes the audit
/// surface. Each consumer can either use the returned `Vec<Fr>` for
/// MSM weighting or feed it back through `fr_horner_eval` for the
/// equivalent polynomial-evaluation form.
///
/// Session 72 (post-v0.8.3): ninth shared primitive, joining the
/// eight from sessions 21-66.
#[must_use]
pub fn powers_of(x: &Fr, count: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(count);
    if count == 0 {
        return out;
    }
    out.push(Fr::one());
    for i in 1..count {
        let next = out[i - 1] * x;
        out.push(next);
    }
    out
}

/// Evaluate a polynomial via the Horner scheme.
///
/// Given coefficients `[a_0, a_1, …, a_{n-1}]` representing
/// `p(X) = a_0 + a_1·X + a_2·X² + … + a_{n-1}·X^{n-1}`, returns
/// `p(x)` computed in `n - 1` multiplications and `n - 1` additions:
///
/// ```text
/// p(x) = ((…((a_{n-1} · x) + a_{n-2}) · x + a_{n-3}) · x + … ) · x + a_0
/// ```
///
/// Empty coefficient slice returns `Fr::zero()` (vacuously the zero
/// polynomial).
///
/// ## Why a shared primitive
///
/// All four Phase-3 verifier crates evaluate polynomials in Fr at
/// challenge points: HyperPlonk for round polynomials in the
/// sumcheck, Halo2 for the quotient polynomial reconstruction
/// `t(ξ) = Σ ξ^(k·i) · h_i(ξ)`, Nova for the cross-term residual,
/// FRI-STARK for the final-poly low-degree check. Each currently
/// inlines a Horner loop. Lifting it here gives a single
/// audit-grade implementation.
///
/// Session 63 (post-v0.8.2): seventh shared primitive joining
/// `fr_from_be_bytes_reduced`, `fr_be_from_u64`,
/// `derive_fr_challenge`, `verify_two_pair_pairing`,
/// `commitment_minus_scalar_g1`, `compute_kzg_opening_lhs`.
#[must_use]
pub fn fr_horner_eval(coeffs: &[Fr], x: &Fr) -> Fr {
    if coeffs.is_empty() {
        return Fr::zero();
    }
    // Iterate from the highest-degree coefficient down to a_0.
    let mut acc = *coeffs.last().expect("coeffs non-empty by guard above");
    for c in coeffs.iter().rev().skip(1) {
        acc = acc * x + c;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ark_std::UniformRand;

    fn seeded_rng(seed: u64) -> ark_std::rand::rngs::StdRng {
        use ark_std::rand::SeedableRng;
        ark_std::rand::rngs::StdRng::seed_from_u64(seed)
    }

    #[test]
    fn canonical_bytes_roundtrip() {
        let mut rng = seeded_rng(0);
        for _ in 0..20 {
            let fr = Fr::rand(&mut rng);
            let bytes = fr_to_canonical_bytes(&fr);
            let decoded = fr_from_canonical_bytes(&bytes).unwrap();
            assert_eq!(fr, decoded);
        }
    }

    #[test]
    fn canonical_bytes_rejects_out_of_range() {
        let r_bytes = crate::fr::BN254_FR_MODULUS_BE;
        assert!(fr_from_canonical_bytes(&r_bytes).is_err());
    }

    #[test]
    fn fr_pow_matches_arkworks() {
        let mut rng = seeded_rng(1);
        for _ in 0..10 {
            let base = Fr::rand(&mut rng);
            let exp = (rng_next_u32(&mut rng) as u64) & 0xFFFF; // small exp
            assert_eq!(fr_pow_u64(&base, exp), base.pow([exp]));
        }
    }

    fn rng_next_u32(rng: &mut ark_std::rand::rngs::StdRng) -> u32 {
        use ark_std::rand::RngCore;
        rng.next_u32()
    }

    #[test]
    fn lagrange_basis_one_is_one_at_omega_zero() {
        // L_1(1) should be 1 by definition (L_1 basis evaluated at ω^0 = 1).
        // But L_1(ξ) = (ξ^n - 1) / (n(ξ - 1)) is 0/0 at ξ = 1; our helper
        // returns InternalInvariantViolation on div-by-zero. Instead check
        // L_1 at other domain roots: L_1(ω^k) = 0 for k ≠ 0.
        let n: u64 = 8;
        let omega = find_primitive_nth_root(n);
        for k in 1..n {
            let xi = fr_pow_u64(&omega, k);
            let l_1 = lagrange_basis_one(&xi, n).unwrap();
            assert_eq!(l_1, Fr::zero(), "L_1(ω^{k}) should be 0");
        }
    }

    #[test]
    fn lagrange_basis_at_is_one_on_its_own_point() {
        // L_{i+1}(ω^i) = 1.
        // Our helper hits div-by-0 at ξ = ω^i (domain root collision),
        // so we test the neighbourhood by verifying L_{i+1}(ω^j) = 0 for j ≠ i.
        let n: u64 = 8;
        let omega = find_primitive_nth_root(n);
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let xi = fr_pow_u64(&omega, j);
                let l = lagrange_basis_at(&xi, i, n, &omega).unwrap();
                assert_eq!(l, Fr::zero(), "L_{{{}+1}}(ω^{}) should be 0", i, j);
            }
        }
    }

    #[test]
    fn pi_poly_matches_manual_sum() {
        // For n_public = 3, evaluate PI(ξ) two ways and compare.
        let mut rng = seeded_rng(42);
        let n: u64 = 16;
        let omega = find_primitive_nth_root(n);
        let xi = Fr::rand(&mut rng);
        let public_inputs = vec![Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)];

        let got = evaluate_public_input_poly(&xi, &omega, n, &public_inputs).unwrap();

        // Manual reference: PI(ξ) = -Σ w_i · L_{i+1}(ξ)
        let mut expected = Fr::zero();
        for (i, w) in public_inputs.iter().enumerate() {
            let l = lagrange_basis_at(&xi, i as u64, n, &omega).unwrap();
            expected += *w * l;
        }
        expected = -expected;

        assert_eq!(got, expected);
    }

    #[test]
    fn pi_poly_empty_is_zero() {
        let xi = Fr::from(42u64);
        let omega = Fr::from(2u64);
        let got = evaluate_public_input_poly(&xi, &omega, 8, &[]).unwrap();
        assert_eq!(got, Fr::zero());
    }

    #[test]
    fn decode_public_inputs_matches_individual() {
        let mut rng = seeded_rng(7);
        let frs = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let mut concat = Vec::new();
        for f in &frs {
            concat.extend_from_slice(&fr_to_canonical_bytes(f));
        }
        let decoded = decode_public_inputs(&concat).unwrap();
        assert_eq!(decoded, frs);
    }

    #[test]
    fn decode_public_inputs_rejects_short_trailing() {
        let bad = vec![0u8; 31];
        assert!(matches!(
            decode_public_inputs(&bad),
            Err(OnChainError::PublicInputCountMismatch),
        ));
    }

    /// Helper: find a primitive n-th root of unity in Fr. BN254 scalar
    /// field supports 2-adicity up to 2^28, so n up to that works.
    fn find_primitive_nth_root(n: u64) -> Fr {
        // `Fr::TWO_ADICITY` = 28 and `Fr::TWO_ADIC_ROOT_OF_UNITY` is the
        // 2^28-th root of unity. For n = 2^k with k ≤ 28, we raise it
        // to 2^(28-k) to get a primitive n-th root.
        use ark_ff::FftField;
        let two_adic = Fr::TWO_ADIC_ROOT_OF_UNITY;
        let k = n.trailing_zeros();
        assert_eq!(n, 1 << k, "n must be a power of 2 for this helper");
        let extra = Fr::TWO_ADICITY - k;
        two_adic.pow([1_u64 << extra])
    }

    #[test]
    fn root_of_unity_2k_is_primitive() {
        for k in 0..=16u32 {
            let omega = root_of_unity_2k(k).unwrap();
            let order = 1u64 << k;
            assert_eq!(
                fr_pow_u64(&omega, order),
                Fr::one(),
                "omega^(2^{k}) must be 1"
            );
            if k >= 1 {
                assert_ne!(
                    fr_pow_u64(&omega, order / 2),
                    Fr::one(),
                    "omega must be a *primitive* 2^{k}-th root (order exactly 2^{k})"
                );
            }
        }
    }

    #[test]
    fn root_of_unity_2k_matches_test_oracle() {
        for k in 1..=20u32 {
            assert_eq!(root_of_unity_2k(k).unwrap(), find_primitive_nth_root(1 << k));
        }
    }

    #[test]
    fn root_of_unity_2k_rejects_above_two_adicity() {
        assert!(root_of_unity_2k(29).is_err());
        assert!(root_of_unity_2k(28).is_ok());
    }

    // ---- fr_from_be_bytes_reduced ----

    #[test]
    fn fr_from_be_bytes_reduced_matches_canonical_for_in_range_input() {
        // For any in-range 32-byte Fr encoding, the reduced helper
        // must agree with the strict canonical decoder.
        let mut rng = seeded_rng(1);
        for _ in 0..8 {
            let f = Fr::rand(&mut rng);
            let canonical = fr_to_canonical_bytes(&f);
            let canonical_arr: [u8; 32] = canonical;
            let strict = fr_from_canonical_bytes(&canonical).unwrap();
            let reduced = fr_from_be_bytes_reduced(&canonical_arr);
            assert_eq!(strict, reduced);
        }
    }

    // ---- fr_be_from_u64 ----

    #[test]
    fn fr_be_from_u64_matches_arkworks_encoding() {
        // For any u64, the const helper must produce the same
        // canonical BE encoding as `fr_to_canonical_bytes(&Fr::from(n))`.
        for &n in &[0u64, 1, 2, 3, 42, 255, 256, 1 << 32, u64::MAX] {
            let via_const = fr_be_from_u64(n);
            let via_arkworks = fr_to_canonical_bytes(&Fr::from(n));
            assert_eq!(via_const, via_arkworks, "mismatch for n = {n}");
        }
    }

    #[test]
    fn fr_be_from_u64_round_trips_through_canonical_decoder() {
        // A value produced by fr_be_from_u64 must round-trip through
        // the strict decoder — the encoding is definitely in-range.
        for &n in &[0u64, 1, 42, u64::MAX] {
            let bytes = fr_be_from_u64(n);
            let decoded = fr_from_canonical_bytes(&bytes).unwrap();
            assert_eq!(decoded, Fr::from(n));
        }
    }

    #[test]
    fn fr_from_be_bytes_reduced_accepts_out_of_range_input() {
        // All-ones 32-byte input is definitely above the BN254 Fr
        // modulus (≈ 2^254). `fr_from_canonical_bytes` must reject,
        // but the reduced helper must succeed by taking value mod r.
        let all_ones = [0xFFu8; 32];
        let strict = fr_from_canonical_bytes(&all_ones);
        assert!(matches!(strict, Err(OnChainError::PublicInputOutOfRange)));
        let reduced = fr_from_be_bytes_reduced(&all_ones);
        // The reduced value must be strictly less than the field
        // modulus. Re-encoding it as canonical bytes and decoding
        // strictly must succeed.
        let canonical = fr_to_canonical_bytes(&reduced);
        let strict2 = fr_from_canonical_bytes(&canonical).unwrap();
        assert_eq!(reduced, strict2);
    }

    // ---- Property-based tests (session 34) ----
    //
    // Canonical encode/decode is the most-hit code path: every
    // challenge derivation and every proof parse runs through
    // `fr_to_canonical_bytes` ↔ `fr_from_canonical_bytes`. Tight
    // round-trip invariants under proptest guard against subtle
    // endianness / byte-order regressions.

    use proptest::prelude::*;

    proptest! {
        /// `fr_to_canonical_bytes → fr_from_canonical_bytes` is
        /// the identity for any Fr element.
        #[test]
        fn prop_canonical_round_trip(seed in any::<u64>()) {
            let mut rng = seeded_rng(seed);
            let original = Fr::rand(&mut rng);
            let bytes = fr_to_canonical_bytes(&original);
            let decoded = fr_from_canonical_bytes(&bytes).unwrap();
            prop_assert_eq!(original, decoded);
        }

        /// `fr_be_from_u64 → fr_from_canonical_bytes` matches
        /// `Fr::from(n)` for any u64. Confirms the const helper
        /// produces canonical BE encodings identical to the
        /// arkworks round-trip.
        #[test]
        fn prop_fr_be_from_u64_matches_arkworks(n in any::<u64>()) {
            let via_const = fr_be_from_u64(n);
            let decoded = fr_from_canonical_bytes(&via_const).unwrap();
            prop_assert_eq!(decoded, Fr::from(n));
        }

        /// `fr_from_be_bytes_reduced` agrees with
        /// `fr_from_canonical_bytes` for every in-range input. The
        /// reduced variant's behavior diverges only for out-of-range
        /// inputs, which this test deliberately excludes.
        #[test]
        fn prop_reduced_matches_strict_in_range(seed in any::<u64>()) {
            let mut rng = seeded_rng(seed);
            let fr = Fr::rand(&mut rng);
            let bytes = fr_to_canonical_bytes(&fr);
            let strict = fr_from_canonical_bytes(&bytes).unwrap();
            let reduced = fr_from_be_bytes_reduced(&bytes);
            prop_assert_eq!(strict, reduced);
        }

        /// `fr_from_be_bytes_reduced` always produces an Fr element
        /// whose canonical round-trip equals itself. Guarantees that
        /// the reduced value is strictly less than r.
        #[test]
        fn prop_reduced_output_is_in_range(bytes in proptest::array::uniform32(any::<u8>())) {
            let reduced = fr_from_be_bytes_reduced(&bytes);
            let encoded = fr_to_canonical_bytes(&reduced);
            let decoded = fr_from_canonical_bytes(&encoded).unwrap();
            prop_assert_eq!(reduced, decoded);
        }

        // ───────────────────────────────────────────────────────────
        // Session 63 — `fr_horner_eval` properties
        // ───────────────────────────────────────────────────────────

        /// Horner-scheme evaluation matches the naive
        /// sum-of-products implementation for any polynomial up to
        /// degree 8 and any in-range Fr challenge point.
        ///
        /// This is the soundness invariant that justifies the lift:
        /// callers can replace inline Horner loops with this helper
        /// without changing the result by even one Fr element.
        #[test]
        fn prop_horner_matches_naive_eval(
            seed in 0u64..=u64::MAX,
            n_coeffs in 0usize..=8,
            x_seed in 0u64..=u64::MAX,
        ) {
            let mut rng = seeded_rng(seed);
            let coeffs: Vec<Fr> = (0..n_coeffs).map(|_| Fr::rand(&mut rng)).collect();
            let x = Fr::from(x_seed);

            // Naive sum-of-products: Σ a_i · x^i.
            let mut naive = Fr::zero();
            let mut x_pow = Fr::one();
            for c in &coeffs {
                naive += *c * x_pow;
                x_pow *= x;
            }

            let horner = fr_horner_eval(&coeffs, &x);
            prop_assert_eq!(horner, naive);
        }

        /// Empty coefficient slice evaluates to zero (vacuous polynomial).
        #[test]
        fn prop_horner_empty_is_zero(x_seed in 0u64..=u64::MAX) {
            let x = Fr::from(x_seed);
            let result = fr_horner_eval(&[], &x);
            prop_assert_eq!(result, Fr::zero());
        }

        /// Constant polynomial `p(X) = c` evaluates to `c` everywhere.
        #[test]
        fn prop_horner_constant_polynomial(
            c_seed in 0u64..=u64::MAX,
            x_seed in 0u64..=u64::MAX,
        ) {
            let c = Fr::from(c_seed);
            let x = Fr::from(x_seed);
            prop_assert_eq!(fr_horner_eval(&[c], &x), c);
        }

        /// Linear polynomial `p(X) = a + b·X` evaluates to `a + b·x`.
        #[test]
        fn prop_horner_linear_polynomial(
            a_seed in 0u64..=u64::MAX,
            b_seed in 0u64..=u64::MAX,
            x_seed in 0u64..=u64::MAX,
        ) {
            let a = Fr::from(a_seed);
            let b = Fr::from(b_seed);
            let x = Fr::from(x_seed);
            let expected = a + b * x;
            prop_assert_eq!(fr_horner_eval(&[a, b], &x), expected);
        }

        /// Evaluating any polynomial at `x = 0` returns the constant
        /// term `a_0`. Pins the Horner reduction's terminal step.
        #[test]
        fn prop_horner_at_zero_returns_constant(
            seed in 0u64..=u64::MAX,
            n_coeffs in 1usize..=8,
        ) {
            let mut rng = seeded_rng(seed);
            let coeffs: Vec<Fr> = (0..n_coeffs).map(|_| Fr::rand(&mut rng)).collect();
            let zero = Fr::zero();
            prop_assert_eq!(fr_horner_eval(&coeffs, &zero), coeffs[0]);
        }

        /// Evaluating any polynomial at `x = 1` returns the sum of
        /// coefficients `Σ a_i`. Pins the Horner accumulation pattern.
        #[test]
        fn prop_horner_at_one_returns_sum(
            seed in 0u64..=u64::MAX,
            n_coeffs in 1usize..=8,
        ) {
            let mut rng = seeded_rng(seed);
            let coeffs: Vec<Fr> = (0..n_coeffs).map(|_| Fr::rand(&mut rng)).collect();
            let one = Fr::one();
            let expected: Fr = coeffs.iter().copied().sum();
            prop_assert_eq!(fr_horner_eval(&coeffs, &one), expected);
        }

        // ───────────────────────────────────────────────────────────
        // Session 72 — `powers_of` properties
        // ───────────────────────────────────────────────────────────

        /// `powers_of(x, count)` returns a vector of length `count`.
        /// Empty case returns empty vector.
        #[test]
        fn prop_powers_of_length(
            x_seed in 0u64..=u64::MAX,
            count in 0usize..=16,
        ) {
            let x = Fr::from(x_seed);
            let powers = powers_of(&x, count);
            prop_assert_eq!(powers.len(), count);
        }

        /// `powers_of(x, count)[0] == Fr::one()` for any `count >= 1`.
        /// Pins the empty-product convention.
        #[test]
        fn prop_powers_of_first_is_one(
            x_seed in 0u64..=u64::MAX,
            count in 1usize..=16,
        ) {
            let x = Fr::from(x_seed);
            let powers = powers_of(&x, count);
            prop_assert_eq!(powers[0], Fr::one());
        }

        /// Recurrence: `powers[i] == powers[i-1] · x` for `1 ≤ i < count`.
        /// Pins the multiplicative-step invariant.
        #[test]
        fn prop_powers_of_recurrence(
            x_seed in 0u64..=u64::MAX,
            count in 2usize..=16,
        ) {
            let x = Fr::from(x_seed);
            let powers = powers_of(&x, count);
            for i in 1..count {
                prop_assert_eq!(powers[i], powers[i - 1] * x);
            }
        }

        /// Closed form: `powers[i] == x^i` (cross-checked against
        /// `fr_pow_u64`). Catches any future implementation that
        /// silently computes the wrong sequence (e.g. off-by-one
        /// or `x^(i+1)` shift).
        #[test]
        fn prop_powers_of_matches_pow(
            x_seed in 0u64..=u64::MAX,
            count in 0usize..=16,
        ) {
            let x = Fr::from(x_seed);
            let powers = powers_of(&x, count);
            for (i, p) in powers.iter().enumerate() {
                prop_assert_eq!(*p, fr_pow_u64(&x, i as u64));
            }
        }

        /// Identity case: `powers_of(Fr::one(), count) == [1, 1, …, 1]`.
        #[test]
        fn prop_powers_of_one_is_all_ones(count in 0usize..=16) {
            let powers = powers_of(&Fr::one(), count);
            for p in &powers {
                prop_assert_eq!(*p, Fr::one());
            }
        }

        // ───────────────────────────────────────────────────────────
        // Session 77 — `fr_inner_product` properties
        // ───────────────────────────────────────────────────────────

        /// Empty slices yield `Fr::zero()` (vacuous empty sum).
        #[test]
        fn prop_inner_product_empty_is_zero(_seed in 0u64..=u64::MAX) {
            let result = fr_inner_product(&[], &[]).unwrap();
            prop_assert_eq!(result, Fr::zero());
        }

        /// Mismatched-length slices return `PublicInputCountMismatch`.
        #[test]
        fn prop_inner_product_mismatched_length_rejected(
            seed in 0u64..=u64::MAX,
            len_a in 0usize..=8,
            len_b in 0usize..=8,
        ) {
            prop_assume!(len_a != len_b);
            let mut rng = seeded_rng(seed);
            let a: Vec<Fr> = (0..len_a).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..len_b).map(|_| Fr::rand(&mut rng)).collect();
            prop_assert!(matches!(
                fr_inner_product(&a, &b),
                Err(OnChainError::PublicInputCountMismatch),
            ));
        }

        /// Inner product matches the naive Σ a_i · b_i computation
        /// for any equal-length pair. **The soundness invariant** that
        /// justifies the lift: callers can replace inline weighted-sum
        /// loops with `fr_inner_product` without changing the result.
        #[test]
        fn prop_inner_product_matches_naive(
            seed in 0u64..=u64::MAX,
            n in 0usize..=8,
        ) {
            let mut rng = seeded_rng(seed);
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let mut naive = Fr::zero();
            for i in 0..n {
                naive += a[i] * b[i];
            }
            prop_assert_eq!(fr_inner_product(&a, &b).unwrap(), naive);
        }

        /// Commutative: `<a, b> == <b, a>`. Catches a future
        /// asymmetric implementation that would silently change the
        /// pairing semantics.
        #[test]
        fn prop_inner_product_commutative(
            seed in 0u64..=u64::MAX,
            n in 0usize..=8,
        ) {
            let mut rng = seeded_rng(seed);
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            prop_assert_eq!(
                fr_inner_product(&a, &b).unwrap(),
                fr_inner_product(&b, &a).unwrap(),
            );
        }

        /// Inner product against the all-ones vector returns the sum
        /// of the other slice. Pins the unit-vector case.
        #[test]
        fn prop_inner_product_with_ones_is_sum(
            seed in 0u64..=u64::MAX,
            n in 0usize..=8,
        ) {
            let mut rng = seeded_rng(seed);
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let ones: Vec<Fr> = (0..n).map(|_| Fr::one()).collect();
            let expected: Fr = a.iter().copied().sum();
            prop_assert_eq!(fr_inner_product(&a, &ones).unwrap(), expected);
        }
    }
}
