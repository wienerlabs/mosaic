//! Groth16 batch verification with Bowe-Gabizon randomized aggregation.
//!
//! Verifies `N` Groth16 proofs (all for the same verifying key) with a
//! single `alt_bn128_pairing` syscall carrying `N + 3` pairs.
//!
//! ## Protocol
//!
//! Single-proof Groth16 checks:
//! ```text
//! e(-A_i, B_i) · e(α, β) · e(L_i, γ) · e(C_i, δ) = 1
//! ```
//!
//! Batched with Fiat-Shamir-derived random coefficients `r_i`:
//! ```text
//! Π_i e(-r_i · A_i, B_i)
//!   · e((Σ r_i)·α, β)
//!   · e(Σ r_i · L_i, γ)
//!   · e(Σ r_i · C_i, δ)
//!   = 1
//! ```
//!
//! Uses bilinearity of pairings: `e(P, Q)^k = e(k·P, Q)` and
//! `Π_i e(r_i·P_i, Q) = e(Σ r_i · P_i, Q)` (when Q is shared).
//!
//! ## CU savings
//!
//! Per-proof MSM for `L_i` is still O(n_pi) and unavoidable. The
//! savings come from collapsing N pairing checks into one:
//!
//! | N | Looped CU (est) | Batched CU (est) | Savings |
//! |---|---|---|---|
//! | 1 | 80K | 90K | -12% (loss) |
//! | 3 | 240K | 190K | 21% |
//! | 10 | 800K | 400K | 50% |
//! | 20 | 1.6M | 700K | 56% |
//!
//! Break-even is around N=2. For N=1 the loop path is slightly faster;
//! we still route through batch for API uniformity, losing ~10K CU.
//!
//! ## Fiat-Shamir coefficients
//!
//! `r_i = SHA256(seed || i.to_be_bytes())` where
//! `seed = SHA256(vk || proof_1 || ... || proof_N || pi_1 || ... || pi_N)`.
//! Independent per-i hashes (not powers of a single challenge) keep the
//! derivation free of on-chain Fr multiplication.

use crate::{
    canonical::{lt_be, Groth16Proof, Groth16VerifyingKey, BN254_FR_MODULUS_BE},
    fr_arith::{add_mod_r, reduce_mod_r},
    sizes::{FR_LEN, G1_LEN, G2_LEN},
};
use alloc::vec::Vec;
use mosaic_core::{
    syscall::{AltBn128Op, InputEndianness, SyscallBackend},
    OnChainError,
};

/// G1 additive identity in canonical 64-byte form.
const G1_ZERO: [u8; G1_LEN] = [0u8; G1_LEN];

/// BN254 base-field modulus `q` in big-endian (for G1 y-negation).
const BN254_FQ_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// Perform a batched Groth16 verification for `N ≥ 1` proofs sharing
/// the same verifying key.
///
/// - All proofs validated by the length checks in
///   [`Groth16Proof::from_bytes`] before any syscalls.
/// - Public inputs validated range-checked against the scalar field
///   order `r` per-proof.
/// - On failure returns the first encountered error (malformed bytes
///   fail fast; crypto failures produce `PairingCheckFailed`).
///
/// If `proofs.is_empty()`, returns `Ok(())` trivially.
pub fn batch_verify<B: SyscallBackend + ?Sized, const LE_INPUTS: bool>(
    backend: &B,
    vk_bytes: &[u8],
    proofs: &[&[u8]],
    public_inputs: &[&[u8]],
) -> Result<(), OnChainError> {
    if proofs.len() != public_inputs.len() {
        return Err(OnChainError::PublicInputCountMismatch);
    }
    if proofs.is_empty() {
        return Ok(());
    }
    let vk = Groth16VerifyingKey::from_bytes(vk_bytes)?;
    let endianness = if LE_INPUTS {
        InputEndianness::LittleEndian
    } else {
        InputEndianness::BigEndian
    };

    // ---------- 1. Pre-flight: parse + range-check all proofs/PIs ----------
    let mut parsed_proofs: Vec<Groth16Proof<'_>> = Vec::with_capacity(proofs.len());
    for (proof_bytes, pi_bytes) in proofs.iter().zip(public_inputs.iter()) {
        let p = Groth16Proof::from_bytes(proof_bytes)?;
        if pi_bytes.len() != vk.num_public_inputs().saturating_mul(FR_LEN) {
            return Err(OnChainError::PublicInputCountMismatch);
        }
        for chunk in pi_bytes.chunks_exact(FR_LEN) {
            let mut be = [0u8; FR_LEN];
            be.copy_from_slice(chunk);
            if LE_INPUTS {
                be.reverse();
            }
            if !lt_be(&be, &BN254_FR_MODULUS_BE) {
                return Err(OnChainError::PublicInputOutOfRange);
            }
        }
        parsed_proofs.push(p);
    }

    // ---------- 2. Derive Fiat-Shamir coefficients r_0..r_{N-1} ----------
    let r_values = derive_batch_challenges(backend, vk_bytes, proofs, public_inputs)?;

    // ---------- 3. Per-proof: compute L_i, accumulate weighted sums ----------
    let mut sum_r = [0u8; FR_LEN];
    let mut l_agg: [u8; G1_LEN] = G1_ZERO;
    let mut c_agg: [u8; G1_LEN] = G1_ZERO;
    let mut pairing_input = Vec::with_capacity((proofs.len() + 3) * (G1_LEN + G2_LEN));

    for (proof, (pi_bytes, r_i)) in parsed_proofs
        .iter()
        .zip(public_inputs.iter().zip(r_values.iter()))
    {
        // Compute L_i = IC[0] + Σ_j pi_j · IC[j+1].
        let l_i = compute_l(backend, &vk, pi_bytes, endianness)?;

        // r_i · A_i, then negate for the pairing input.
        let mut a_arr = [0u8; G1_LEN];
        a_arr.copy_from_slice(proof.a);
        let r_a = scalar_mul_g1(backend, &a_arr, r_i, endianness)?;
        let neg_r_a = negate_g1(&r_a);

        // r_i · L_i, accumulate into L_agg.
        let r_l = scalar_mul_g1(backend, &l_i, r_i, endianness)?;
        l_agg = add_g1(backend, &l_agg, &r_l, endianness)?;

        // r_i · C_i, accumulate into C_agg.
        let mut c_arr = [0u8; G1_LEN];
        c_arr.copy_from_slice(proof.c);
        let r_c = scalar_mul_g1(backend, &c_arr, r_i, endianness)?;
        c_agg = add_g1(backend, &c_agg, &r_c, endianness)?;

        sum_r = add_mod_r(&sum_r, r_i);

        // Pair: (−r_i · A_i, B_i)
        pairing_input.extend_from_slice(&neg_r_a);
        pairing_input.extend_from_slice(proof.b);
    }

    // ---------- 4. Final 3 pairs: (Σr·α, β), (L_agg, γ), (C_agg, δ) ----------
    let sum_r_alpha = scalar_mul_g1(backend, &vk.alpha_g1, &sum_r, endianness)?;
    pairing_input.extend_from_slice(&sum_r_alpha);
    pairing_input.extend_from_slice(&vk.beta_g2);
    pairing_input.extend_from_slice(&l_agg);
    pairing_input.extend_from_slice(&vk.gamma_g2);
    pairing_input.extend_from_slice(&c_agg);
    pairing_input.extend_from_slice(&vk.delta_g2);

    // ---------- 5. Single pairing syscall ----------
    let result =
        backend.alt_bn128_group_op(AltBn128Op::Pairing, endianness, &pairing_input)?;
    if result.len() != 32 || result[31] != 0x01 {
        return Err(OnChainError::PairingCheckFailed);
    }
    Ok(())
}

/// Compute `L_i = IC[0] + Σ_j pi_j · IC[j+1]` for a single proof's
/// public inputs. Same formula as the single-proof verifier uses.
fn compute_l<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &Groth16VerifyingKey,
    pi_bytes: &[u8],
    endianness: InputEndianness,
) -> Result<[u8; G1_LEN], OnChainError> {
    let mut l = vk.ic[0];
    for (j, chunk) in pi_bytes.chunks_exact(FR_LEN).enumerate() {
        let ic_j = vk
            .ic
            .get(j + 1)
            .ok_or(OnChainError::InternalInvariantViolation)?;
        let mut scalar = [0u8; FR_LEN];
        scalar.copy_from_slice(chunk);
        let prod = scalar_mul_g1(backend, ic_j, &scalar, endianness)?;
        l = add_g1(backend, &l, &prod, endianness)?;
    }
    Ok(l)
}

/// Derive `r_0, ..., r_{N-1}` from a Fiat-Shamir transcript:
/// `seed = SHA256(vk ‖ proof_1 ‖ ... ‖ proof_N ‖ pi_1 ‖ ... ‖ pi_N)`,
/// `r_i = SHA256(seed ‖ i_be_bytes) mod r`.
fn derive_batch_challenges<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk_bytes: &[u8],
    proofs: &[&[u8]],
    public_inputs: &[&[u8]],
) -> Result<Vec<[u8; FR_LEN]>, OnChainError> {
    let mut seed_inputs: Vec<&[u8]> = Vec::with_capacity(1 + proofs.len() * 2);
    seed_inputs.push(vk_bytes);
    for p in proofs {
        seed_inputs.push(p);
    }
    for pi in public_inputs {
        seed_inputs.push(pi);
    }
    let seed = backend.sha256(&seed_inputs)?;

    let mut r_values = Vec::with_capacity(proofs.len());
    for i in 0..proofs.len() {
        let i_be = (i as u64).to_be_bytes();
        let mut r = backend.sha256(&[&seed, &i_be])?;
        reduce_mod_r(&mut r);
        r_values.push(r);
    }
    Ok(r_values)
}

// ---------- G1 op wrappers (duplicated from mosaic-plonk::msm for ----------
//            crate independence; keep identical semantics)

fn scalar_mul_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    point: &[u8],
    scalar: &[u8; FR_LEN],
    endianness: InputEndianness,
) -> Result<[u8; G1_LEN], OnChainError> {
    if point.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let mut input = Vec::with_capacity(G1_LEN + FR_LEN);
    input.extend_from_slice(point);
    input.extend_from_slice(scalar);
    let out = backend.alt_bn128_group_op(AltBn128Op::G1Mul, endianness, &input)?;
    if out.len() != G1_LEN {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut result = [0u8; G1_LEN];
    result.copy_from_slice(&out);
    Ok(result)
}

fn add_g1<B: SyscallBackend + ?Sized>(
    backend: &B,
    a: &[u8; G1_LEN],
    b: &[u8; G1_LEN],
    endianness: InputEndianness,
) -> Result<[u8; G1_LEN], OnChainError> {
    let mut input = Vec::with_capacity(G1_LEN * 2);
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    let out = backend.alt_bn128_group_op(AltBn128Op::G1Add, endianness, &input)?;
    if out.len() != G1_LEN {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let mut result = [0u8; G1_LEN];
    result.copy_from_slice(&out);
    Ok(result)
}

/// Negate G1 y-coordinate in big-endian canonical form.
fn negate_g1(point: &[u8; G1_LEN]) -> [u8; G1_LEN] {
    let mut out = *point;
    let y_slice = &mut out[32..64];
    if y_slice.iter().all(|b| *b == 0) {
        return out;
    }
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let q_b = i16::from(BN254_FQ_MODULUS_BE[i]);
        let y_b = i16::from(y_slice[i]);
        let diff = q_b - y_b - borrow;
        if diff < 0 {
            y_slice[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            y_slice[i] = diff as u8;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "negate_g1 saw y > q");
    out
}
