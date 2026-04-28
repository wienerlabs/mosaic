//! PLONK verifier linearization + KZG batched-opening pairing check.
//!
//! Mirrors the snarkjs 0.7.x `plonk_verify.js` reference flow:
//!
//! ```text
//! challenges        → RoundChallenges::derive          (challenges.rs)
//! → [decode to Fr]  → ComputedScalars::from_bytes
//!   * xi_n, zh, L_1, PI, r_0, v_powers
//! → [G1 MSMs]
//!   * D = Qm·(a·b) + Ql·a + Qr·b + Qo·c + Qc
//!       + Z·(α·perm + α²·L_1 + u) - S3·(α·β·zw·perm_s) - Zh·(T1 + ξⁿ·T2 + ξ²ⁿ·T3)
//!   * F = D + A·v + B·v² + C·v³ + S1·v⁴ + S2·v⁵
//!   * E = e · [1]_1
//! → [pairing]
//!   * A1 = Wxi + u·Wxiω
//!   * B1 = ξ·Wxi + u·ξ·ω·Wxiω + F - E
//!   * pairing(-A1, X_2) · pairing(B1, [1]_2) == 1
//! ```
//!
//! All Fr arithmetic goes through arkworks; all G1/G2 operations go
//! through [`SyscallBackend`]. The pairing is a single syscall with a
//! 2-pair input (384 bytes) returning `[0u8; 31] || 0x01` on success.

use crate::{
    canonical::{PlonkProof, PlonkVerifyingKey},
    challenges::RoundChallenges,
    field::{
        decode_public_inputs, evaluate_public_input_poly, fr_from_canonical_bytes, fr_pow_u64,
        fr_to_canonical_bytes, lagrange_basis_at,
    },
    g1_consts::{g1_generator_bytes, g2_generator_bytes},
    msm::{add_g1, msm_g1, negate_g1, scalar_mul_g1},
};
use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use mosaic_core::{
    syscall::{AltBn128Op, InputEndianness, SyscallBackend},
    OnChainError,
};

/// Fr-valued computed inputs consumed by the G1 MSM and pairing steps.
/// Derived once from `RoundChallenges` + VK + proof + public inputs.
#[derive(Debug, Clone)]
pub struct ComputedScalars {
    // ----- challenges as Fr -----
    pub beta: Fr,
    pub gamma: Fr,
    pub alpha: Fr,
    pub xi: Fr,
    /// v_powers[i] = v^i; v_powers[0] = 1 (unused padding), v_powers[1..=5] used.
    pub v_powers: [Fr; 6],
    pub u: Fr,

    // ----- domain-dependent computations -----
    /// ξⁿ where n = 2^power.
    pub xi_n: Fr,
    /// Zh(ξ) = ξⁿ - 1.
    pub zh: Fr,
    /// L_1(ξ).
    pub l1: Fr,
    /// PI(ξ).
    pub pi: Fr,
    /// r_0 — constant term of the linearization polynomial.
    pub r0: Fr,

    // ----- VK constants as Fr -----
    pub k1: Fr,
    pub k2: Fr,
    /// Primitive n-th root of unity for the evaluation domain.
    pub omega: Fr,
    /// Domain size n = 2^power.
    pub n: u64,
}

impl ComputedScalars {
    /// Derive all scalar quantities needed by the verifier. Mirrors
    /// snarkjs's `calculateLagrangeEvaluations` + `calculatePI` +
    /// `calculateR0` in one pass so the data flow is explicit.
    ///
    /// Factored across several `#[inline(never)]` helpers so each
    /// stack frame stays under the SBF 4 KB limit. A single monolithic
    /// derive() would consume >5 KB on the stack.
    #[inline(never)]
    pub fn derive(
        challenges: &RoundChallenges,
        vk: &PlonkVerifyingKey,
        proof: &PlonkProof<'_>,
        public_inputs_bytes: &[u8],
    ) -> Result<Self, OnChainError> {
        let (beta, gamma, alpha, xi, v, u) = decode_challenges(challenges)?;
        let v_powers = compute_v_powers(&v);
        let (k1, k2, omega, n) = decode_vk_constants(vk)?;
        let (xi_n, zh, l1) = compute_domain_scalars(&xi, n, &omega)?;
        let pi = compute_pi(&xi, &omega, n, public_inputs_bytes)?;
        let r0 = compute_r0_scalar(proof, &beta, &gamma, &alpha, &l1, &pi)?;

        Ok(Self {
            beta,
            gamma,
            alpha,
            xi,
            v_powers,
            u,
            xi_n,
            zh,
            l1,
            pi,
            r0,
            k1,
            k2,
            omega,
            n,
        })
    }
}

#[inline(never)]
fn decode_challenges(c: &RoundChallenges) -> Result<(Fr, Fr, Fr, Fr, Fr, Fr), OnChainError> {
    Ok((
        fr_from_canonical_bytes(&c.beta)?,
        fr_from_canonical_bytes(&c.gamma)?,
        fr_from_canonical_bytes(&c.alpha)?,
        fr_from_canonical_bytes(&c.xi)?,
        fr_from_canonical_bytes(&c.v)?,
        fr_from_canonical_bytes(&c.u)?,
    ))
}

#[inline(never)]
fn compute_v_powers(v: &Fr) -> [Fr; 6] {
    let mut p = [Fr::one(); 6];
    p[1] = *v;
    for i in 2..6 {
        p[i] = p[i - 1] * v;
    }
    p
}

#[inline(never)]
fn decode_vk_constants(vk: &PlonkVerifyingKey) -> Result<(Fr, Fr, Fr, u64), OnChainError> {
    let k1 = fr_from_canonical_bytes(&vk.k1)?;
    let k2 = fr_from_canonical_bytes(&vk.k2)?;
    let omega = fr_from_canonical_bytes(&vk.omega)?;
    let n = 1u64
        .checked_shl(vk.power)
        .ok_or(OnChainError::InternalInvariantViolation)?;
    Ok((k1, k2, omega, n))
}

#[inline(never)]
fn compute_domain_scalars(xi: &Fr, n: u64, omega: &Fr) -> Result<(Fr, Fr, Fr), OnChainError> {
    let xi_n = fr_pow_u64(xi, n);
    let zh = xi_n - Fr::one();
    let l1 = lagrange_basis_at(xi, 0, n, omega)?;
    Ok((xi_n, zh, l1))
}

#[inline(never)]
fn compute_pi(xi: &Fr, omega: &Fr, n: u64, public_inputs_bytes: &[u8]) -> Result<Fr, OnChainError> {
    let public_inputs_fr = decode_public_inputs(public_inputs_bytes)?;
    evaluate_public_input_poly(xi, omega, n, &public_inputs_fr)
}

/// Sub-helper: e3 = α · (ea + β·s1 + γ) · (eb + β·s2 + γ) · (ec + γ) · eval_zw.
/// Split out so the bigger r0 function's frame stays small.
#[inline(never)]
fn compute_e3(
    proof: &PlonkProof<'_>,
    beta: &Fr,
    gamma: &Fr,
    alpha: &Fr,
) -> Result<Fr, OnChainError> {
    let eval_a = fr_from_canonical_bytes(proof.eval_a)?;
    let eval_b = fr_from_canonical_bytes(proof.eval_b)?;
    let eval_c = fr_from_canonical_bytes(proof.eval_c)?;
    let eval_s1 = fr_from_canonical_bytes(proof.eval_s1)?;
    let eval_s2 = fr_from_canonical_bytes(proof.eval_s2)?;
    let eval_zw = fr_from_canonical_bytes(proof.eval_zw)?;

    let e3a = eval_a + *beta * eval_s1 + *gamma;
    let e3b = eval_b + *beta * eval_s2 + *gamma;
    let e3c = eval_c + *gamma;
    Ok(e3a * e3b * e3c * eval_zw * alpha)
}

#[inline(never)]
fn compute_r0_scalar(
    proof: &PlonkProof<'_>,
    beta: &Fr,
    gamma: &Fr,
    alpha: &Fr,
    l1: &Fr,
    pi: &Fr,
) -> Result<Fr, OnChainError> {
    let e3 = compute_e3(proof, beta, gamma, alpha)?;
    let alpha_sq = *alpha * alpha;
    Ok(*pi - *l1 * alpha_sq - e3)
}

/// Compute `D` — the linearization polynomial commitment.
///
/// Split into four sub-functions (d1, d2, d3, d4) each
/// `#[inline(never)]` so the SBF stack frame stays under 4 KB.
///
/// snarkjs `calculateD`:
/// ```text
/// d1 = Qm·(eval_a · eval_b) + Ql·eval_a + Qr·eval_b + Qo·eval_c + Qc
/// d2 = Z · (α·(eval_a + β·ξ + γ)(eval_b + β·k1·ξ + γ)(eval_c + β·k2·ξ + γ) + α²·L_1 + u)
/// d3 = S3 · ((eval_a + β·s1 + γ)(eval_b + β·s2 + γ)·α·β·eval_zw)
/// d4 = Zh · (T1 + ξⁿ·T2 + ξ²ⁿ·T3)
/// D  = d1 + d2 - d3 - d4
/// ```
#[inline(never)]
pub fn compute_d<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof<'_>,
    scalars: &ComputedScalars,
) -> Result<[u8; 64], OnChainError> {
    let d1 = compute_d1(backend, vk, proof)?;
    let d2 = compute_d2(backend, proof, scalars)?;
    let d3 = compute_d3(backend, vk, proof, scalars)?;
    let d4 = compute_d4(backend, proof, scalars)?;

    let d12 = add_g1(backend, &d1, &d2)?;
    let neg_d3 = negate_g1(&d3);
    let d123 = add_g1(backend, &d12, &neg_d3)?;
    let neg_d4 = negate_g1(&d4);
    add_g1(backend, &d123, &neg_d4)
}

/// d1 = Qm·(eval_a·eval_b) + Ql·eval_a + Qr·eval_b + Qo·eval_c + Qc.
#[inline(never)]
fn compute_d1<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof<'_>,
) -> Result<[u8; 64], OnChainError> {
    let eval_a = fr_from_canonical_bytes(proof.eval_a)?;
    let eval_b = fr_from_canonical_bytes(proof.eval_b)?;
    let eval_c = fr_from_canonical_bytes(proof.eval_c)?;
    let gate_scalars = [
        fr_to_canonical_bytes(&(eval_a * eval_b)),
        fr_to_canonical_bytes(&eval_a),
        fr_to_canonical_bytes(&eval_b),
        fr_to_canonical_bytes(&eval_c),
        fr_to_canonical_bytes(&Fr::one()),
    ];
    let gate_points: [&[u8]; 5] = [&vk.qm_g1, &vk.ql_g1, &vk.qr_g1, &vk.qo_g1, &vk.qc_g1];
    msm_g1(backend, &gate_points, &gate_scalars)
}

/// d2a = α · (eval_a + β·ξ + γ) · (eval_b + β·k1·ξ + γ) · (eval_c + β·k2·ξ + γ).
#[inline(never)]
fn compute_d2a(proof: &PlonkProof<'_>, scalars: &ComputedScalars) -> Result<Fr, OnChainError> {
    let eval_a = fr_from_canonical_bytes(proof.eval_a)?;
    let eval_b = fr_from_canonical_bytes(proof.eval_b)?;
    let eval_c = fr_from_canonical_bytes(proof.eval_c)?;
    let betaxi = scalars.beta * scalars.xi;
    let d2a1 = eval_a + betaxi + scalars.gamma;
    let d2a2 = eval_b + betaxi * scalars.k1 + scalars.gamma;
    let d2a3 = eval_c + betaxi * scalars.k2 + scalars.gamma;
    Ok(d2a1 * d2a2 * d2a3 * scalars.alpha)
}

/// Sub-helper: d2 coefficient = d2a + α²·L_1 + u.
#[inline(never)]
fn compute_d2_coeff(proof: &PlonkProof<'_>, scalars: &ComputedScalars) -> Result<Fr, OnChainError> {
    let d2a = compute_d2a(proof, scalars)?;
    let d2b = scalars.l1 * scalars.alpha * scalars.alpha;
    Ok(d2a + d2b + scalars.u)
}

/// d2 = Z · (α·(ea+βξ+γ)(eb+βk1ξ+γ)(ec+βk2ξ+γ) + α²·L_1 + u).
#[inline(never)]
fn compute_d2<B: SyscallBackend + ?Sized>(
    backend: &B,
    proof: &PlonkProof<'_>,
    scalars: &ComputedScalars,
) -> Result<[u8; 64], OnChainError> {
    let coeff = compute_d2_coeff(proof, scalars)?;
    scalar_mul_g1(backend, proof.z, &fr_to_canonical_bytes(&coeff))
}

/// d3 = S3 · ((ea+β·s1+γ)(eb+β·s2+γ)·α·β·eval_zw).
#[inline(never)]
fn compute_d3<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof<'_>,
    scalars: &ComputedScalars,
) -> Result<[u8; 64], OnChainError> {
    let eval_a = fr_from_canonical_bytes(proof.eval_a)?;
    let eval_b = fr_from_canonical_bytes(proof.eval_b)?;
    let eval_s1 = fr_from_canonical_bytes(proof.eval_s1)?;
    let eval_s2 = fr_from_canonical_bytes(proof.eval_s2)?;
    let eval_zw = fr_from_canonical_bytes(proof.eval_zw)?;
    let d3a = eval_a + scalars.beta * eval_s1 + scalars.gamma;
    let d3b = eval_b + scalars.beta * eval_s2 + scalars.gamma;
    let d3c = scalars.alpha * scalars.beta * eval_zw;
    let d3_coeff = d3a * d3b * d3c;
    scalar_mul_g1(backend, &vk.s3_g1, &fr_to_canonical_bytes(&d3_coeff))
}

/// d4 = Zh · (T1 + ξⁿ·T2 + ξ²ⁿ·T3).
#[inline(never)]
fn compute_d4<B: SyscallBackend + ?Sized>(
    backend: &B,
    proof: &PlonkProof<'_>,
    scalars: &ComputedScalars,
) -> Result<[u8; 64], OnChainError> {
    let xi_2n = scalars.xi_n * scalars.xi_n;
    let d4_scalars = [
        fr_to_canonical_bytes(&scalars.zh),
        fr_to_canonical_bytes(&(scalars.zh * scalars.xi_n)),
        fr_to_canonical_bytes(&(scalars.zh * xi_2n)),
    ];
    let d4_points: [&[u8]; 3] = [proof.t1, proof.t2, proof.t3];
    msm_g1(backend, &d4_points, &d4_scalars)
}

/// Compute `F = D + A·v + B·v² + C·v³ + S1·v⁴ + S2·v⁵`.
#[inline(never)]
pub fn compute_f<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof<'_>,
    scalars: &ComputedScalars,
    d: &[u8; 64],
) -> Result<[u8; 64], OnChainError> {
    // Five scalar-mul-and-sum terms combined via MSM + final add with D.
    let scalars_arr = [
        fr_to_canonical_bytes(&scalars.v_powers[1]),
        fr_to_canonical_bytes(&scalars.v_powers[2]),
        fr_to_canonical_bytes(&scalars.v_powers[3]),
        fr_to_canonical_bytes(&scalars.v_powers[4]),
        fr_to_canonical_bytes(&scalars.v_powers[5]),
    ];
    let points: [&[u8]; 5] = [proof.a, proof.b, proof.c, &vk.s1_g1, &vk.s2_g1];
    let linear_combo = msm_g1(backend, &points, &scalars_arr)?;
    add_g1(backend, d, &linear_combo)
}

/// Compute `E = e · [1]_1` where
/// ```text
/// e = -r_0 + v·eval_a + v²·eval_b + v³·eval_c + v⁴·eval_s1 + v⁵·eval_s2 + u·eval_zw
/// ```
#[inline(never)]
pub fn compute_e<B: SyscallBackend + ?Sized>(
    backend: &B,
    proof: &PlonkProof<'_>,
    scalars: &ComputedScalars,
) -> Result<[u8; 64], OnChainError> {
    let eval_a = fr_from_canonical_bytes(proof.eval_a)?;
    let eval_b = fr_from_canonical_bytes(proof.eval_b)?;
    let eval_c = fr_from_canonical_bytes(proof.eval_c)?;
    let eval_s1 = fr_from_canonical_bytes(proof.eval_s1)?;
    let eval_s2 = fr_from_canonical_bytes(proof.eval_s2)?;
    let eval_zw = fr_from_canonical_bytes(proof.eval_zw)?;

    let e_scalar = -scalars.r0
        + scalars.v_powers[1] * eval_a
        + scalars.v_powers[2] * eval_b
        + scalars.v_powers[3] * eval_c
        + scalars.v_powers[4] * eval_s1
        + scalars.v_powers[5] * eval_s2
        + scalars.u * eval_zw;

    let e_bytes = fr_to_canonical_bytes(&e_scalar);
    let g1_gen = g1_generator_bytes();
    scalar_mul_g1(backend, &g1_gen, &e_bytes)
}

/// Build A1 = Wxi + u · Wxiω.
pub fn compute_a1<B: SyscallBackend + ?Sized>(
    backend: &B,
    proof: &PlonkProof<'_>,
    scalars: &ComputedScalars,
) -> Result<[u8; 64], OnChainError> {
    let u_wxiw = scalar_mul_g1(backend, proof.w_xiw, &fr_to_canonical_bytes(&scalars.u))?;
    let mut wxi_arr = [0u8; 64];
    if proof.w_xi.len() != 64 {
        return Err(OnChainError::InvalidPointEncoding);
    }
    wxi_arr.copy_from_slice(proof.w_xi);
    add_g1(backend, &wxi_arr, &u_wxiw)
}

/// Build B1 = ξ·Wxi + (u·ξ·ω)·Wxiω + F - E.
pub fn compute_b1<B: SyscallBackend + ?Sized>(
    backend: &B,
    proof: &PlonkProof<'_>,
    scalars: &ComputedScalars,
    f: &[u8; 64],
    e: &[u8; 64],
) -> Result<[u8; 64], OnChainError> {
    let xi_bytes = fr_to_canonical_bytes(&scalars.xi);
    let xi_wxi = scalar_mul_g1(backend, proof.w_xi, &xi_bytes)?;
    let u_xi_omega = scalars.u * scalars.xi * scalars.omega;
    let u_xi_omega_bytes = fr_to_canonical_bytes(&u_xi_omega);
    let u_xi_omega_wxiw = scalar_mul_g1(backend, proof.w_xiw, &u_xi_omega_bytes)?;
    let openings = add_g1(backend, &xi_wxi, &u_xi_omega_wxiw)?;
    let openings_plus_f = add_g1(backend, &openings, f)?;
    let neg_e = negate_g1(e);
    add_g1(backend, &openings_plus_f, &neg_e)
}

/// Call `alt_bn128_pairing` with the 2-pair input and assert the
/// result byte is 0x01.
///
/// Pairing equation:  e(-A1, X_2) · e(B1, [1]_2) = 1
pub fn verify_pairing<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &PlonkVerifyingKey,
    a1: &[u8; 64],
    b1: &[u8; 64],
) -> Result<(), OnChainError> {
    let neg_a1 = negate_g1(a1);
    let g2_gen = g2_generator_bytes();

    let mut pairing_input: Vec<u8> = Vec::with_capacity(2 * 192);
    // Pair 1: (-A1, X_2)
    pairing_input.extend_from_slice(&neg_a1);
    pairing_input.extend_from_slice(&vk.x2_g2);
    // Pair 2: (B1, [1]_2)
    pairing_input.extend_from_slice(b1);
    pairing_input.extend_from_slice(&g2_gen);

    let result = backend.alt_bn128_group_op(
        AltBn128Op::Pairing,
        InputEndianness::BigEndian,
        &pairing_input,
    )?;
    if result.len() != 32 || result[31] != 0x01 {
        return Err(OnChainError::PairingCheckFailed);
    }
    Ok(())
}

/// **Session 94 — ADR-0006-named alias for [`verify_pairing`].**
///
/// PLONK's KZG batched-opening pairing identity:
///
/// ```text
/// e(-A1, X_2) · e(B1, [1]_2) = 1
/// ```
///
/// where `A1` and `B1` are the prover-side and verifier-side
/// linearization MSM outputs (computed by the upstream
/// `compute_a1` / `compute_b1` primitives). A satisfying proof
/// produces a pairing product that equals the Fq12 multiplicative
/// identity (the syscall's 32-byte payload ends in `0x01`); any
/// divergence is rejected as [`OnChainError::PairingCheckFailed`].
///
/// This is the audit-grade "is the prover's batched opening
/// consistent with the linearization commitment at the evaluation
/// point ξ?" check — the **only** soundness boundary in PLONK's
/// final verification step (the rest of the verifier is parsing,
/// challenge derivation, and MSM assembly).
///
/// Sessions ≤93 exposed the soundness check as `verify_pairing`,
/// which has a domain-neutral name. Session 94 adds this
/// ADR-0006-named alias following the recipe codified in
/// [docs/adr/0006-verifier-audit-gate-pattern.md] so external
/// auditors can grep `pub fn verify_<verifier>_*` to find every
/// soundness boundary across the workspace consistently. The two
/// names are byte-identical wrappers; either can be called.
///
/// Mirrors session 93's `verify_groth16_pairing_identity` for
/// the Phase-2 sister verifier.
///
/// ## Inputs
///
/// - `backend` — the syscall backend implementing `alt_bn128_group_op`.
/// - `vk` — the PLONK verifying key (used for `vk.x2_g2`, the SRS G2
///   element).
/// - `a1, b1` — the prover-side and verifier-side G1 linearization
///   MSM outputs computed upstream.
///
/// ## Errors
///
/// - [`OnChainError::PairingCheckFailed`] — the pairing product is
///   not the Fq12 identity, OR the syscall returned an unexpected
///   payload length.
/// - Syscall errors propagated from `alt_bn128_group_op`.
pub fn verify_plonk_pairing_identity<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &PlonkVerifyingKey,
    a1: &[u8; 64],
    b1: &[u8; 64],
) -> Result<(), OnChainError> {
    verify_pairing(backend, vk, a1, b1)
}

/// The orchestrated verifier body — called from `PlonkKzgBn254::verify`.
#[inline(never)]
pub fn finalize_verify<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof<'_>,
    challenges: &RoundChallenges,
    public_inputs_bytes: &[u8],
) -> Result<(), OnChainError> {
    let scalars = ComputedScalars::derive(challenges, vk, proof, public_inputs_bytes)?;
    let d = compute_d(backend, vk, proof, &scalars)?;
    let f = compute_f(backend, vk, proof, &scalars, &d)?;
    let e = compute_e(backend, proof, &scalars)?;
    let a1 = compute_a1(backend, proof, &scalars)?;
    let b1 = compute_b1(backend, proof, &scalars, &f, &e)?;
    verify_pairing(backend, vk, &a1, &b1)
}

// Suppress unused-import warning for Zero in certain feature combinations
// that only use the arithmetic trait re-exports from `Field`/`One`.
#[allow(dead_code)]
const _: fn() = || {
    let _ = Fr::zero();
};

#[cfg(test)]
mod tests {
    // ───────────────────────────────────────────────────────────────────
    // Session 94 — verify_plonk_pairing_identity audit-gate coverage.
    //
    // The Phase-2 sister of session 93's Groth16 work. Same
    // ProgrammablePairingBackend testing pattern, just routed through
    // the PLONK gate signature.
    // ───────────────────────────────────────────────────────────────────

    use super::*;
    use crate::canonical::sizes::{FR_LEN, G1_LEN, G2_LEN};
    use mosaic_core::syscall::SyscallBackend;

    fn dummy_vk() -> PlonkVerifyingKey {
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
            n_public: 1,
        }
    }

    /// Backend that returns a programmable pairing-check verdict.
    /// Mirror of the session-93 helper in mosaic-groth16.
    struct ProgrammablePairingBackend {
        verdict_byte: u8,
    }

    impl SyscallBackend for ProgrammablePairingBackend {
        fn alt_bn128_group_op(
            &self,
            op: AltBn128Op,
            _: InputEndianness,
            _: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            match op {
                AltBn128Op::Pairing => {
                    let mut out = alloc::vec![0u8; 32];
                    out[31] = self.verdict_byte;
                    Ok(out)
                }
                AltBn128Op::G1Add | AltBn128Op::G1Mul => {
                    Ok(alloc::vec![0u8; G1_LEN])
                }
            }
        }
        fn alt_bn128_compression(
            &self,
            _: mosaic_core::syscall::AltBn128Compress,
            _: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            Err(OnChainError::AltBn128CompressionSyscallFailed)
        }
        fn poseidon(
            &self,
            _: mosaic_core::syscall::PoseidonParameters,
            _: InputEndianness,
            _: &[&[u8]],
        ) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::PoseidonSyscallFailed)
        }
        fn sha256(&self, _: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::Sha256SyscallFailed)
        }
        fn keccak256(&self, _: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::Keccak256SyscallFailed)
        }
    }

    /// Programmable backend reports pairing success ⇒ gate accepts.
    #[test]
    fn audit_gate_accepts_when_pairing_returns_success_byte() {
        let backend = ProgrammablePairingBackend { verdict_byte: 0x01 };
        let vk = dummy_vk();
        let a1 = [0u8; 64];
        let b1 = [0u8; 64];
        verify_plonk_pairing_identity(&backend, &vk, &a1, &b1)
            .expect("pairing-success backend → gate accepts");
    }

    /// Programmable backend reports pairing failure ⇒ gate rejects.
    #[test]
    fn audit_gate_rejects_when_pairing_returns_failure_byte() {
        let backend = ProgrammablePairingBackend { verdict_byte: 0x00 };
        let vk = dummy_vk();
        let a1 = [0u8; 64];
        let b1 = [0u8; 64];
        let res = verify_plonk_pairing_identity(&backend, &vk, &a1, &b1);
        assert!(
            matches!(res, Err(OnChainError::PairingCheckFailed)),
            "pairing-failure verdict must reject as PairingCheckFailed; got {res:?}",
        );
    }

    /// Sweep representative non-`0x01` verdict bytes.
    #[test]
    fn audit_gate_rejects_any_non_one_verdict_byte() {
        let vk = dummy_vk();
        let a1 = [0u8; 64];
        let b1 = [0u8; 64];
        for verdict in [0x00u8, 0x02, 0x42, 0x7F, 0xFE, 0xFF] {
            let backend = ProgrammablePairingBackend { verdict_byte: verdict };
            let res = verify_plonk_pairing_identity(&backend, &vk, &a1, &b1);
            assert!(
                matches!(res, Err(OnChainError::PairingCheckFailed)),
                "verdict byte 0x{verdict:02X} must reject; got {res:?}",
            );
        }
    }

    /// Wrong-length pairing payload ⇒ reject.
    #[test]
    fn audit_gate_rejects_wrong_length_pairing_payload() {
        struct WrongLengthBackend;
        impl SyscallBackend for WrongLengthBackend {
            fn alt_bn128_group_op(
                &self,
                op: AltBn128Op,
                _: InputEndianness,
                _: &[u8],
            ) -> Result<Vec<u8>, OnChainError> {
                if matches!(op, AltBn128Op::Pairing) {
                    // Return 16 bytes — last byte happens to be `0x01`
                    // but length is wrong; gate must reject.
                    let mut out = alloc::vec![0u8; 16];
                    out[15] = 0x01;
                    Ok(out)
                } else {
                    Ok(alloc::vec![0u8; G1_LEN])
                }
            }
            fn alt_bn128_compression(
                &self,
                _: mosaic_core::syscall::AltBn128Compress,
                _: &[u8],
            ) -> Result<Vec<u8>, OnChainError> {
                Err(OnChainError::AltBn128CompressionSyscallFailed)
            }
            fn poseidon(
                &self,
                _: mosaic_core::syscall::PoseidonParameters,
                _: InputEndianness,
                _: &[&[u8]],
            ) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::PoseidonSyscallFailed)
            }
            fn sha256(&self, _: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::Sha256SyscallFailed)
            }
            fn keccak256(&self, _: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::Keccak256SyscallFailed)
            }
        }
        let vk = dummy_vk();
        let a1 = [0u8; 64];
        let b1 = [0u8; 64];
        let res = verify_plonk_pairing_identity(&WrongLengthBackend, &vk, &a1, &b1);
        assert!(
            matches!(res, Err(OnChainError::PairingCheckFailed)),
            "wrong-length pairing payload must reject; got {res:?}",
        );
    }

    /// Backend syscall error ⇒ propagates through `?`.
    #[test]
    fn audit_gate_propagates_syscall_error() {
        struct FailingBackend;
        impl SyscallBackend for FailingBackend {
            fn alt_bn128_group_op(
                &self,
                _: AltBn128Op,
                _: InputEndianness,
                _: &[u8],
            ) -> Result<Vec<u8>, OnChainError> {
                Err(OnChainError::AltBn128SyscallFailed)
            }
            fn alt_bn128_compression(
                &self,
                _: mosaic_core::syscall::AltBn128Compress,
                _: &[u8],
            ) -> Result<Vec<u8>, OnChainError> {
                Err(OnChainError::AltBn128CompressionSyscallFailed)
            }
            fn poseidon(
                &self,
                _: mosaic_core::syscall::PoseidonParameters,
                _: InputEndianness,
                _: &[&[u8]],
            ) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::PoseidonSyscallFailed)
            }
            fn sha256(&self, _: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::Sha256SyscallFailed)
            }
            fn keccak256(&self, _: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::Keccak256SyscallFailed)
            }
        }
        let vk = dummy_vk();
        let a1 = [0u8; 64];
        let b1 = [0u8; 64];
        let res = verify_plonk_pairing_identity(&FailingBackend, &vk, &a1, &b1);
        assert!(
            matches!(res, Err(OnChainError::AltBn128SyscallFailed)),
            "syscall failure must propagate, not collapse to PairingCheckFailed; got {res:?}",
        );
    }

    /// `verify_plonk_pairing_identity` and `verify_pairing` are
    /// byte-equivalent wrappers — exercising both with the same
    /// backend + inputs yields identical results.
    #[test]
    fn audit_gate_equivalent_to_verify_pairing() {
        for verdict in [0x00u8, 0x01, 0x42, 0xFF] {
            let backend = ProgrammablePairingBackend { verdict_byte: verdict };
            let vk = dummy_vk();
            let a1 = [0u8; 64];
            let b1 = [0u8; 64];
            let r_alias = verify_plonk_pairing_identity(&backend, &vk, &a1, &b1);
            let r_orig = verify_pairing(&backend, &vk, &a1, &b1);
            // Both must agree on Ok(()) vs Err(PairingCheckFailed).
            assert_eq!(
                r_alias.is_ok(),
                r_orig.is_ok(),
                "verdict 0x{verdict:02X}: alias = {r_alias:?}, orig = {r_orig:?}",
            );
        }
    }
}
