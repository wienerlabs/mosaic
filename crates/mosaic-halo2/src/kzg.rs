//! KZG opening verifier (scaffold).
//!
//! Halo2 ships a **two-point batched** opening `(W_ξ, W_ξω)` — one
//! per evaluation site in the grand-product-style argument. This
//! module's scaffold only exercises the single-point W_ξ path to keep
//! the wiring minimal while structurally correct; session 4e pins the
//! full two-point batching against Espresso/PSE reference fixtures.
//!
//! ## Pairing check
//!
//! ```text
//! e(C - [y]_G1 + ξ · W_ξ, [1]_G2) · e(-W_ξ, [x]_G2) ?= 1
//! ```
//!
//! where:
//! - `C` = batched commitment (scaffold: single `permutation_z` commit
//!   from the proof).
//! - `y` = claimed evaluation (scaffold: `evaluations[0]`).
//! - `ξ` = evaluation point (challenge from transcript).
//!
//! Same bilinearity rewrite as `mosaic-hyperplonk::kzg` — avoids
//! on-chain G2 scalar mul.
//!
//! ## Scaffold limitations
//!
//! - **Single-commitment opening** vs real Halo2's multi-poly batched
//!   opening. Session 4e extends to the full MSM over advice +
//!   permutation + quotient + VK preprocessing commits.
//! - **No ξω second opening** — the canonical W_ξω field is parsed but
//!   unused until session 4e.
//! - No on-chain ω computation (needs domain generator from `k`).

use crate::canonical::{
    sizes::{FR_LEN, G1_LEN},
    Halo2KzgProof, Halo2KzgVerifyingKey,
};
use alloc::vec::Vec;
use ark_bn254::Fr;
use mosaic_core::{
    syscall::{AltBn128Op, InputEndianness, SyscallBackend},
    OnChainError,
};
use mosaic_zk_primitives::{
    field::{fr_from_canonical_bytes, fr_to_canonical_bytes},
    g1_consts::{g1_generator_bytes, g2_generator_bytes},
    msm::{add_g1, msm_g1, negate_g1, scalar_mul_g1, verify_two_pair_pairing},
};

/// Scaffold single-point KZG opening check.
///
/// Verifies `e(C - y·G1 + ξ·W_ξ, G2) · e(-W_ξ, x2_G2) == 1` where
/// `C = proof.permutation_z` and `y = proof.evaluations[0]`.
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if proof evaluations are
///   empty (need at least one Fr for the opening value).
/// - [`OnChainError::InvalidPointEncoding`] if permutation_z or w_xi
///   is malformed.
/// - [`OnChainError::PublicInputOutOfRange`] if the evaluation Fr is
///   out of range.
/// - [`OnChainError::PairingCheckFailed`] on a false pairing result.
pub fn verify_opening_scaffold<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &Halo2KzgVerifyingKey,
    proof: &Halo2KzgProof<'_>,
    xi: &Fr,
) -> Result<(), OnChainError> {
    if proof.evaluations.len() < FR_LEN {
        return Err(OnChainError::ProofLengthMismatch);
    }
    if proof.permutation_z.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    if proof.w_xi.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }

    // Claimed evaluation: first Fr in the evaluations bundle.
    let y = fr_from_canonical_bytes(&proof.evaluations[..FR_LEN])?;
    let y_bytes = fr_to_canonical_bytes(&y);

    // C - y·G1.
    let g1_gen = g1_generator_bytes();
    let y_g1 = scalar_mul_g1(backend, &g1_gen, &y_bytes)?;
    let neg_y_g1 = negate_g1(&y_g1);

    let mut c_arr = [0u8; G1_LEN];
    c_arr.copy_from_slice(proof.permutation_z);
    let c_minus_y = add_g1(backend, &c_arr, &neg_y_g1)?;

    // ξ·W_ξ.
    let xi_bytes = fr_to_canonical_bytes(xi);
    let mut wxi_arr = [0u8; G1_LEN];
    wxi_arr.copy_from_slice(proof.w_xi);
    let xi_wxi = scalar_mul_g1(backend, &wxi_arr, &xi_bytes)?;

    // A1 = C - y·G1 + ξ·W_ξ.
    let a1 = add_g1(backend, &c_minus_y, &xi_wxi)?;

    // -W_ξ for the second pair.
    let neg_wxi = negate_g1(&wxi_arr);

    // Pairing:
    //   Pair 1: (A1, [1]_G2)
    //   Pair 2: (-W_ξ, [x]_G2)
    verify_two_pair_pairing(backend, &a1, &g2_generator_bytes(), &neg_wxi, &vk.x2_g2)
}

/// Session-16: two-point batched KZG opening.
///
/// Halo2 verifies two opening proofs simultaneously — one at `ξ`
/// (most polynomials) and one at `ξω = ξ · ω` (shift-requiring
/// polynomials like the permutation grand-product `z(ξω)`). The
/// verifier combines both via a batching challenge `u` squeezed
/// from the transcript after absorbing both opening commitments:
///
/// ```text
/// A1 = C_ξ - y_ξ·G1 + ξ·W_ξ
/// A2 = C_ξω - y_ξω·G1 + ξω·W_ξω
/// A_batched = A1 + u·A2
/// W_batched = W_ξ + u·W_ξω
///
/// e(A_batched, [1]_2) · e(-W_batched, [x]_2) ?= 1
/// ```
///
/// Matches the standard Halo2-KZG reduction from PSE's
/// `halo2_proofs::plonk::verify_proof`. Single 2-pair pairing
/// syscall vs two independent pairings.
///
/// ## Scaffold choices
///
/// - `C_ξ` and `C_ξω` both use `proof.permutation_z` (single-
///   commitment scaffold). Real Halo2 does a full MSM over all
///   committed polys weighted by a per-poly batching challenge `v`.
/// - `y_ξ` = `evaluations[Z]`, `y_ξω` = `evaluations[Z_NEXT]`.
/// - `u` is caller-provided — session 16 derives it inline in
///   `verifier.rs` via transcript absorb/squeeze after the
///   session-4 challenge set. Future session may promote it to a
///   `Halo2Challenges` field.
///
/// ## Errors
///
/// - `ProofLengthMismatch`: `proof.evaluations` shorter than
///   `FIXED_SLOTS × FR_LEN` (can't read `Z` and `Z_NEXT`).
/// - `InvalidPointEncoding`: `permutation_z`, `w_xi`, or `w_xiw`
///   not 64 bytes.
/// - `PublicInputOutOfRange`: evaluation Fr out of BN254 scalar range.
/// - `PairingCheckFailed`: the batched pairing doesn't reduce to
///   the Fq12 identity.
#[allow(clippy::too_many_arguments)]
pub fn verify_two_point_opening_scaffold<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &Halo2KzgVerifyingKey,
    proof: &Halo2KzgProof<'_>,
    xi: &Fr,
    xi_omega: &Fr,
    u: &Fr,
) -> Result<(), OnChainError> {
    use crate::bundle::idx;
    const BUNDLE_MIN: usize = (idx::Z_NEXT + 1) * FR_LEN;
    if proof.evaluations.len() < BUNDLE_MIN {
        return Err(OnChainError::ProofLengthMismatch);
    }
    if proof.permutation_z.len() != G1_LEN
        || proof.w_xi.len() != G1_LEN
        || proof.w_xiw.len() != G1_LEN
    {
        return Err(OnChainError::InvalidPointEncoding);
    }

    // Parse the two evaluation points.
    let y_xi = fr_from_canonical_bytes(
        &proof.evaluations[idx::Z * FR_LEN..(idx::Z + 1) * FR_LEN],
    )?;
    let y_xi_omega = fr_from_canonical_bytes(
        &proof.evaluations[idx::Z_NEXT * FR_LEN..(idx::Z_NEXT + 1) * FR_LEN],
    )?;

    // C - y·G1 for each opening point.
    let g1_gen = g1_generator_bytes();
    let y_xi_g1 = scalar_mul_g1(backend, &g1_gen, &fr_to_canonical_bytes(&y_xi))?;
    let y_xi_omega_g1 =
        scalar_mul_g1(backend, &g1_gen, &fr_to_canonical_bytes(&y_xi_omega))?;

    let mut c_arr = [0u8; G1_LEN];
    c_arr.copy_from_slice(proof.permutation_z);

    let c_minus_y_xi = add_g1(backend, &c_arr, &negate_g1(&y_xi_g1))?;
    let c_minus_y_xi_omega = add_g1(backend, &c_arr, &negate_g1(&y_xi_omega_g1))?;

    // ξ·W_ξ  +  ξω·W_ξω
    let mut wxi_arr = [0u8; G1_LEN];
    wxi_arr.copy_from_slice(proof.w_xi);
    let mut wxiw_arr = [0u8; G1_LEN];
    wxiw_arr.copy_from_slice(proof.w_xiw);

    let xi_wxi = scalar_mul_g1(backend, &wxi_arr, &fr_to_canonical_bytes(xi))?;
    let xi_omega_wxiw =
        scalar_mul_g1(backend, &wxiw_arr, &fr_to_canonical_bytes(xi_omega))?;

    let a1 = add_g1(backend, &c_minus_y_xi, &xi_wxi)?;
    let a2 = add_g1(backend, &c_minus_y_xi_omega, &xi_omega_wxiw)?;

    // Batch: A_batched = A1 + u·A2.
    let u_bytes = fr_to_canonical_bytes(u);
    let u_a2 = scalar_mul_g1(backend, &a2, &u_bytes)?;
    let a_batched = add_g1(backend, &a1, &u_a2)?;

    // Batch: W_batched = W_ξ + u·W_ξω.
    let u_wxiw = scalar_mul_g1(backend, &wxiw_arr, &u_bytes)?;
    let w_batched = add_g1(backend, &wxi_arr, &u_wxiw)?;
    let neg_w_batched = negate_g1(&w_batched);

    // Pairing: e(A_batched, [1]_2) · e(-W_batched, [x]_2) = 1.
    verify_two_pair_pairing(
        backend,
        &a_batched,
        &g2_generator_bytes(),
        &neg_w_batched,
        &vk.x2_g2,
    )
}

/// Session-17: multi-poly batched two-point KZG opening.
///
/// Upgrades the session-16 scaffold from single-commitment batching
/// (`C_ξ = C_ξω = permutation_z`) to the real Halo2 convention where
/// a `v` batching challenge collapses the full set of committed
/// polynomials into two batched commitments — one per opening point.
///
/// ```text
/// // v-powers: [1, v, v^2, …, v^{m-1}]
/// C_ξ_batched   = Σ_i v^i · commits_at_ξ[i]
/// y_ξ_batched   = Σ_i v^i · evals_at_ξ[i]
/// C_ξω_batched  = Σ_j v^j · commits_at_ξω[j]
/// y_ξω_batched  = Σ_j v^j · evals_at_ξω[j]
///
/// A1 = C_ξ_batched  - y_ξ_batched·G1  + ξ ·W_ξ
/// A2 = C_ξω_batched - y_ξω_batched·G1 + ξω·W_ξω
/// A_batched = A1 + u·A2
/// W_batched = W_ξ + u·W_ξω
/// e(A_batched, [1]_2) · e(-W_batched, [x]_2) ?= 1
/// ```
///
/// Matches PSE `halo2_proofs::plonk::verifier::verify_proof`
/// semantics: any committed poly evaluated at the given point
/// contributes at the MSM step, so tampering with *any* commit or
/// evaluation propagates to the batched point → pairing check.
///
/// ## Scaffold mapping
///
/// This function accepts pre-collected commit/eval slices; the
/// caller pairs each commit to its corresponding evaluation value
/// and picks the evaluation point. The typical Halo2 pairing is:
///
/// - **At ξ**: advice commits ↔ wire evals, lookup commits ↔
///   lookup evals, permutation_z ↔ `Z`, quotient chunks ↔
///   quotient evals. Fixed/selector commits from the VK are
///   paired with their selector evals.
/// - **At ξω**: permutation_z ↔ `Z_NEXT` (the only shifted
///   polynomial in vanilla Halo2).
///
/// ## Errors
///
/// - [`OnChainError::PublicInputCountMismatch`]: commit/eval slice
///   length disagreement at either opening point, or empty xi slice.
/// - [`OnChainError::InvalidPointEncoding`]: any commit, `w_xi`, or
///   `w_xiw` is not 64 bytes.
/// - [`OnChainError::PairingCheckFailed`]: batched pairing fails.
#[allow(clippy::too_many_arguments)]
pub fn verify_two_point_opening_multipoly<B: SyscallBackend + ?Sized>(
    backend: &B,
    vk: &Halo2KzgVerifyingKey,
    commits_xi: &[&[u8]],
    evals_xi: &[Fr],
    commits_xi_omega: &[&[u8]],
    evals_xi_omega: &[Fr],
    w_xi: &[u8],
    w_xi_omega: &[u8],
    xi: &Fr,
    xi_omega: &Fr,
    v: &Fr,
    u: &Fr,
) -> Result<(), OnChainError> {
    if commits_xi.len() != evals_xi.len() || commits_xi.is_empty() {
        return Err(OnChainError::PublicInputCountMismatch);
    }
    if commits_xi_omega.len() != evals_xi_omega.len() || commits_xi_omega.is_empty() {
        return Err(OnChainError::PublicInputCountMismatch);
    }
    if w_xi.len() != G1_LEN || w_xi_omega.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    for c in commits_xi.iter().chain(commits_xi_omega.iter()) {
        if c.len() != G1_LEN {
            return Err(OnChainError::InvalidPointEncoding);
        }
    }

    // v-powers: [1, v, v^2, …, v^{m-1}] for the longer side.
    let max_len = commits_xi.len().max(commits_xi_omega.len());
    let mut v_powers = Vec::with_capacity(max_len);
    let mut acc = Fr::from(1u64);
    for _ in 0..max_len {
        v_powers.push(acc);
        acc *= v;
    }

    // MSM at ξ: C_batched = Σ v^i · commits_xi[i]; y_batched = Σ v^i · evals_xi[i].
    let scalars_xi: Vec<[u8; FR_LEN]> = v_powers[..commits_xi.len()]
        .iter()
        .map(fr_to_canonical_bytes)
        .collect();
    let c_xi_batched = msm_g1(backend, commits_xi, &scalars_xi)?;
    let mut y_xi_batched = Fr::from(0u64);
    for (i, e) in evals_xi.iter().enumerate() {
        y_xi_batched += v_powers[i] * e;
    }

    // MSM at ξω.
    let scalars_xi_omega: Vec<[u8; FR_LEN]> = v_powers[..commits_xi_omega.len()]
        .iter()
        .map(fr_to_canonical_bytes)
        .collect();
    let c_xi_omega_batched = msm_g1(backend, commits_xi_omega, &scalars_xi_omega)?;
    let mut y_xi_omega_batched = Fr::from(0u64);
    for (i, e) in evals_xi_omega.iter().enumerate() {
        y_xi_omega_batched += v_powers[i] * e;
    }

    // From here, the pairing reduction matches session-16 exactly,
    // substituting the batched (C, y) pairs for the single-commit
    // scaffold choice.
    let g1_gen = g1_generator_bytes();
    let y_xi_g1 =
        scalar_mul_g1(backend, &g1_gen, &fr_to_canonical_bytes(&y_xi_batched))?;
    let y_xi_omega_g1 = scalar_mul_g1(
        backend,
        &g1_gen,
        &fr_to_canonical_bytes(&y_xi_omega_batched),
    )?;

    let c_minus_y_xi = add_g1(backend, &c_xi_batched, &negate_g1(&y_xi_g1))?;
    let c_minus_y_xi_omega =
        add_g1(backend, &c_xi_omega_batched, &negate_g1(&y_xi_omega_g1))?;

    let mut wxi_arr = [0u8; G1_LEN];
    wxi_arr.copy_from_slice(w_xi);
    let mut wxiw_arr = [0u8; G1_LEN];
    wxiw_arr.copy_from_slice(w_xi_omega);

    let xi_wxi = scalar_mul_g1(backend, &wxi_arr, &fr_to_canonical_bytes(xi))?;
    let xi_omega_wxiw =
        scalar_mul_g1(backend, &wxiw_arr, &fr_to_canonical_bytes(xi_omega))?;

    let a1 = add_g1(backend, &c_minus_y_xi, &xi_wxi)?;
    let a2 = add_g1(backend, &c_minus_y_xi_omega, &xi_omega_wxiw)?;

    let u_bytes = fr_to_canonical_bytes(u);
    let u_a2 = scalar_mul_g1(backend, &a2, &u_bytes)?;
    let a_batched = add_g1(backend, &a1, &u_a2)?;
    let u_wxiw = scalar_mul_g1(backend, &wxiw_arr, &u_bytes)?;
    let w_batched = add_g1(backend, &wxi_arr, &u_wxiw)?;
    let neg_w_batched = negate_g1(&w_batched);

    verify_two_pair_pairing(
        backend,
        &a_batched,
        &g2_generator_bytes(),
        &neg_w_batched,
        &vk.x2_g2,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sizes::FIXED_HEADER_LEN;
    use alloc::vec;
    use mosaic_core::syscall::host::HostBackend;

    fn valid_g2_vk() -> Halo2KzgVerifyingKey {
        Halo2KzgVerifyingKey {
            k: 4,
            n_instances: 0,
            n_advice: 1,
            n_fixed: 0,
            x2_g2: g2_generator_bytes(),
            omega_fr: [0u8; 32],
            fixed_commits: vec![],
            permutation_commits: vec![],
        }
    }

    fn minimal_proof_bytes() -> alloc::vec::Vec<u8> {
        // 1 advice, 0 lookups, 1 quotient, 1 eval.
        let n_advice: u32 = 1;
        let n_lookups: u32 = 0;
        let n_quotient: u32 = 1;
        let n_evals: u32 = 1;
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
        buf
    }

    #[test]
    fn all_zero_trivially_passes_pairing() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();

        let r = verify_opening_scaffold(&backend, &vk, &proof, &Fr::from(0u64));
        // Zero permutation_z + zero eval + zero W_xi → pairing of
        // identities = 1 trivially.
        assert!(r.is_ok(), "zero-proof pairing should pass, got {r:?}");
    }

    /// Build a minimal proof with 10 Fr evaluations (enough to cover
    /// `idx::Z` and `idx::Z_NEXT`) so `verify_two_point_opening_scaffold`
    /// can parse its bundle.
    fn two_point_proof_bytes() -> alloc::vec::Vec<u8> {
        let n_advice: u32 = 1;
        let n_lookups: u32 = 0;
        let n_quotient: u32 = 1;
        let n_evals: u32 = 10; // covers up through idx::Z_NEXT = 9
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
        buf
    }

    /// Session-16 dedicated tamper test: set `z_next_eval` (the
    /// y_xiω value consumed by the two-point opening) to 1 while
    /// leaving everything else zero. With permutation_z = 0,
    /// w_xi = 0, w_xiw = 0, z_eval = 0: the ξω-side of the pairing
    /// produces `A2 = 0 - 1·G1 + ξω·0 = -G1`, so the batched
    /// pairing becomes `e(u·(-G1), G2) · e(0, x·G2) = e(G1, G2)^(-u) ≠ 1`
    /// for any non-zero `u` → `PairingCheckFailed`.
    ///
    /// This exercises the new two-point KZG path directly (session 16's
    /// flagged coverage gap in `docs/phase3-soundness.md`).
    #[test]
    fn two_point_rejects_tampered_z_next_eval() {
        use crate::bundle::idx;
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let mut proof_buf = two_point_proof_bytes();

        // Set z_next evaluation = 1 (last byte of its Fr slot).
        // Evaluations start at FIXED + n_advice·G1 + n_lookups·G1 +
        //   perm_z_G1 + n_quotient·G1 = 16 + 64 + 0 + 64 + 64 = 208.
        let eval_base = FIXED_HEADER_LEN
            + 1 * G1_LEN
            + 0 * G1_LEN
            + G1_LEN
            + 1 * G1_LEN;
        let z_next_off = eval_base + idx::Z_NEXT * FR_LEN;
        proof_buf[z_next_off + FR_LEN - 1] = 1;

        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();

        // Use non-zero ξ and u so the tamper propagates to the pairing.
        let xi = Fr::from(7u64);
        let xi_omega = Fr::from(11u64);
        let u = Fr::from(3u64);
        let r =
            verify_two_point_opening_scaffold(&backend, &vk, &proof, &xi, &xi_omega, &u);
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "tampered z_next_eval should fail batched pairing, got {r:?}",
        );
    }

    #[test]
    fn rejects_short_evaluations() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let proof_parsed = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let bad_proof = Halo2KzgProof {
            evaluations: &[],
            ..proof_parsed
        };
        let r = verify_opening_scaffold(&backend, &vk, &bad_proof, &Fr::from(0u64));
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn rejects_short_w_xi() {
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let proof_buf = minimal_proof_bytes();
        let proof_parsed = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let bad_proof = Halo2KzgProof {
            w_xi: &proof_parsed.w_xi[..63],
            ..proof_parsed
        };
        let r = verify_opening_scaffold(&backend, &vk, &bad_proof, &Fr::from(0u64));
        assert!(matches!(r, Err(OnChainError::InvalidPointEncoding)));
    }

    #[test]
    fn nonzero_commit_with_wrong_opening_fails() {
        // Set permutation_z = G1_generator, eval = 1, W_xi = G1_generator,
        // ξ = 2. Then A1 = G1 - G1 + 2·G1 = 2·G1, Pair1 = e(2G1, G2),
        // Pair2 = e(-G1, G2) (since x = 1 in scaffold SRS). Product =
        // e(G1, G2) ≠ 1 → fails.
        let backend = HostBackend::new();
        let vk = valid_g2_vk();
        let mut proof_buf = minimal_proof_bytes();

        let g1_gen = g1_generator_bytes();
        // permutation_z offset: FIXED + n_advice·G1 + n_lookups·G1
        // = 16 + 64 + 0 = 80.
        let z_off = FIXED_HEADER_LEN + G1_LEN;
        proof_buf[z_off..z_off + G1_LEN].copy_from_slice(&g1_gen);
        // First evaluation (Fr = 1): offset = z_off + G1_LEN (perm_z) +
        // n_quotient·G1 = 80 + 64 + 64 = 208; last byte of Fr = 1.
        let eval_off = z_off + G1_LEN + G1_LEN;
        proof_buf[eval_off + FR_LEN - 1] = 1;
        // W_xi at the end, second-to-last G1.
        let w_xi_off = proof_buf.len() - 2 * G1_LEN;
        proof_buf[w_xi_off..w_xi_off + G1_LEN].copy_from_slice(&g1_gen);

        let proof = Halo2KzgProof::from_bytes(&proof_buf).unwrap();
        let r = verify_opening_scaffold(&backend, &vk, &proof, &Fr::from(2u64));
        assert!(
            matches!(r, Err(OnChainError::PairingCheckFailed)),
            "expected PairingCheckFailed, got {r:?}",
        );
    }
}
