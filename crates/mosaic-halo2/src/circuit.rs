//! Circuit-specific expression evaluators at the vanishing point ξ.
//!
//! Halo2's vanishing identity decomposes into three circuit-specific
//! terms summed with `y`-powers:
//!
//! ```text
//! gate_expr(ξ)  +  y · perm_expr(ξ)  +  y² · lookup_expr(ξ)
//! ```
//!
//! Each term is a polynomial-at-point expression computed from:
//! - Per-gate / per-table / per-lookup evaluations sent by the prover.
//! - Challenges `(θ, β, γ)` from the transcript.
//! - Structural constants (identity permutation factors, etc.).
//!
//! This module provides a **single-gate scaffold** targeting the
//! minimum circuit structure we can differential-test against:
//!
//! - One PLONK-style gate (`q_M·a·b` + `q_L·a` + `q_R·b` + `q_O·c` + `q_C`).
//! - One permutation argument over three wires.
//! - One lookup argument (log-derivative form).
//!
//! Richer custom-gate families and multi-lookup circuits land in
//! session 4e when real fixtures drive the extension.

use ark_bn254::Fr;
use ark_ff::{Field, Zero};
use mosaic_core::OnChainError;

// ---------------------------------------------------------------------
// Gate expression (PLONK-style arithmetic gate)
// ---------------------------------------------------------------------

/// Wire evaluations at `ξ`: `a(ξ), b(ξ), c(ξ)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WireEvals {
    /// Left wire.
    pub a: Fr,
    /// Right wire.
    pub b: Fr,
    /// Output wire.
    pub c: Fr,
}

/// Selector polynomial evaluations at `ξ`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SelectorEvals {
    /// Multiplication selector.
    pub q_m: Fr,
    /// Left linear selector.
    pub q_l: Fr,
    /// Right linear selector.
    pub q_r: Fr,
    /// Output linear selector.
    pub q_o: Fr,
    /// Constant selector.
    pub q_c: Fr,
}

/// Evaluate the PLONK-style gate expression at ξ:
///
/// ```text
/// gate(ξ) = q_M·a·b + q_L·a + q_R·b + q_O·c + q_C
/// ```
#[must_use]
pub fn gate_expr(wires: &WireEvals, selectors: &SelectorEvals) -> Fr {
    selectors.q_m * wires.a * wires.b
        + selectors.q_l * wires.a
        + selectors.q_r * wires.b
        + selectors.q_o * wires.c
        + selectors.q_c
}

// ---------------------------------------------------------------------
// Permutation argument (PLONK grand-product)
// ---------------------------------------------------------------------

/// Permutation-argument evaluations at `ξ`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PermutationEvals {
    /// Grand-product `z(ξ)`.
    pub z: Fr,
    /// Grand-product `z(ξ·ω)` at the shifted point — needed for the
    /// recurrence `z(X·ω) · den == z(X) · num`.
    pub z_next: Fr,
    /// `σ_1(ξ)` — left-wire permutation commitment evaluation.
    pub sigma_1: Fr,
    /// `σ_2(ξ)` — right-wire permutation.
    pub sigma_2: Fr,
    /// `σ_3(ξ)` — output-wire permutation.
    pub sigma_3: Fr,
}

/// Evaluate the permutation argument at ξ:
///
/// ```text
/// perm(ξ) = z(ξ·ω) · den - z(ξ) · num
///         = z_next · Π_i (a_i + β·σ_i + γ) - z · Π_i (a_i + β·id_i + γ)
/// ```
///
/// where `id_i(ξ)` are identity permutation values. For the scaffold
/// we use `id_1 = ξ, id_2 = k_1·ξ, id_3 = k_2·ξ` with hard-coded
/// cosets `k_1 = 2, k_2 = 3` (matches Groth/PLONK conventions; real
/// Halo2 uses the `k_i` from VK).
///
/// A well-behaved proof has `perm(ξ) = 0` on boundary conditions of
/// the domain; in general `perm(ξ)` contributes to the vanishing
/// identity's RHS as one of the three `y`-weighted terms.
#[must_use]
pub fn permutation_expr(
    wires: &WireEvals,
    perm: &PermutationEvals,
    beta: &Fr,
    gamma: &Fr,
    xi: &Fr,
) -> Fr {
    let k1 = Fr::from(2u64);
    let k2 = Fr::from(3u64);

    // Numerator: z(ξ) · Π (a_i + β·id_i + γ).
    //   id_1 = ξ, id_2 = k_1·ξ, id_3 = k_2·ξ.
    let num = perm.z
        * (wires.a + *beta * xi + gamma)
        * (wires.b + *beta * k1 * xi + gamma)
        * (wires.c + *beta * k2 * xi + gamma);

    // Denominator: z(ξ·ω) · Π (a_i + β·σ_i + γ).
    let den = perm.z_next
        * (wires.a + *beta * perm.sigma_1 + gamma)
        * (wires.b + *beta * perm.sigma_2 + gamma)
        * (wires.c + *beta * perm.sigma_3 + gamma);

    den - num
}

// ---------------------------------------------------------------------
// Lookup argument (log-derivative form)
// ---------------------------------------------------------------------

/// Lookup-argument evaluations at `ξ`.
///
/// Halo2's lookup uses the logUp / log-derivative technique: for each
/// lookup, the prover commits a helper polynomial `m(X)` that encodes
/// the multiplicities of each table row used. At ξ, the verifier
/// checks a rational-function identity relating input, table, and m.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LookupEvals {
    /// Input expression evaluation `input(ξ)`.
    pub input: Fr,
    /// Table column evaluation `table(ξ)`.
    pub table: Fr,
    /// Multiplicity polynomial `m(ξ)`.
    pub m: Fr,
}

/// Evaluate the lookup argument at ξ (log-derivative form):
///
/// ```text
/// lookup(ξ) = m · (table + θ)⁻¹ - (input + θ)⁻¹
/// ```
///
/// A satisfying lookup has this term zero when summed over the domain.
/// The `θ` challenge combines multi-column lookups into a single
/// expression; for single-column lookups (scaffold) it's a simple
/// additive blinder.
///
/// ## Errors
///
/// Returns [`OnChainError::InternalInvariantViolation`] if either
/// `table + θ` or `input + θ` is zero (i.e., would require inverse of
/// zero). Probability is `≈ 2/r` for random θ — negligible in
/// practice but explicit for consensus safety.
pub fn lookup_expr(lookup: &LookupEvals, theta: &Fr) -> Result<Fr, OnChainError> {
    let table_plus_theta = lookup.table + theta;
    let input_plus_theta = lookup.input + theta;

    let table_inv = table_plus_theta
        .inverse()
        .ok_or(OnChainError::InternalInvariantViolation)?;
    let input_inv = input_plus_theta
        .inverse()
        .ok_or(OnChainError::InternalInvariantViolation)?;

    Ok(lookup.m * table_inv - input_inv)
}

// ---------------------------------------------------------------------
// Multi-column lookup (session 85 — Phase-3 lookup arity expansion)
// ---------------------------------------------------------------------

/// Multi-column lookup-argument evaluations at `ξ`.
///
/// Real Halo2 lookups support arity > 1: a single lookup constraint
/// can pair `k` input columns against `k` table columns, all checked
/// simultaneously. The verifier collapses the `k`-arity tuple into a
/// single Fr via the θ challenge before applying the log-derivative
/// identity:
///
/// ```text
/// input_combined(ξ) = Σ_{i=0}^{k-1} θ^i · input_cols[i]
/// table_combined(ξ) = Σ_{i=0}^{k-1} θ^i · table_cols[i]
///
/// lookup(ξ) = m · (table_combined + θ^k)⁻¹ - (input_combined + θ^k)⁻¹
/// ```
///
/// Note: the outer additive blinder uses `θ^k` (one degree past the
/// linear-combination weights) to keep input_combined / table_combined
/// distinguishable from the blinder. For arity 1 this collapses to
/// the basic `lookup_expr` form (`input + θ` blinder, single column),
/// pinned by `multi_column_lookup_arity_1_matches_basic` below.
///
/// Phase-3 audit caveat
///
/// This is the structural per-evaluation-point reduction. Real Halo2
/// log-derivative lookups also need the **sum-over-domain identity**:
///
/// ```text
/// Σ_{X ∈ H}  [ m(X) · (table_combined(X) + θ^k)⁻¹
///            − (input_combined(X) + θ^k)⁻¹ ]   =   0
/// ```
///
/// holding when summed across the trace domain `H`. The vanishing
/// polynomial check `t(ξ) · Z_H(ξ) == combined_expr(ξ)` performed by
/// [`crate::vanishing::vanishing_identity_holds`] enforces this
/// implicitly (the lookup contribution is folded into `combined_expr`
/// with a `y²` weight, then the quotient division handles the
/// sum-to-zero), so the present module's job is the per-row primitive.
///
/// The session-85 docstring previously claimed `Σ_X m(X) = 0` — that
/// is **incorrect**. In a satisfying log-derivative lookup,
/// `Σ_X m(X) = N` (the input row count, since each input row
/// contributes one to the multiplicity of its matching table row).
/// Session 88 corrects the doc and adds an audit-gate function
/// [`verify_multi_column_lookup_identity`] that wraps the per-row
/// reduction with the explicit `== 0` soundness check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiColumnLookupEvals {
    /// `k` input column evaluations at ξ. Empty input is rejected as
    /// `ProofLengthMismatch`.
    pub input_cols: alloc::vec::Vec<Fr>,
    /// `k` table column evaluations at ξ. Length must equal
    /// `input_cols.len()`.
    pub table_cols: alloc::vec::Vec<Fr>,
    /// Multiplicity polynomial evaluation `m(ξ)`.
    pub m: Fr,
}

impl MultiColumnLookupEvals {
    /// **Session 88** — safe constructor that validates wire-shape
    /// invariants up-front instead of deferring to
    /// [`multi_column_lookup_expr`]. Callers that build the evals
    /// from parsed proof bytes can fail at parse time rather than
    /// at evaluation time.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] if `input_cols` is
    ///   empty or its length disagrees with `table_cols`.
    pub fn try_new(
        input_cols: alloc::vec::Vec<Fr>,
        table_cols: alloc::vec::Vec<Fr>,
        m: Fr,
    ) -> Result<Self, OnChainError> {
        if input_cols.is_empty() || input_cols.len() != table_cols.len() {
            return Err(OnChainError::ProofLengthMismatch);
        }
        Ok(Self {
            input_cols,
            table_cols,
            m,
        })
    }

    /// Arity (number of column pairs). Always ≥ 1 for a value
    /// constructed via [`try_new`](Self::try_new).
    #[must_use]
    pub fn arity(&self) -> usize {
        self.input_cols.len()
    }

    /// **Session 89** — lift a single-column [`LookupEvals`] into the
    /// equivalent arity-1 multi-column form.
    ///
    /// Backward-compatibility bridge: callers parsing the existing
    /// scaffold proof layout (which carries one (input, table, m)
    /// tuple) can promote it to the new audit-gate API without any
    /// wire-format change. The
    /// [`prop_basic_lookup_promotes_to_multi_arity_1`] proptest pins
    /// the algebraic equivalence — [`lookup_expr`] and
    /// [`multi_column_lookup_expr`] must agree byte-for-byte at
    /// arity 1 because the θ-power weighting collapses
    /// (`θ⁰ = 1`, `θ^k = θ¹ = θ`).
    #[must_use]
    pub fn from_basic(basic: LookupEvals) -> Self {
        Self {
            input_cols: alloc::vec![basic.input],
            table_cols: alloc::vec![basic.table],
            m: basic.m,
        }
    }
}

impl From<LookupEvals> for MultiColumnLookupEvals {
    fn from(basic: LookupEvals) -> Self {
        Self::from_basic(basic)
    }
}

/// Evaluate the multi-column lookup argument at ξ via the θ-combined
/// log-derivative form documented on [`MultiColumnLookupEvals`].
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] if `input_cols.is_empty()`
///   or `input_cols.len() != table_cols.len()`.
/// - [`OnChainError::InternalInvariantViolation`] if either combined
///   denominator (`table_combined + θ^k` or `input_combined + θ^k`)
///   is zero. Probability ≈ 2/r for random θ — negligible in practice
///   but explicit for consensus safety.
pub fn multi_column_lookup_expr(
    lookup: &MultiColumnLookupEvals,
    theta: &Fr,
) -> Result<Fr, OnChainError> {
    if lookup.input_cols.is_empty() || lookup.input_cols.len() != lookup.table_cols.len() {
        return Err(OnChainError::ProofLengthMismatch);
    }
    // Session 88 — defensive check: θ = 0 collapses the blinder
    // (`θ^k = 0` for k ≥ 1) and also makes the combined input/table
    // sums lose the column distinguishability the θ-power weighting
    // provides (every weight becomes 0 except the leading column).
    // The Fiat-Shamir transcript is constructed to make `θ = 0`
    // computationally impossible, but defense-in-depth catches a
    // hypothetical transcript bug at the soundness boundary instead
    // of at the inverse fault, which gives a clearer audit trail.
    if theta.is_zero() {
        return Err(OnChainError::InternalInvariantViolation);
    }
    let k = lookup.input_cols.len();

    // θ-powers `[1, θ, θ², …, θ^(k-1)]` for the linear combination.
    // The blinder uses `θ^k` — one degree past the combination — so
    // it can't coincide with any column weight.
    let theta_powers = mosaic_zk_primitives::field::powers_of(theta, k);

    let input_combined =
        mosaic_zk_primitives::field::fr_inner_product(&theta_powers, &lookup.input_cols)?;
    let table_combined =
        mosaic_zk_primitives::field::fr_inner_product(&theta_powers, &lookup.table_cols)?;

    let blinder = mosaic_zk_primitives::field::fr_pow_u64(theta, k as u64);

    let table_plus_blinder = table_combined + blinder;
    let input_plus_blinder = input_combined + blinder;

    let table_inv = table_plus_blinder
        .inverse()
        .ok_or(OnChainError::InternalInvariantViolation)?;
    let input_inv = input_plus_blinder
        .inverse()
        .ok_or(OnChainError::InternalInvariantViolation)?;

    Ok(lookup.m * table_inv - input_inv)
}

/// **Session 88** — high-level audit gate for the multi-column
/// log-derivative lookup identity at the evaluation point ξ.
///
/// Computes [`multi_column_lookup_expr`] and rejects the proof if
/// the result is non-zero. A satisfying lookup with unit
/// multiplicity per matched row produces a per-row identity value
/// of zero; the row-level zero combined with the sum-over-domain
/// identity (handled by the vanishing polynomial check) is the full
/// soundness story for log-derivative lookups.
///
/// Use this from the verifier instead of calling
/// `multi_column_lookup_expr` and ad-hoc-checking the result against
/// zero. The named function gives an external auditor a single point
/// to read for "this is the lookup soundness check" and a single
/// error type ([`OnChainError::SumcheckFailed`], reused for
/// consistency with other claim-reduction failures across the
/// workspace's verifiers).
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] — empty or arity-mismatched
///   evals.
/// - [`OnChainError::InternalInvariantViolation`] — `θ = 0` or one of
///   the combined denominators is zero (≈ 2/r probability for random
///   θ — negligible in practice but explicit at the audit boundary).
/// - [`OnChainError::SumcheckFailed`] — the lookup identity is
///   violated (the per-row expression is non-zero).
pub fn verify_multi_column_lookup_identity(
    lookup: &MultiColumnLookupEvals,
    theta: &Fr,
) -> Result<(), OnChainError> {
    let value = multi_column_lookup_expr(lookup, theta)?;
    if !value.is_zero() {
        return Err(OnChainError::SumcheckFailed);
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Combined claim reduction
// ---------------------------------------------------------------------

/// Evaluate the full vanishing-identity RHS at ξ:
///
/// ```text
/// gate_expr(ξ)  +  y · perm_expr(ξ)  +  y² · lookup_expr(ξ)
/// ```
///
/// Combines the three circuit-specific evaluators with `y`-power
/// weighting. Caller compares the result against `t(ξ) · Z_H(ξ)` to
/// check the vanishing identity.
pub fn combined_expr(
    wires: &WireEvals,
    selectors: &SelectorEvals,
    perm: &PermutationEvals,
    lookup: &LookupEvals,
    theta: &Fr,
    beta: &Fr,
    gamma: &Fr,
    y: &Fr,
    xi: &Fr,
) -> Result<Fr, OnChainError> {
    let gate = gate_expr(wires, selectors);
    let perm_value = permutation_expr(wires, perm, beta, gamma, xi);
    let lookup_value = lookup_expr(lookup, theta)?;
    let y_sq = *y * y;
    Ok(gate + *y * perm_value + y_sq * lookup_value)
}

/// **Session 100** — multi-column variant of [`combined_expr`].
///
/// Like [`combined_expr`] but uses [`multi_column_lookup_expr`] for
/// the lookup contribution, supporting arity ≥ 2 lookup arguments.
/// At arity 1 the result is byte-equivalent to `combined_expr` —
/// pinned by `prop_basic_lookup_promotes_to_multi_arity_1` (session
/// 89) which proves the algebraic equivalence between the two
/// lookup primitives at arity 1.
///
/// Used by the Halo2 verifier when the proof's `lookup_arity ≥ 2`.
/// For arity-1 proofs, the verifier continues to call `combined_expr`
/// with the legacy `LookupEvals` to preserve byte-equivalence with
/// pre-session-100 fixtures.
///
/// ## Errors
///
/// Propagates errors from [`multi_column_lookup_expr`]:
/// - [`OnChainError::ProofLengthMismatch`] — empty / arity-mismatched
///   columns.
/// - [`OnChainError::InternalInvariantViolation`] — `θ = 0` or
///   denominator inverse failure.
#[allow(clippy::too_many_arguments)]
pub fn combined_expr_multi_column(
    wires: &WireEvals,
    selectors: &SelectorEvals,
    perm: &PermutationEvals,
    lookup: &MultiColumnLookupEvals,
    theta: &Fr,
    beta: &Fr,
    gamma: &Fr,
    y: &Fr,
    xi: &Fr,
) -> Result<Fr, OnChainError> {
    let gate = gate_expr(wires, selectors);
    let perm_value = permutation_expr(wires, perm, beta, gamma, xi);
    let lookup_value = multi_column_lookup_expr(lookup, theta)?;
    let y_sq = *y * y;
    Ok(gate + *y * perm_value + y_sq * lookup_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    // ---- gate_expr ----

    #[test]
    fn gate_expr_mul_gate_zero_on_valid() {
        let a = Fr::from(7u64);
        let b = Fr::from(11u64);
        let c = a * b;
        let wires = WireEvals { a, b, c };
        let selectors = SelectorEvals {
            q_m: Fr::one(),
            q_l: Fr::zero(),
            q_r: Fr::zero(),
            q_o: -Fr::one(),
            q_c: Fr::zero(),
        };
        assert_eq!(gate_expr(&wires, &selectors), Fr::zero());
    }

    #[test]
    fn gate_expr_matches_manual_formula() {
        let mut r = rng(1);
        for _ in 0..5 {
            let wires = WireEvals {
                a: Fr::rand(&mut r),
                b: Fr::rand(&mut r),
                c: Fr::rand(&mut r),
            };
            let s = SelectorEvals {
                q_m: Fr::rand(&mut r),
                q_l: Fr::rand(&mut r),
                q_r: Fr::rand(&mut r),
                q_o: Fr::rand(&mut r),
                q_c: Fr::rand(&mut r),
            };
            let expected = s.q_m * wires.a * wires.b
                + s.q_l * wires.a
                + s.q_r * wires.b
                + s.q_o * wires.c
                + s.q_c;
            assert_eq!(gate_expr(&wires, &s), expected);
        }
    }

    // ---- permutation_expr ----

    #[test]
    fn permutation_identity_permutation_trivially_zero_when_z_equals_z_next() {
        // When σ_i = id_i (identity permutation) and z = z_next, the
        // numerator and denominator of the grand-product argument are
        // equal, so the difference is 0.
        let mut r = rng(10);
        let xi = Fr::rand(&mut r);
        let wires = WireEvals {
            a: Fr::rand(&mut r),
            b: Fr::rand(&mut r),
            c: Fr::rand(&mut r),
        };
        let z = Fr::rand(&mut r);
        let perm = PermutationEvals {
            z,
            z_next: z,
            sigma_1: xi,
            sigma_2: Fr::from(2u64) * xi,
            sigma_3: Fr::from(3u64) * xi,
        };
        let beta = Fr::rand(&mut r);
        let gamma = Fr::rand(&mut r);
        assert_eq!(
            permutation_expr(&wires, &perm, &beta, &gamma, &xi),
            Fr::zero()
        );
    }

    #[test]
    fn permutation_generally_nonzero_for_nontrivial_permutation() {
        let mut r = rng(11);
        let xi = Fr::rand(&mut r);
        let wires = WireEvals {
            a: Fr::rand(&mut r),
            b: Fr::rand(&mut r),
            c: Fr::rand(&mut r),
        };
        let perm = PermutationEvals {
            z: Fr::rand(&mut r),
            z_next: Fr::rand(&mut r),
            sigma_1: Fr::rand(&mut r),
            sigma_2: Fr::rand(&mut r),
            sigma_3: Fr::rand(&mut r),
        };
        let beta = Fr::rand(&mut r);
        let gamma = Fr::rand(&mut r);
        // With random inputs, probability of zero is negligible.
        assert_ne!(
            permutation_expr(&wires, &perm, &beta, &gamma, &xi),
            Fr::zero()
        );
    }

    // ---- lookup_expr ----

    #[test]
    fn lookup_expr_zero_when_multiplicity_makes_equation_hold() {
        // Choose m such that m·(table+θ)⁻¹ = (input+θ)⁻¹.
        //   m = (table + θ) / (input + θ).
        let mut r = rng(20);
        let theta = Fr::rand(&mut r);
        let table = Fr::rand(&mut r);
        let input = Fr::rand(&mut r);
        let m = (table + theta) * (input + theta).inverse().unwrap();
        let got = lookup_expr(&LookupEvals { input, table, m }, &theta).unwrap();
        assert_eq!(got, Fr::zero());
    }

    #[test]
    fn lookup_expr_nonzero_for_unrelated_m() {
        let mut r = rng(21);
        let theta = Fr::rand(&mut r);
        let lookup = LookupEvals {
            input: Fr::rand(&mut r),
            table: Fr::rand(&mut r),
            m: Fr::rand(&mut r),
        };
        // Random m has negligible probability of hitting the valid
        // relation.
        let got = lookup_expr(&lookup, &theta).unwrap();
        assert_ne!(got, Fr::zero());
    }

    #[test]
    fn lookup_expr_rejects_zero_denominator() {
        // table + theta = 0 → inverse fails.
        let theta = Fr::from(5u64);
        let lookup = LookupEvals {
            input: Fr::from(1u64),
            table: -theta, // table = -θ → table + θ = 0
            m: Fr::from(1u64),
        };
        assert!(matches!(
            lookup_expr(&lookup, &theta),
            Err(OnChainError::InternalInvariantViolation),
        ));
    }

    // ---- combined_expr ----

    #[test]
    fn combined_expr_is_gate_when_y_is_zero() {
        // y = 0 → only the gate term contributes.
        let mut r = rng(30);
        let wires = WireEvals {
            a: Fr::rand(&mut r),
            b: Fr::rand(&mut r),
            c: Fr::rand(&mut r),
        };
        let s = SelectorEvals {
            q_m: Fr::rand(&mut r),
            q_l: Fr::rand(&mut r),
            q_r: Fr::rand(&mut r),
            q_o: Fr::rand(&mut r),
            q_c: Fr::rand(&mut r),
        };
        let perm = PermutationEvals {
            z: Fr::rand(&mut r),
            z_next: Fr::rand(&mut r),
            sigma_1: Fr::rand(&mut r),
            sigma_2: Fr::rand(&mut r),
            sigma_3: Fr::rand(&mut r),
        };
        let lookup = LookupEvals {
            input: Fr::rand(&mut r),
            table: Fr::rand(&mut r),
            m: Fr::rand(&mut r),
        };
        let theta = Fr::rand(&mut r);
        let beta = Fr::rand(&mut r);
        let gamma = Fr::rand(&mut r);
        let xi = Fr::rand(&mut r);

        let combined = combined_expr(
            &wires,
            &s,
            &perm,
            &lookup,
            &theta,
            &beta,
            &gamma,
            &Fr::zero(),
            &xi,
        )
        .unwrap();
        assert_eq!(combined, gate_expr(&wires, &s));
    }

    #[test]
    fn combined_expr_y_scales_contributions() {
        // Changing y changes the weighting; verify non-trivial
        // dependence.
        let mut r = rng(31);
        let wires = WireEvals {
            a: Fr::rand(&mut r),
            b: Fr::rand(&mut r),
            c: Fr::rand(&mut r),
        };
        let s = SelectorEvals {
            q_m: Fr::rand(&mut r),
            q_l: Fr::rand(&mut r),
            q_r: Fr::rand(&mut r),
            q_o: Fr::rand(&mut r),
            q_c: Fr::rand(&mut r),
        };
        let perm = PermutationEvals {
            z: Fr::rand(&mut r),
            z_next: Fr::rand(&mut r),
            sigma_1: Fr::rand(&mut r),
            sigma_2: Fr::rand(&mut r),
            sigma_3: Fr::rand(&mut r),
        };
        let lookup = LookupEvals {
            input: Fr::rand(&mut r),
            table: Fr::rand(&mut r),
            m: Fr::rand(&mut r),
        };
        let theta = Fr::rand(&mut r);
        let beta = Fr::rand(&mut r);
        let gamma = Fr::rand(&mut r);
        let xi = Fr::rand(&mut r);

        let a = combined_expr(
            &wires,
            &s,
            &perm,
            &lookup,
            &theta,
            &beta,
            &gamma,
            &Fr::from(1u64),
            &xi,
        )
        .unwrap();
        let b = combined_expr(
            &wires,
            &s,
            &perm,
            &lookup,
            &theta,
            &beta,
            &gamma,
            &Fr::from(2u64),
            &xi,
        )
        .unwrap();
        assert_ne!(a, b, "combined expression should depend on y");
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 85 — multi_column_lookup_expr properties
    // ───────────────────────────────────────────────────────────────────

    use proptest::prelude::*;

    #[test]
    fn multi_column_lookup_rejects_empty() {
        let theta = Fr::from(7u64);
        let lookup = MultiColumnLookupEvals {
            input_cols: alloc::vec::Vec::new(),
            table_cols: alloc::vec::Vec::new(),
            m: Fr::from(1u64),
        };
        assert!(matches!(
            multi_column_lookup_expr(&lookup, &theta),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn multi_column_lookup_rejects_arity_mismatch() {
        let theta = Fr::from(7u64);
        let lookup = MultiColumnLookupEvals {
            input_cols: alloc::vec![Fr::from(1u64), Fr::from(2u64)],
            table_cols: alloc::vec![Fr::from(3u64)],
            m: Fr::from(1u64),
        };
        assert!(matches!(
            multi_column_lookup_expr(&lookup, &theta),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    proptest! {
        /// Arity-1 multi-column lookup matches the basic
        /// single-column `lookup_expr` form structurally:
        ///   - input_combined = θ⁰ · input_cols[0] = input
        ///   - table_combined = θ⁰ · table_cols[0] = table
        ///   - blinder        = θ¹                  = θ
        /// so the inner identity reduces to
        ///   `m · (table + θ)⁻¹ - (input + θ)⁻¹` — exactly the
        /// basic `lookup_expr` output.
        #[test]
        fn prop_multi_column_lookup_arity_1_matches_basic(
            input_seed in 1u64..=u64::MAX,
            table_seed in 1u64..=u64::MAX,
            m_seed in 1u64..=u64::MAX,
            theta_seed in 1u64..=u64::MAX,
        ) {
            let input = Fr::from(input_seed);
            let table = Fr::from(table_seed);
            let m = Fr::from(m_seed);
            let theta = Fr::from(theta_seed);

            let basic = lookup_expr(&LookupEvals { input, table, m }, &theta).unwrap();
            let multi = multi_column_lookup_expr(
                &MultiColumnLookupEvals {
                    input_cols: alloc::vec![input],
                    table_cols: alloc::vec![table],
                    m,
                },
                &theta,
            )
            .unwrap();

            prop_assert_eq!(basic, multi);
        }

        /// When `input_combined == table_combined` (every column pair
        /// matches at ξ), the unique satisfying multiplicity is
        /// `m = 1`, and the expression vanishes:
        ///   m · (T + θ^k)⁻¹ - (I + θ^k)⁻¹ = (T + θ^k)⁻¹ - (I + θ^k)⁻¹ = 0
        ///
        /// This is the audit-grade soundness pin for the multi-column
        /// reduction: a satisfying assignment with unit multiplicity
        /// makes the lookup contribute nothing to the vanishing
        /// identity.
        #[test]
        fn prop_multi_column_lookup_zero_on_matching_arity_2(
            seed in 1u64..=u64::MAX,
            theta_seed in 2u64..=u64::MAX, // skip θ=0 to avoid blinder collisions
        ) {
            let mut r = rng(seed);
            let col_a = Fr::rand(&mut r);
            let col_b = Fr::rand(&mut r);
            let theta = Fr::from(theta_seed);
            // Same column values on both sides ⇒ input_combined = table_combined.
            let lookup = MultiColumnLookupEvals {
                input_cols: alloc::vec![col_a, col_b],
                table_cols: alloc::vec![col_a, col_b],
                m: Fr::from(1u64),
            };
            let v = multi_column_lookup_expr(&lookup, &theta).unwrap();
            prop_assert_eq!(v, Fr::zero());
        }

        /// θ-combination is faithful: changing any single column on
        /// the input side AND tweaking m so the basic identity holds
        /// for arity-1 should NOT make arity-2 vanish — the second
        /// column is still mismatched.
        #[test]
        fn prop_multi_column_lookup_distinguishes_columns(
            seed in 1u64..=u64::MAX,
            theta_seed in 2u64..=u64::MAX,
        ) {
            let mut r = rng(seed);
            let col_a = Fr::rand(&mut r);
            let col_b = Fr::rand(&mut r);
            let mismatch = col_b + Fr::from(1u64);
            let theta = Fr::from(theta_seed);
            let lookup = MultiColumnLookupEvals {
                input_cols: alloc::vec![col_a, col_b],
                table_cols: alloc::vec![col_a, mismatch], // only 2nd column differs
                m: Fr::from(1u64),
            };
            let v = multi_column_lookup_expr(&lookup, &theta).unwrap();
            // With probability ≈ 1 - 1/r the mismatch surfaces as a
            // non-zero contribution.
            prop_assert_ne!(v, Fr::zero());
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 88 — `try_new` constructor + θ=0 defensive check +
    // `verify_multi_column_lookup_identity` audit gate.
    // ───────────────────────────────────────────────────────────────────

    // ---- try_new ----

    #[test]
    fn try_new_accepts_arity_1() {
        let evals = MultiColumnLookupEvals::try_new(
            alloc::vec![Fr::from(1u64)],
            alloc::vec![Fr::from(1u64)],
            Fr::from(1u64),
        )
        .unwrap();
        assert_eq!(evals.arity(), 1);
    }

    #[test]
    fn try_new_accepts_arity_5() {
        let evals = MultiColumnLookupEvals::try_new(
            alloc::vec![Fr::from(1u64); 5],
            alloc::vec![Fr::from(2u64); 5],
            Fr::from(3u64),
        )
        .unwrap();
        assert_eq!(evals.arity(), 5);
    }

    #[test]
    fn try_new_rejects_empty() {
        let r = MultiColumnLookupEvals::try_new(
            alloc::vec::Vec::new(),
            alloc::vec::Vec::new(),
            Fr::from(1u64),
        );
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn try_new_rejects_arity_mismatch() {
        let r = MultiColumnLookupEvals::try_new(
            alloc::vec![Fr::from(1u64); 3],
            alloc::vec![Fr::from(2u64); 2],
            Fr::from(3u64),
        );
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    // ---- θ = 0 defensive check ----

    #[test]
    fn multi_column_lookup_rejects_theta_zero() {
        let lookup = MultiColumnLookupEvals::try_new(
            alloc::vec![Fr::from(1u64), Fr::from(2u64)],
            alloc::vec![Fr::from(1u64), Fr::from(2u64)],
            Fr::from(1u64),
        )
        .unwrap();
        let r = multi_column_lookup_expr(&lookup, &Fr::zero());
        assert!(
            matches!(r, Err(OnChainError::InternalInvariantViolation)),
            "θ=0 should be rejected at the input-validation boundary",
        );
    }

    /// The defensive check fires *before* any inverse computation, so
    /// even an otherwise valid satisfying tuple at θ=0 rejects.
    #[test]
    fn multi_column_lookup_rejects_theta_zero_even_for_satisfying_tuple() {
        let lookup = MultiColumnLookupEvals::try_new(
            alloc::vec![Fr::from(7u64)],
            alloc::vec![Fr::from(7u64)], // equal => would satisfy at θ ≠ 0 with m=1
            Fr::from(1u64),
        )
        .unwrap();
        assert!(matches!(
            multi_column_lookup_expr(&lookup, &Fr::zero()),
            Err(OnChainError::InternalInvariantViolation)
        ));
    }

    // ---- verify_multi_column_lookup_identity ----

    #[test]
    fn verify_lookup_identity_accepts_satisfying_tuple() {
        // (a, b) on both sides + m=1 ⇒ identity vanishes ⇒ accept.
        let lookup = MultiColumnLookupEvals::try_new(
            alloc::vec![Fr::from(3u64), Fr::from(5u64)],
            alloc::vec![Fr::from(3u64), Fr::from(5u64)],
            Fr::from(1u64),
        )
        .unwrap();
        let theta = Fr::from(11u64);
        verify_multi_column_lookup_identity(&lookup, &theta).expect("satisfying tuple must accept");
    }

    #[test]
    fn verify_lookup_identity_rejects_non_satisfying_tuple() {
        // Random m with mismatched columns ⇒ identity ≠ 0 ⇒ reject as
        // SumcheckFailed.
        let lookup = MultiColumnLookupEvals::try_new(
            alloc::vec![Fr::from(3u64), Fr::from(5u64)],
            alloc::vec![Fr::from(3u64), Fr::from(99u64)], // 2nd column differs
            Fr::from(1u64),
        )
        .unwrap();
        let theta = Fr::from(11u64);
        let r = verify_multi_column_lookup_identity(&lookup, &theta);
        assert!(
            matches!(r, Err(OnChainError::SumcheckFailed)),
            "non-zero lookup expression must surface as SumcheckFailed, got {r:?}",
        );
    }

    #[test]
    fn verify_lookup_identity_propagates_input_validation_errors() {
        // Empty cols → ProofLengthMismatch (NOT SumcheckFailed).
        let lookup = MultiColumnLookupEvals {
            input_cols: alloc::vec::Vec::new(),
            table_cols: alloc::vec::Vec::new(),
            m: Fr::from(1u64),
        };
        let theta = Fr::from(7u64);
        assert!(matches!(
            verify_multi_column_lookup_identity(&lookup, &theta),
            Err(OnChainError::ProofLengthMismatch)
        ));

        // Arity mismatch → ProofLengthMismatch (NOT SumcheckFailed).
        let lookup = MultiColumnLookupEvals {
            input_cols: alloc::vec![Fr::from(1u64), Fr::from(2u64)],
            table_cols: alloc::vec![Fr::from(1u64)],
            m: Fr::from(1u64),
        };
        assert!(matches!(
            verify_multi_column_lookup_identity(&lookup, &theta),
            Err(OnChainError::ProofLengthMismatch)
        ));
    }

    #[test]
    fn verify_lookup_identity_propagates_theta_zero() {
        // θ=0 → InternalInvariantViolation (NOT SumcheckFailed).
        let lookup = MultiColumnLookupEvals::try_new(
            alloc::vec![Fr::from(3u64)],
            alloc::vec![Fr::from(3u64)],
            Fr::from(1u64),
        )
        .unwrap();
        assert!(matches!(
            verify_multi_column_lookup_identity(&lookup, &Fr::zero()),
            Err(OnChainError::InternalInvariantViolation)
        ));
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 88 — proptest soundness for the audit gate.
    // ───────────────────────────────────────────────────────────────────

    proptest! {
        /// Audit gate accepts any satisfying tuple
        /// (input_cols == table_cols, m = 1) over a random arity and
        /// random θ ≠ 0. This is the round-trip invariant: an honest
        /// prover always passes.
        #[test]
        fn proptest_audit_gate_accepts_matching_columns(
            arity in 1usize..=8,
            seed in 1u64..=u64::MAX,
            theta_seed in 2u64..=u64::MAX,
        ) {
            let mut r = rng(seed);
            let cols: alloc::vec::Vec<Fr> =
                (0..arity).map(|_| Fr::rand(&mut r)).collect();
            let lookup = MultiColumnLookupEvals::try_new(
                cols.clone(),
                cols,
                Fr::from(1u64),
            ).expect("well-formed evals");
            let theta = Fr::from(theta_seed);
            prop_assert!(
                verify_multi_column_lookup_identity(&lookup, &theta).is_ok(),
                "audit gate must accept satisfying tuple at arity={}",
                arity
            );
        }

        /// Audit gate rejects any tuple with a single mismatched
        /// column (chosen randomly within the arity), surfacing as
        /// `SumcheckFailed`. Catches the failure mode where an
        /// adversarial prover tampers one column but leaves the
        /// remainder intact.
        #[test]
        fn proptest_audit_gate_rejects_single_column_mismatch(
            arity in 2usize..=8,
            mismatch_idx in 0usize..8,
            seed in 1u64..=u64::MAX,
            theta_seed in 2u64..=u64::MAX,
        ) {
            prop_assume!(mismatch_idx < arity);
            let mut r = rng(seed);
            let mut input_cols: alloc::vec::Vec<Fr> =
                (0..arity).map(|_| Fr::rand(&mut r)).collect();
            let table_cols = input_cols.clone();
            // Tamper one column on the input side.
            input_cols[mismatch_idx] += Fr::from(1u64);
            let lookup = MultiColumnLookupEvals::try_new(
                input_cols,
                table_cols,
                Fr::from(1u64),
            ).expect("well-formed evals");
            let theta = Fr::from(theta_seed);
            let res = verify_multi_column_lookup_identity(&lookup, &theta);
            prop_assert!(
                matches!(res, Err(OnChainError::SumcheckFailed)),
                "single-column tamper at arity={} idx={} should reject; got {:?}",
                arity, mismatch_idx, res
            );
        }

        /// Wrong multiplicity rejects: with matching columns but
        /// `m ≠ 1`, the per-row identity is `(m - 1) · denom⁻¹` which
        /// is non-zero whenever m ≠ 1. Audit gate must reject as
        /// `SumcheckFailed`.
        #[test]
        fn proptest_audit_gate_rejects_wrong_multiplicity(
            arity in 1usize..=4,
            seed in 1u64..=u64::MAX,
            wrong_m in 2u64..=u64::MAX, // any m ≠ 1
            theta_seed in 2u64..=u64::MAX,
        ) {
            let mut r = rng(seed);
            let cols: alloc::vec::Vec<Fr> =
                (0..arity).map(|_| Fr::rand(&mut r)).collect();
            let lookup = MultiColumnLookupEvals::try_new(
                cols.clone(),
                cols,
                Fr::from(wrong_m),
            ).expect("well-formed evals");
            let theta = Fr::from(theta_seed);
            let res = verify_multi_column_lookup_identity(&lookup, &theta);
            prop_assert!(
                matches!(res, Err(OnChainError::SumcheckFailed)),
                "wrong multiplicity m={} at arity={} should reject; got {:?}",
                wrong_m, arity, res
            );
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 89 — LookupEvals → MultiColumnLookupEvals bridge.
    // ───────────────────────────────────────────────────────────────────

    /// `From` impl is a thin wrapper around `from_basic`. Direct
    /// regression test: round-trip a `LookupEvals` through the From
    /// conversion and confirm field-by-field equality.
    #[test]
    fn from_basic_preserves_fields() {
        let basic = LookupEvals {
            input: Fr::from(7u64),
            table: Fr::from(13u64),
            m: Fr::from(2u64),
        };
        let lifted = MultiColumnLookupEvals::from_basic(basic);
        assert_eq!(lifted.arity(), 1);
        assert_eq!(lifted.input_cols, alloc::vec![Fr::from(7u64)]);
        assert_eq!(lifted.table_cols, alloc::vec![Fr::from(13u64)]);
        assert_eq!(lifted.m, Fr::from(2u64));
    }

    /// `From<LookupEvals>` agrees with `from_basic`. Both spell the
    /// same construction; pinning the equivalence prevents one path
    /// from drifting.
    #[test]
    fn from_trait_matches_from_basic() {
        let basic = LookupEvals {
            input: Fr::from(100u64),
            table: Fr::from(200u64),
            m: Fr::from(300u64),
        };
        let via_method = MultiColumnLookupEvals::from_basic(basic.clone());
        let via_trait: MultiColumnLookupEvals = basic.into();
        assert_eq!(via_method, via_trait);
    }

    proptest! {
        /// **Session 89 — backward-compatibility soundness pin.**
        ///
        /// The basic single-column [`lookup_expr`] and the multi-column
        /// [`multi_column_lookup_expr`] applied to the arity-1
        /// promotion of the same `LookupEvals` MUST produce identical
        /// `Fr` values for every (input, table, m, θ) tuple where
        /// θ ≠ 0 and the denominators don't degenerate.
        ///
        /// Algebraic justification: at arity-1 the θ-power vector is
        /// `[θ⁰] = [1]`, so input_combined = input and table_combined
        /// = table. The blinder is `θ^k = θ¹ = θ`. Substituting:
        ///   m·(table + θ)⁻¹ - (input + θ)⁻¹
        /// — exactly the basic `lookup_expr` formula.
        ///
        /// This is the load-bearing invariant for the bridge: any
        /// future verifier that wants to unify single-column and
        /// multi-column lookup paths under the new audit-gate API
        /// can do so without changing the underlying soundness story.
        #[test]
        fn prop_basic_lookup_promotes_to_multi_arity_1(
            input_seed in 1u64..=u64::MAX,
            table_seed in 1u64..=u64::MAX,
            m_seed in 0u64..=u64::MAX,
            theta_seed in 1u64..=u64::MAX,
        ) {
            let basic = LookupEvals {
                input: Fr::from(input_seed),
                table: Fr::from(table_seed),
                m: Fr::from(m_seed),
            };
            let theta = Fr::from(theta_seed);
            // Skip the (table + θ = 0) and (input + θ = 0) corners
            // where both formulations degenerate identically — those
            // are covered by `lookup_expr_rejects_zero_denominator`.
            prop_assume!((basic.table + theta) != Fr::zero());
            prop_assume!((basic.input + theta) != Fr::zero());

            let basic_val =
                lookup_expr(&basic, &theta).expect("basic eval succeeds");
            let lifted: MultiColumnLookupEvals = basic.into();
            let multi_val = multi_column_lookup_expr(&lifted, &theta)
                .expect("multi-column eval succeeds at arity-1");
            prop_assert_eq!(
                basic_val, multi_val,
                "basic lookup_expr must equal multi-column at arity-1",
            );
        }

        /// **Audit-gate equivalence at arity-1.**
        ///
        /// If a basic lookup tuple satisfies `lookup_expr == 0`, the
        /// promoted arity-1 tuple MUST satisfy
        /// `verify_multi_column_lookup_identity == Ok(())`. Bridges
        /// the soundness contract from `lookup_expr` (which the
        /// vanishing identity check already absorbs) to the new
        /// audit-gate API without behavioural drift.
        ///
        /// We construct a satisfying tuple by choosing
        ///   m = (table + θ) / (input + θ)
        /// — exactly the inverse-relation that makes
        ///   m · (table + θ)⁻¹ - (input + θ)⁻¹ = 0
        /// hold. The promoted multi-column form must also accept it.
        #[test]
        fn prop_audit_gate_accepts_satisfying_basic_promotion(
            input_seed in 1u64..=u64::MAX,
            table_seed in 1u64..=u64::MAX,
            theta_seed in 2u64..=u64::MAX, // ≥ 2 to avoid θ=0 rejection
        ) {
            let input = Fr::from(input_seed);
            let table = Fr::from(table_seed);
            let theta = Fr::from(theta_seed);
            prop_assume!((table + theta) != Fr::zero());
            prop_assume!((input + theta) != Fr::zero());
            // Force a satisfying multiplicity.
            let m = (table + theta) * (input + theta).inverse().unwrap();
            let basic = LookupEvals { input, table, m };

            // Sanity: basic form vanishes.
            let basic_val = lookup_expr(&basic, &theta).unwrap();
            prop_assert_eq!(basic_val, Fr::zero(), "construction error");

            // Audit gate on the promoted form must accept.
            let lifted: MultiColumnLookupEvals = basic.into();
            let res = verify_multi_column_lookup_identity(&lifted, &theta);
            prop_assert!(
                res.is_ok(),
                "audit gate must accept the promoted satisfying tuple, got {:?}",
                res
            );
        }
    }
}
