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
use ark_ff::Field;
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
}
