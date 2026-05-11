//! Sudoku R1CS circuit (arkworks low-level API).
//!
//! Public inputs (length 81, row-major): the puzzle clues. `0` for
//! "unknown", `1..=9` for "given". Visible to the verifier.
//!
//! Witness: 81 solution cells (the actual solved grid) + per-cell
//! intermediate products from the in-range chain + per-cell squared
//! values.
//!
//! Constraint breakdown for a 9×9 board:
//!
//! | Constraint family            | Count | Source                                       |
//! |------------------------------|------:|----------------------------------------------|
//! | In-range chain (`p_k = p_{k-1} · (v - k)`) | 81 × 8 = 648 | Each cell ∈ {1..9} via degree-9 polynomial. |
//! | In-range terminator (`p_9 = 0`) | 81 | Closes the chain at zero.                   |
//! | Square allocation (`sq = v · v`) | 81 | Witness for the sum-of-squares group check. |
//! | Clue match (`clue · (clue − sol) = product`) | 81 | Product witness allocation.                 |
//! | Clue match zero (`product = 0`) | 81 | If clue ≠ 0, forces clue == solution.       |
//! | Group sums (`Σ v = 45 · 1`)  | 27 × 1 = 27 | 9 rows + 9 cols + 9 boxes; one constraint each. |
//! | Group sum-of-squares (`Σ sq = 285 · 1`) | 27 × 1 = 27 | Same groups, on squared witnesses.          |
//! | **Total**                    | **1026** |                                         |
//!
//! Power-sum group constraints are a documented soundness trade-off
//! for this demo. See the crate-level rustdoc.

use ark_bn254::Fr;
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    },
};

use crate::puzzles::Grid;

/// Constraint-count breakdown reported by the generator binary into
/// the demo's provenance panel.
#[derive(Debug, Clone, Copy)]
pub struct ConstraintBreakdown {
    pub in_range_chain: usize,
    pub in_range_terminator: usize,
    pub square_allocation: usize,
    pub clue_match: usize,
    pub clue_match_zero: usize,
    pub group_sum: usize,
    pub group_sum_of_squares: usize,
}

impl ConstraintBreakdown {
    pub const SUDOKU_9X9: Self = Self {
        in_range_chain: 81 * 8,
        in_range_terminator: 81,
        square_allocation: 81,
        clue_match: 81,
        clue_match_zero: 81,
        group_sum: 27,
        group_sum_of_squares: 27,
    };

    #[must_use]
    pub const fn total(self) -> usize {
        self.in_range_chain
            + self.in_range_terminator
            + self.square_allocation
            + self.clue_match
            + self.clue_match_zero
            + self.group_sum
            + self.group_sum_of_squares
    }
}

/// The sudoku ConstraintSynthesizer.
///
/// `clues` and `solution` are required for prove-time; for setup-time
/// (which only inspects the shape of the circuit, not values) pass a
/// `solution: None`. The clue layout is still inspected to size the
/// public-input count, so always pass the real clues even at setup.
#[derive(Clone)]
pub struct SudokuCircuit {
    pub clues: Grid,
    /// `None` during `Groth16::circuit_specific_setup`; `Some(grid)`
    /// during `Groth16::prove`.
    pub solution: Option<Grid>,
}

impl ConstraintSynthesizer<Fr> for SudokuCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── 1. Public inputs: 81 clue cells (row-major).
        let clue_vars: Vec<Variable> = self
            .clues
            .iter()
            .map(|&c| cs.new_input_variable(|| Ok(Fr::from(u64::from(c)))))
            .collect::<Result<_, _>>()?;

        // ── 2. Witnesses: 81 solution cells.
        let sol_vars: Vec<Variable> = (0..81)
            .map(|i| {
                cs.new_witness_variable(|| {
                    self.solution
                        .as_ref()
                        .map(|s| Fr::from(u64::from(s[i])))
                        .ok_or(SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<_, _>>()?;

        // ── 3. In-range constraints: (v-1)(v-2)…(v-9) = 0.
        // Encoded as a chain of multiplications, one R1CS constraint each:
        //     p_2 = (v - 1) · (v - 2)
        //     p_3 = p_2 · (v - 3)
        //     …
        //     p_9 = p_8 · (v - 9)
        //     p_9 = 0
        for (i, &v) in sol_vars.iter().enumerate() {
            // First factor: (v - 1). Represented as a LinearCombination,
            // no witness allocated yet.
            let mut prev: LinearCombination<Fr> = lc!() + v - (Fr::ONE, Variable::One);

            for k in 2u64..=9 {
                let factor: LinearCombination<Fr> =
                    lc!() + v - (Fr::from(k), Variable::One);
                let product_value = || -> Result<Fr, SynthesisError> {
                    let s = self
                        .solution
                        .as_ref()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let s_val = Fr::from(u64::from(s[i]));
                    let mut prod = Fr::ONE;
                    for j in 1u64..=k {
                        prod *= s_val - Fr::from(j);
                    }
                    Ok(prod)
                };
                let product = cs.new_witness_variable(product_value)?;
                // a · b = c   →   prev · factor = product
                cs.enforce_constraint(prev, factor, lc!() + product)?;
                prev = lc!() + product;
            }
            // Terminator: the final product must be zero.
            // 1 · prev = 0  →  prev = 0.
            cs.enforce_constraint(lc!() + Variable::One, prev, lc!())?;
        }

        // ── 4. Square allocation: sq_i = v_i · v_i (witness allocation).
        let sq_vars: Vec<Variable> = sol_vars
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let sq_val = || -> Result<Fr, SynthesisError> {
                    let s = self
                        .solution
                        .as_ref()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let s_val = Fr::from(u64::from(s[i]));
                    Ok(s_val * s_val)
                };
                let sq = cs.new_witness_variable(sq_val)?;
                cs.enforce_constraint(lc!() + v, lc!() + v, lc!() + sq)?;
                Ok(sq)
            })
            .collect::<Result<_, _>>()?;

        // ── 5. Clue match: clue · (clue - sol) = 0.
        // When clue == 0, the LHS is trivially 0; when clue != 0, this
        // forces clue == sol.
        for (i, (&clue_v, &sol_v)) in clue_vars.iter().zip(sol_vars.iter()).enumerate() {
            let diff: LinearCombination<Fr> = lc!() + clue_v - sol_v;
            // Witness for the product so that the R1CS form holds:
            //   clue · diff = product = 0.
            let product_value = || -> Result<Fr, SynthesisError> {
                let s = self
                    .solution
                    .as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                let c = Fr::from(u64::from(self.clues[i]));
                let sv = Fr::from(u64::from(s[i]));
                Ok(c * (c - sv))
            };
            let product = cs.new_witness_variable(product_value)?;
            cs.enforce_constraint(lc!() + clue_v, diff, lc!() + product)?;
            // product = 0 enforced by the next constraint.
            cs.enforce_constraint(lc!() + Variable::One, lc!() + product, lc!())?;
        }

        // ── 6. Group sums and sum-of-squares.
        // Row r:    cells (r, 0..9), Σ v = 45,   Σ v² = 285
        // Column c: cells (0..9, c), Σ v = 45,   Σ v² = 285
        // Box b:    cells in 3×3 block, Σ v = 45, Σ v² = 285
        let target_sum = Fr::from(45u64);
        let target_sq = Fr::from(285u64);

        for r in 0..9usize {
            let mut sum_lc: LinearCombination<Fr> = lc!();
            let mut sq_lc: LinearCombination<Fr> = lc!();
            for c in 0..9usize {
                sum_lc = sum_lc + sol_vars[r * 9 + c];
                sq_lc = sq_lc + sq_vars[r * 9 + c];
            }
            // sum_lc · 1 = target_sum · 1
            cs.enforce_constraint(
                sum_lc,
                lc!() + Variable::One,
                lc!() + (target_sum, Variable::One),
            )?;
            cs.enforce_constraint(
                sq_lc,
                lc!() + Variable::One,
                lc!() + (target_sq, Variable::One),
            )?;
        }
        for c in 0..9usize {
            let mut sum_lc: LinearCombination<Fr> = lc!();
            let mut sq_lc: LinearCombination<Fr> = lc!();
            for r in 0..9usize {
                sum_lc = sum_lc + sol_vars[r * 9 + c];
                sq_lc = sq_lc + sq_vars[r * 9 + c];
            }
            cs.enforce_constraint(
                sum_lc,
                lc!() + Variable::One,
                lc!() + (target_sum, Variable::One),
            )?;
            cs.enforce_constraint(
                sq_lc,
                lc!() + Variable::One,
                lc!() + (target_sq, Variable::One),
            )?;
        }
        for box_r in 0..3usize {
            for box_c in 0..3usize {
                let mut sum_lc: LinearCombination<Fr> = lc!();
                let mut sq_lc: LinearCombination<Fr> = lc!();
                for dr in 0..3usize {
                    for dc in 0..3usize {
                        let idx = (box_r * 3 + dr) * 9 + (box_c * 3 + dc);
                        sum_lc = sum_lc + sol_vars[idx];
                        sq_lc = sq_lc + sq_vars[idx];
                    }
                }
                cs.enforce_constraint(
                    sum_lc,
                    lc!() + Variable::One,
                    lc!() + (target_sum, Variable::One),
                )?;
                cs.enforce_constraint(
                    sq_lc,
                    lc!() + Variable::One,
                    lc!() + (target_sq, Variable::One),
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::puzzles::{PUZZLE_INKALA_2010, SOLUTION_INKALA_2010};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn inkala_puzzle_satisfies_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = SudokuCircuit {
            clues: PUZZLE_INKALA_2010,
            solution: Some(SOLUTION_INKALA_2010),
        };
        circuit.generate_constraints(cs.clone()).expect("synthesize");
        assert!(cs.is_satisfied().unwrap(), "constraints must be satisfied");
        let num_constraints = cs.num_constraints();
        let expected = ConstraintBreakdown::SUDOKU_9X9.total();
        assert_eq!(
            num_constraints, expected,
            "constraint count drift: synthesized {num_constraints}, expected {expected}",
        );
    }

    #[test]
    fn wrong_solution_fails_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        // Swap two cells in the solution — definitely no longer valid.
        let mut bad = SOLUTION_INKALA_2010;
        bad.swap(0, 1);
        let circuit = SudokuCircuit {
            clues: PUZZLE_INKALA_2010,
            solution: Some(bad),
        };
        circuit.generate_constraints(cs.clone()).expect("synthesize");
        assert!(
            !cs.is_satisfied().unwrap(),
            "swapped-cell solution must NOT satisfy the constraints",
        );
    }
}
