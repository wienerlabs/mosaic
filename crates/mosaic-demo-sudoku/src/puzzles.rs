//! Hard-coded demo puzzles.
//!
//! The puzzle / solution pair is Arto Inkala's 2010 "hardest"-class
//! sudoku (21 clues) — widely reproduced and benchmarked. Verified
//! by hand against the canonical solution. Public-domain — we treat
//! it as an opaque pair of 81-cell 0..=9 grids and don't re-derive
//! it. The 17-clue minimum is a separate result (McGuire et al.
//! 2012) and not what's shipped here.
//!
//! Grids are row-major: `cell[row * 9 + col]`. `0` means "blank" in
//! the puzzle (unknown to the verifier); `1..=9` are the values.

/// A 9×9 grid stored row-major.
pub type Grid = [u8; 81];

/// 17-clue ("hardest"-class) demo puzzle, clue layout only.
pub const PUZZLE_INKALA_2010: Grid = [
    8, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 3, 6, 0, 0, 0, 0, 0,
    0, 7, 0, 0, 9, 0, 2, 0, 0,
    0, 5, 0, 0, 0, 7, 0, 0, 0,
    0, 0, 0, 0, 4, 5, 7, 0, 0,
    0, 0, 0, 1, 0, 0, 0, 3, 0,
    0, 0, 1, 0, 0, 0, 0, 6, 8,
    0, 0, 8, 5, 0, 0, 0, 1, 0,
    0, 9, 0, 0, 0, 0, 4, 0, 0,
];

/// The unique solution to `PUZZLE_INKALA_2010`. Re-verified by hand
/// to satisfy: every row, column, and 3×3 box contains digits 1..=9
/// exactly once AND every clue position matches.
pub const SOLUTION_INKALA_2010: Grid = [
    8, 1, 2, 7, 5, 3, 6, 4, 9,
    9, 4, 3, 6, 8, 2, 1, 7, 5,
    6, 7, 5, 4, 9, 1, 2, 8, 3,
    1, 5, 4, 2, 3, 7, 8, 9, 6,
    3, 6, 9, 8, 4, 5, 7, 2, 1,
    2, 8, 7, 1, 6, 9, 5, 3, 4,
    5, 2, 1, 9, 7, 4, 3, 6, 8,
    4, 3, 8, 5, 2, 6, 9, 1, 7,
    7, 9, 6, 3, 1, 8, 4, 5, 2,
];

/// Validate a candidate solution against `PUZZLE_INKALA_2010`.
///
/// Used as a sanity check before handing the bytes to arkworks so the
/// circuit doesn't fail at the constraint-synthesis step (which would
/// indicate a typo'd puzzle, not a circuit bug).
#[must_use]
pub fn validate(puzzle: &Grid, solution: &Grid) -> Result<(), &'static str> {
    // Cells in {1..=9}.
    for &v in solution {
        if v < 1 || v > 9 {
            return Err("solution cell out of range");
        }
    }
    // Clues match.
    for (i, (&p, &s)) in puzzle.iter().zip(solution.iter()).enumerate() {
        if p != 0 && p != s {
            // index/row/col not exposed in the &'static str — caller
            // already knows the input pair, so a short message is
            // enough. If we ever hit this in CI, we'll add file:line.
            let _ = i;
            return Err("clue contradicts solution");
        }
    }
    // Rows, cols, boxes are permutations of 1..=9.
    for group in 0..9 {
        let mut row = [false; 9];
        let mut col = [false; 9];
        let mut bx = [false; 9];
        for k in 0..9 {
            let r = solution[group * 9 + k] as usize - 1;
            let c = solution[k * 9 + group] as usize - 1;
            let box_row = (group / 3) * 3 + (k / 3);
            let box_col = (group % 3) * 3 + (k % 3);
            let b = solution[box_row * 9 + box_col] as usize - 1;
            if row[r] {
                return Err("solution row not a permutation");
            }
            if col[c] {
                return Err("solution column not a permutation");
            }
            if bx[b] {
                return Err("solution box not a permutation");
            }
            row[r] = true;
            col[c] = true;
            bx[b] = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inkala_solution_is_valid() {
        validate(&PUZZLE_INKALA_2010, &SOLUTION_INKALA_2010)
            .expect("Inkala puzzle / solution mismatch — fix the constants");
    }
}
