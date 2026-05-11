//! # mosaic-demo-sudoku
//!
//! Real ZK-Sudoku demo for the Mosaic onepager.
//!
//! What it proves: knowledge of a valid solution to a 9×9 sudoku
//! puzzle whose clues are public. The prover never reveals the
//! solution — only that one exists.
//!
//! Stack:
//!   - Circuit: arkworks r1cs (this crate, low-level Variable +
//!     LinearCombination API; no `ark-r1cs-std` dependency).
//!   - Setup + prover: `ark-groth16` over BN254.
//!   - Canonical byte adapter: `mosaic-serde::arkworks::ArkworksCodec`.
//!   - Verifier: `mosaic-groth16::Groth16Verifier` over the
//!     `mosaic-core::syscall::host::HostBackend`. The byte format is
//!     identical to what the on-chain `mosaic-program` accepts.
//!
//! Soundness caveat
//!
//! The circuit's group constraint uses the power-sum check (sum and
//! sum-of-squares per row/column/box equal 45 and 285 respectively).
//! Combined with the in-range check (each cell ∈ {1..9}) this is
//! sufficient for the demo's purpose — demonstrating Mosaic's
//! verifier loop — but is NOT a production-strength permutation
//! check. A real deployment would add pairwise-inequality witnesses
//! (36 per group × 27 groups = 972 extra constraints) or a lookup
//! argument. See `circuit::constraint_count_breakdown()` for the
//! exact tally.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod circuit;
pub mod prover;
pub mod puzzles;
