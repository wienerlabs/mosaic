//! Fuzz harness — STARK `verify_fri_query` audit gate.
//!
//! Session 95 — fuzzes the per-query FRI audit-gate primitive directly
//! over a randomized layer count + per-layer evaluations + final
//! polynomial.
//!
//! Input layout (variable):
//!
//! ```text
//! [num_layers:    1 B u8, clamped to 0..=8]
//! [initial_x:     8 B Goldilocks LE]
//! [layer_evals:   num_layers × 16 B (f_x ‖ f_neg_x), each 8 B]
//! [betas:         num_layers × 8 B Goldilocks LE]
//! [final_poly:    remaining bytes, padded to multiple of 8]
//! ```
//!
//! Each Goldilocks element must be < `2^64 - 2^32 + 1`; out-of-range
//! values are early-rejected.
//!
//! The gate's documented rejection paths:
//! - Length mismatch between layer_evals and betas (`ProofLengthMismatch`)
//! - Fold arithmetic degeneracy (e.g. `x = 0`, `InternalInvariantViolation`)
//! - Layer-to-layer `f_x` consistency failure (`VerificationFailed`)
//! - Final-poly evaluation mismatch (`VerificationFailed`)
//!
//! Final-poly bytes are passed verbatim — `eval_poly_le_bytes`
//! tolerates any multiple-of-8 length (rejects partial trailing
//! coefficient). Non-multiples are rejected by the gate's
//! propagation path.
//!
//! ADR-0006 reference: see [`mosaic_stark::verify_fri_query`].

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_stark::{verify_fri_query, Goldilocks};

const GOLDILOCKS_LEN: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Clamp to [0, 8] layers.
    let num_layers = (data[0] % 9) as usize;
    let needed_fixed = 1 + GOLDILOCKS_LEN; // num_layers byte + initial_x
    let needed_per_layer = 2 * GOLDILOCKS_LEN + GOLDILOCKS_LEN; // (f_x, f_neg_x) + beta
    let needed_min = needed_fixed + num_layers * needed_per_layer;
    if data.len() < needed_min {
        return;
    }

    let mut off = 1;

    // initial_x
    let mut x_arr = [0u8; GOLDILOCKS_LEN];
    x_arr.copy_from_slice(&data[off..off + GOLDILOCKS_LEN]);
    off += GOLDILOCKS_LEN;
    let Ok(initial_x) = Goldilocks::from_bytes_le(&x_arr) else {
        return;
    };

    // layer_evals
    let mut layer_evals = Vec::with_capacity(num_layers);
    for _ in 0..num_layers {
        let mut fx_arr = [0u8; GOLDILOCKS_LEN];
        fx_arr.copy_from_slice(&data[off..off + GOLDILOCKS_LEN]);
        off += GOLDILOCKS_LEN;
        let Ok(f_x) = Goldilocks::from_bytes_le(&fx_arr) else {
            return;
        };
        let mut fnx_arr = [0u8; GOLDILOCKS_LEN];
        fnx_arr.copy_from_slice(&data[off..off + GOLDILOCKS_LEN]);
        off += GOLDILOCKS_LEN;
        let Ok(f_neg_x) = Goldilocks::from_bytes_le(&fnx_arr) else {
            return;
        };
        layer_evals.push((f_x, f_neg_x));
    }

    // betas
    let mut betas = Vec::with_capacity(num_layers);
    for _ in 0..num_layers {
        let mut b_arr = [0u8; GOLDILOCKS_LEN];
        b_arr.copy_from_slice(&data[off..off + GOLDILOCKS_LEN]);
        off += GOLDILOCKS_LEN;
        let Ok(beta) = Goldilocks::from_bytes_le(&b_arr) else {
            return;
        };
        betas.push(beta);
    }

    // final_poly = remaining bytes; pass verbatim.
    let final_poly_bytes = &data[off..];

    // Either Ok(()) or any of the documented Err variants is acceptable.
    let _ = verify_fri_query(&layer_evals, &betas, initial_x, final_poly_bytes);
});
