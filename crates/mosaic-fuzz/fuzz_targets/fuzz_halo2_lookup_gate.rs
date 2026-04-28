//! Fuzz harness — Halo2 `verify_multi_column_lookup_identity` audit gate.
//!
//! Session 95 — fuzzes the audit-gate primitive directly. The
//! existing `fuzz_halo2_*` harnesses fuzz the verifier's outer entry
//! point; this harness fuzzes the multi-column lookup soundness
//! boundary specifically.
//!
//! Input layout (variable arity):
//!
//! ```text
//! [arity:        1 B u8, clamped to 1..=8]
//! [m_eval:       32 B Fr]
//! [theta:        32 B Fr]
//! [input_cols:   arity × 32 B Fr]
//! [table_cols:   arity × 32 B Fr]
//! ```
//!
//! Total = 1 + 32 + 32 + 2·arity·32 = 65 + 64·arity bytes.
//! With arity ≤ 8: max 577 bytes.
//!
//! The audit gate has documented rejection paths for:
//! - Empty cols (`ProofLengthMismatch`)
//! - Arity mismatch (`ProofLengthMismatch`)
//! - θ = 0 (`InternalInvariantViolation`)
//! - Denominator inverse failure (`InternalInvariantViolation`)
//! - Non-vanishing identity (`SumcheckFailed`)
//!
//! The fuzzer must always reach one of these or `Ok(())` — never panic.
//!
//! ADR-0006 reference: see
//! [`mosaic_halo2::verify_multi_column_lookup_identity`].

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_halo2::{verify_multi_column_lookup_identity, MultiColumnLookupEvals};
use mosaic_zk_primitives::field::fr_from_canonical_bytes;

const FR_LEN: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Clamp arity to [1, 8]. arity = 0 case exercised by unit tests
    // (try_new rejects empty); fuzzer focuses on valid arities.
    let arity = (data[0] % 8 + 1) as usize;
    let needed = 1 + 2 * FR_LEN + 2 * arity * FR_LEN;
    if data.len() < needed {
        return;
    }
    let mut off = 1;

    let Ok(m) = fr_from_canonical_bytes(&data[off..off + FR_LEN]) else {
        return;
    };
    off += FR_LEN;
    let Ok(theta) = fr_from_canonical_bytes(&data[off..off + FR_LEN]) else {
        return;
    };
    off += FR_LEN;

    let mut input_cols = Vec::with_capacity(arity);
    for _ in 0..arity {
        let Ok(col) = fr_from_canonical_bytes(&data[off..off + FR_LEN]) else {
            return;
        };
        input_cols.push(col);
        off += FR_LEN;
    }
    let mut table_cols = Vec::with_capacity(arity);
    for _ in 0..arity {
        let Ok(col) = fr_from_canonical_bytes(&data[off..off + FR_LEN]) else {
            return;
        };
        table_cols.push(col);
        off += FR_LEN;
    }

    let Ok(lookup) = MultiColumnLookupEvals::try_new(input_cols, table_cols, m) else {
        return;
    };

    // Either Ok(()) or any of the documented Err variants is acceptable.
    let _ = verify_multi_column_lookup_identity(&lookup, &theta);
});
