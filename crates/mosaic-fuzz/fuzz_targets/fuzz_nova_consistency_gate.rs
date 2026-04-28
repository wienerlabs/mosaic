//! Fuzz harness — Nova `verify_folding_consistency` audit gate.
//!
//! Session 95 — fuzzes the audit-gate primitive directly, NOT the
//! verifier's outer entry point. The existing
//! `fuzz_nova_{proof,vk,public_inputs,combined}` harnesses fuzz the
//! verifier's parsing surface; this new harness fuzzes the algebraic
//! soundness boundary.
//!
//! Input layout (7 × 64 G1 + 32 Fr = 480 bytes minimum):
//!
//! ```text
//! [base_e_1: 64 B]
//! [base_e_2: 64 B]
//! [base_w_1: 64 B]
//! [base_w_2: 64 B]
//! [t_comm:   64 B]
//! [decl_e:   64 B]
//! [decl_w:   64 B]
//! [r:        32 B Fr]   — interpreted as canonical BE bytes
//! ```
//!
//! Inputs shorter than the minimum are early-rejected (return without
//! panic). Inputs ≥ minimum are passed verbatim to the gate.
//!
//! Asserted invariant: the gate must always return `Ok(())` or
//! `Err(OnChainError::*)` — never panic. Catches:
//!
//! - syscall payload mishandling that could panic in arkworks
//! - Fr deserialization edge cases
//! - byte-slice boundary issues at the 7-input boundary
//!
//! ADR-0006 reference for the gate's contract: see
//! [`mosaic_nova::verify_folding_consistency`].

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_nova::verify_folding_consistency;
use mosaic_zk_primitives::field::fr_from_canonical_bytes;

const G1_LEN: usize = 64;
const FR_LEN: usize = 32;
const MIN_INPUT_LEN: usize = 7 * G1_LEN + FR_LEN; // 480 B

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN_INPUT_LEN {
        return;
    }
    let mut off = 0;
    let base_e_1 = &data[off..off + G1_LEN];
    off += G1_LEN;
    let base_e_2 = &data[off..off + G1_LEN];
    off += G1_LEN;
    let base_w_1 = &data[off..off + G1_LEN];
    off += G1_LEN;
    let base_w_2 = &data[off..off + G1_LEN];
    off += G1_LEN;
    let t_comm = &data[off..off + G1_LEN];
    off += G1_LEN;
    let decl_e = &data[off..off + G1_LEN];
    off += G1_LEN;
    let decl_w = &data[off..off + G1_LEN];
    off += G1_LEN;
    let r_bytes = &data[off..off + FR_LEN];

    // Fr deserialization is the only path that can early-fail before
    // reaching the gate — propagate that as an early return.
    let Ok(r) = fr_from_canonical_bytes(r_bytes) else {
        return;
    };

    let backend = HostBackend::new();
    // Either Ok(()) or Err(_) is acceptable; a panic is a fuzzer find.
    let _ = verify_folding_consistency(
        &backend, base_e_1, base_e_2, base_w_1, base_w_2, t_comm, decl_e, decl_w, &r,
    );
});
