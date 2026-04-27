//! Fuzz harness — FRI-STARK combined-slot fuzzer.
//!
//! Session 59 — cross-slot interaction surface for FRI-STARK. The
//! richest cross-check fingerprint of any verifier in the workspace:
//!
//! - `vk.field_id == proof.field_id` (StarkFieldId 3-way tag).
//! - `vk.trace_log_height == proof.trace_log_height`
//! - `vk.trace_width == proof.trace_width`
//! - `vk.log_blowup == proof.log_blowup`
//!
//! Each must agree across slots; a coordinated lie on any of these
//! would route the verifier to a wrong-shape Merkle path or FRI
//! fold chain. The combined fuzzer explores every such coordinated
//! misalignment automatically.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::split_three_slots;
use mosaic_stark::FriStark;

fuzz_target!(|data: &[u8]| {
    let Some((vk, proof, public_inputs)) = split_three_slots(data) else {
        return;
    };
    let backend = HostBackend::new();
    let v = FriStark::new(&backend);
    let _ = ProofSystem::verify(&v, vk, proof, public_inputs);
});
