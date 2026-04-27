//! Fuzz harness — HyperPlonk-KZG combined-slot fuzzer.
//!
//! Session 59 — cross-slot interaction surface for HyperPlonk. The
//! `vk.num_variables == proof.sumcheck_rounds` cross-check is the
//! core invariant a combined fuzzer can hit that single-slot
//! harnesses can't: both slots must lie about the same shape
//! parameter for the bug to surface. The harness explores that
//! coordinated misalignment automatically.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::split_three_slots;
use mosaic_hyperplonk::HyperPlonkKzgBn254;

fuzz_target!(|data: &[u8]| {
    let Some((vk, proof, public_inputs)) = split_three_slots(data) else {
        return;
    };
    let backend = HostBackend::new();
    let v = HyperPlonkKzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, vk, proof, public_inputs);
});
