//! Fuzz harness — KZG-PLONK combined-slot fuzzer.
//!
//! Session 59 — cross-slot interaction surface for PLONK. Mirrors
//! the session-56 Halo2 combined-fuzzer template with PLONK as the
//! verifier under test. Both PLONK's VK (744 B fixed) and proof
//! (768 B fixed) are fixed-length envelopes, so the cross-slot
//! interaction surface is narrower than Halo2's; the value is in
//! catching length-mismatch routing bugs that the per-slot harnesses
//! can't reach (e.g. a parser that confuses the two 744 B / 768 B
//! envelopes).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::split_three_slots;
use mosaic_plonk::PlonkKzgBn254;

fuzz_target!(|data: &[u8]| {
    let Some((vk, proof, public_inputs)) = split_three_slots(data) else {
        return;
    };
    let backend = HostBackend::new();
    let v = PlonkKzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, vk, proof, public_inputs);
});
