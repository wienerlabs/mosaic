//! Fuzz harness — arbitrary bytes treated as a KZG-PLONK proof.
//!
//! Session 54 — Phase-2 verifier surface coverage. The harness pins
//! the panic-free invariant on the PLONK verify pipeline: hostile
//! input bytes either return `Err(OnChainError::*)` or — in the rare
//! case the input happens to satisfy scaffold-acceptance rules — `Ok(())`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::PlonkFixtures;
use mosaic_plonk::PlonkKzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = PlonkFixtures::default();
    let backend = HostBackend::new();
    let v = PlonkKzgBn254::new(&backend);
    // Verifier must never panic on hostile input — only return `Err`.
    let _ = ProofSystem::verify(&v, &f.vk, data, &f.public_inputs);
});
