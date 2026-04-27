//! Fuzz harness — arbitrary bytes treated as a KZG-PLONK verifying key.
//!
//! Session 55 — Phase-2 VK surface coverage. Pins the panic-free
//! invariant on PLONK's VK byte-layout parser: a 744-byte fixed
//! envelope. Any input that doesn't exactly match must surface as
//! `Err(VerifyingKeyLengthMismatch)` and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::PlonkFixtures;
use mosaic_plonk::PlonkKzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = PlonkFixtures::default();
    let backend = HostBackend::new();
    let v = PlonkKzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, data, &f.proof, &f.public_inputs);
});
