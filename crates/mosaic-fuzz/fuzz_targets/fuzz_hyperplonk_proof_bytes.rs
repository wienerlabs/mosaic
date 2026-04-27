//! Fuzz harness — arbitrary bytes treated as a HyperPlonk-KZG proof.
//!
//! Session 54 — Phase-3 body coverage. Pins the panic-free invariant
//! on the HyperPlonk verify pipeline (parse → challenges → sumcheck
//! → claim reduction → KZG pairing).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::HyperPlonkFixtures;
use mosaic_hyperplonk::HyperPlonkKzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = HyperPlonkFixtures::default();
    let backend = HostBackend::new();
    let v = HyperPlonkKzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, data, &f.public_inputs);
});
