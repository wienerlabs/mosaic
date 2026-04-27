//! Fuzz harness — arbitrary bytes treated as a Halo2-KZG proof.
//!
//! Session 54 — Phase-3 body coverage. Pins the panic-free invariant
//! on the Halo2 verify pipeline (parse → challenges → multi-poly
//! batched opening → KZG pairing).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::Halo2Fixtures;
use mosaic_halo2::Halo2KzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = Halo2Fixtures::default();
    let backend = HostBackend::new();
    let v = Halo2KzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, data, &f.public_inputs);
});
