//! Fuzz harness — arbitrary bytes treated as a Nova folding proof.
//!
//! Session 54 — Phase-3 body coverage. Pins the panic-free invariant
//! on the Nova verify pipeline (parse → variant tag → challenges →
//! Hadamard residual check → Spartan-batched KZG opening).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::NovaFixtures;
use mosaic_nova::NovaFolding;

fuzz_target!(|data: &[u8]| {
    let f = NovaFixtures::default();
    let backend = HostBackend::new();
    let v = NovaFolding::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, data, &f.public_inputs);
});
