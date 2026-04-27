//! Fuzz harness — arbitrary bytes treated as KZG-PLONK public inputs.
//!
//! Session 58 — public-input parser surface. Pins the panic-free
//! invariant on the PLONK PI parser, including Fr-range validation
//! (`PublicInputOutOfRange`) and length-vs-`vk.n_public` consistency
//! (`PublicInputCountMismatch`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::PlonkFixtures;
use mosaic_plonk::PlonkKzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = PlonkFixtures::default();
    let backend = HostBackend::new();
    let v = PlonkKzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, &f.proof, data);
});
