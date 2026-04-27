//! Fuzz harness — arbitrary bytes treated as HyperPlonk public inputs.
//!
//! Session 58 — public-input parser surface for HyperPlonk. The PI
//! parser must enforce `len % 32 == 0`, `len / 32 == vk.n_public`,
//! and Fr-range on every chunk. Any panic on adversarial PI is a
//! fuzzer-found bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::HyperPlonkFixtures;
use mosaic_hyperplonk::HyperPlonkKzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = HyperPlonkFixtures::default();
    let backend = HostBackend::new();
    let v = HyperPlonkKzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, &f.proof, data);
});
