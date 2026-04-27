//! Fuzz harness — arbitrary bytes treated as a HyperPlonk-KZG VK.
//!
//! Session 55 — Phase-3 VK surface coverage. HyperPlonk's VK is a
//! fixed 744-byte envelope (4 + 4 + 128 + 8·64 + 3·32). The harness
//! pins the panic-free invariant on the VK parser plus the structural
//! cross-check `vk.num_variables == proof.sumcheck_rounds`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::HyperPlonkFixtures;
use mosaic_hyperplonk::HyperPlonkKzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = HyperPlonkFixtures::default();
    let backend = HostBackend::new();
    let v = HyperPlonkKzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, data, &f.proof, &f.public_inputs);
});
