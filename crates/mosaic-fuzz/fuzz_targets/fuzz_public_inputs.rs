//! Fuzz harness — arbitrary bytes treated as Groth16 public inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::SharedFixtures;
use mosaic_groth16::Groth16Verifier;

fuzz_target!(|data: &[u8]| {
    let fixtures = SharedFixtures::default();
    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);
    let _ = ProofSystem::verify(&v, &fixtures.vk, &fixtures.proof, data);
});
