//! Fuzz harness — arbitrary bytes treated as a FRI-STARK proof.
//!
//! Session 54 — Phase-3 body coverage. Pins the panic-free invariant
//! on the STARK verify pipeline (parse → variable-tail length checks
//! → field-id dispatch → per-query Merkle path verification → FRI
//! low-degree test).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::StarkFixtures;
use mosaic_stark::FriStark;

fuzz_target!(|data: &[u8]| {
    let f = StarkFixtures::default();
    let backend = HostBackend::new();
    let v = FriStark::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, data, &f.public_inputs);
});
