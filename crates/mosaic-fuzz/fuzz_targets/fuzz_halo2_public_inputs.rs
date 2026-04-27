//! Fuzz harness — arbitrary bytes treated as Halo2 public inputs.
//!
//! Session 58 — public-input parser surface for Halo2. The PI bytes
//! feed `derive_challenges`'s round-1 absorb, so a regression here
//! would cascade into every Fiat-Shamir challenge. Length and
//! Fr-range checks in `from_bytes` must reject any malformed buffer
//! before the absorb runs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::Halo2Fixtures;
use mosaic_halo2::Halo2KzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = Halo2Fixtures::default();
    let backend = HostBackend::new();
    let v = Halo2KzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, &f.proof, data);
});
