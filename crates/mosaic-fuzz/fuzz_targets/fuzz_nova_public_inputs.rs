//! Fuzz harness — arbitrary bytes treated as Nova folding public inputs.
//!
//! Session 58 — public-input parser surface for Nova. PI is a
//! variable-length Fr vector (length = `vk.n_public * 32`) absorbed
//! into the round-1 transcript alongside the accumulator commitments.
//! Length and Fr-range invariants are pinned by the harness across
//! the full byte-buffer space.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::NovaFixtures;
use mosaic_nova::NovaFolding;

fuzz_target!(|data: &[u8]| {
    let f = NovaFixtures::default();
    let backend = HostBackend::new();
    let v = NovaFolding::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, &f.proof, data);
});
