//! Fuzz harness — arbitrary bytes treated as FRI-STARK public inputs.
//!
//! Session 58 — public-input parser surface for STARK. STARK PI is
//! a sequence of field-id-specific elements (Goldilocks 8-byte LE,
//! BabyBear 4-byte LE, Mersenne31 4-byte LE) absorbed into the
//! domain-separated transcript seed. The parser must reject
//! lengths that aren't a multiple of `field_id.field_elem_bytes()`
//! and panic-free on every other adversarial input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::StarkFixtures;
use mosaic_stark::FriStark;

fuzz_target!(|data: &[u8]| {
    let f = StarkFixtures::default();
    let backend = HostBackend::new();
    let v = FriStark::new(&backend);
    let _ = ProofSystem::verify(&v, &f.vk, &f.proof, data);
});
