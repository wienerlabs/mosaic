//! Fuzz harness — arbitrary bytes treated as a FRI-STARK VK.
//!
//! Session 55 — Phase-3 VK surface coverage. FRI-STARK's VK is a
//! fixed 48-byte envelope (1 + 4 + 2 + 1 + 32 + 8) with a 3-way
//! field-id tag at offset 0. The harness pins:
//!
//!   - the `StarkFieldId::from_byte` rejection for tags ∉ {0, 1, 2}
//!   - the fixed 48-byte envelope check
//!   - the structural cross-check `vk.{trace_log_height,
//!     trace_width, log_blowup} == proof.*` against the bench's
//!     scaffold proof shape

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::StarkFixtures;
use mosaic_stark::FriStark;

fuzz_target!(|data: &[u8]| {
    let f = StarkFixtures::default();
    let backend = HostBackend::new();
    let v = FriStark::new(&backend);
    let _ = ProofSystem::verify(&v, data, &f.proof, &f.public_inputs);
});
