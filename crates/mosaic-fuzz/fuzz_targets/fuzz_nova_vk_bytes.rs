//! Fuzz harness — arbitrary bytes treated as a Nova folding VK.
//!
//! Session 55 — Phase-3 VK surface coverage. Nova's VK is a fixed
//! 235-byte envelope (1 + 2 + 4 + 128 + 3·64 + 32) with a 3-way
//! variant tag at offset 0. The harness pins:
//!
//!   - the `FoldingVariant::from_byte` rejection for tags ∉ {0, 1, 2}
//!   - the fixed-length envelope check
//!   - panic-free behaviour on every other adversarial input shape

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::NovaFixtures;
use mosaic_nova::NovaFolding;

fuzz_target!(|data: &[u8]| {
    let f = NovaFixtures::default();
    let backend = HostBackend::new();
    let v = NovaFolding::new(&backend);
    let _ = ProofSystem::verify(&v, data, &f.proof, &f.public_inputs);
});
