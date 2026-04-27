//! Fuzz harness — arbitrary bytes treated as a Halo2-KZG VK.
//!
//! Session 55 — Phase-3 VK surface coverage. Halo2's VK has a
//! variable-length tail (fixed_commits ‖ permutation_commits) so
//! the harness exercises both the fixed-header parser and the
//! length-prefixed payload bounds checks. Empty IC equivalents
//! (zero-length payload) and oversized payloads are both expected
//! to surface as `Err(VerifyingKeyLengthMismatch)`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::Halo2Fixtures;
use mosaic_halo2::Halo2KzgBn254;

fuzz_target!(|data: &[u8]| {
    let f = Halo2Fixtures::default();
    let backend = HostBackend::new();
    let v = Halo2KzgBn254::new(&backend);
    let _ = ProofSystem::verify(&v, data, &f.proof, &f.public_inputs);
});
