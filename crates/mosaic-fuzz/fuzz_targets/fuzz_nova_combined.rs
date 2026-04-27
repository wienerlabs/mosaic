//! Fuzz harness — Nova folding combined-slot fuzzer.
//!
//! Session 59 — cross-slot interaction surface for Nova. Two cross-
//! checks need coordinated misalignment to surface:
//!
//! - `vk.variant == proof.variant` (FoldingVariant 3-way tag must
//!   agree across both slots).
//! - `vk.n_public == proof.n_public == public_inputs.len() / 32`.
//!
//! The combined fuzzer can vary all three slots independently and
//! hit coordinated lies that single-slot harnesses can't reach.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_fuzz::split_three_slots;
use mosaic_nova::NovaFolding;

fuzz_target!(|data: &[u8]| {
    let Some((vk, proof, public_inputs)) = split_three_slots(data) else {
        return;
    };
    let backend = HostBackend::new();
    let v = NovaFolding::new(&backend);
    let _ = ProofSystem::verify(&v, vk, proof, public_inputs);
});
