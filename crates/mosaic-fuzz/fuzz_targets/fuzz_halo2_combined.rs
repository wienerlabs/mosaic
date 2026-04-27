//! Fuzz harness — Halo2-KZG combined-slot fuzzer.
//!
//! Session 56 — cross-slot interaction surface coverage.
//!
//! The single-slot harnesses in `fuzz_*_proof_bytes.rs` and
//! `fuzz_*_vk_bytes.rs` (sessions 54, 55) each fix two of the three
//! verifier inputs to scaffold-acceptance fixtures and vary the
//! third. That's enough to catch single-slot parser bugs but it
//! deliberately does NOT exercise the cross-slot interaction
//! surface — bugs that only surface when, e.g., the VK and the
//! proof BOTH lie about the same shape parameter in a coordinated
//! way that the structural cross-check missed.
//!
//! This harness splits the libfuzzer input into three length-prefixed
//! sub-buffers (vk, proof, public_inputs) and feeds all three to
//! the Halo2 verifier. A single fuzz iteration explores a coordinate
//! in `(vk_bytes, proof_bytes, pi_bytes)` space rather than the
//! 1-dimensional slice the per-slot harnesses cover.
//!
//! Layout: `[vk_len: u16 LE] [vk_bytes: vk_len B] [proof_len: u16 LE]
//! [proof_bytes: proof_len B] [public_inputs ...]`
//!
//! A malformed length prefix that runs off the end of the input
//! short-circuits the iteration (no panic, no verifier call).
//! Otherwise the verifier sees three slices the fuzzer can vary
//! independently, sized 0..=u16::MAX bytes each.
//!
//! Halo2 was chosen as the first combined fuzzer target because:
//! - it has the richest VK shape (variable-length tail) AND the
//!   richest proof shape (4 dynamic counters in the canonical
//!   header), so the cross-slot interaction surface is widest;
//! - if this pattern proves valuable, the same template can be
//!   copy-pasted for the other 4 systems with minor adjustments
//!   (HyperPlonk, Nova, STARK, PLONK).

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_halo2::Halo2KzgBn254;

fn split_three(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut cursor = data;

    // vk_len (u16 LE).
    if cursor.len() < 2 {
        return None;
    }
    let (lp, rest) = cursor.split_at(2);
    let vk_len = u16::from_le_bytes([lp[0], lp[1]]) as usize;
    if rest.len() < vk_len {
        return None;
    }
    let (vk, rest) = rest.split_at(vk_len);
    cursor = rest;

    // proof_len (u16 LE).
    if cursor.len() < 2 {
        return None;
    }
    let (lp, rest) = cursor.split_at(2);
    let proof_len = u16::from_le_bytes([lp[0], lp[1]]) as usize;
    if rest.len() < proof_len {
        return None;
    }
    let (proof, public_inputs) = rest.split_at(proof_len);

    // Whatever remains is the public-inputs slot.
    Some((vk, proof, public_inputs))
}

fuzz_target!(|data: &[u8]| {
    let Some((vk, proof, public_inputs)) = split_three(data) else {
        return;
    };
    let backend = HostBackend::new();
    let v = Halo2KzgBn254::new(&backend);
    // Verifier must never panic on hostile input — only return `Err`
    // (or, in the rare scaffold-acceptance case, `Ok(())`).
    let _ = ProofSystem::verify(&v, vk, proof, public_inputs);
});
