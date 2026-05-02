//! Fuzz harness — Halo2-KZG compressed VK decoding.
//!
//! Session 111 — fuzzes session-106
//! `Halo2KzgVerifyingKey::from_compressed_bytes`. Compressed Halo2
//! VK has a fixed 4-counter header (k, n_instances, n_advice,
//! n_fixed) + 64-byte compressed G2 (x2_g2) + 32-byte Fr
//! (omega_fr) + 2 length prefixes (fixed_compressed_len,
//! perm_compressed_len) + variable-length compressed commit
//! payloads.
//!
//! The session-105 internal-consistency checks (adapted to
//! compressed sizes) reject:
//!   - fixed_compressed_len ≠ n_fixed × 32
//!   - non-multiple-of-32 fixed/perm lengths
//!   - total length mismatch with the declared shape
//!
//! Asserted invariant: panic-free for every byte sequence.
//!
//! Catches:
//!  - Wrong-length payloads
//!  - n_fixed declared / actual mismatch
//!  - Off-curve compressed G1/G2 points
//!  - Empty buffer (must reject upfront)
//!  - Adversarial header counters that pass the COMPRESSED_FIXED_LEN
//!    pre-check but cause downstream slice arithmetic issues
//!
//! See v0.9.5-halo2-vk-compressed for the wire-format spec.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_halo2::canonical::Halo2KzgVerifyingKey;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = Halo2KzgVerifyingKey::from_compressed_bytes(&backend, data);
});
