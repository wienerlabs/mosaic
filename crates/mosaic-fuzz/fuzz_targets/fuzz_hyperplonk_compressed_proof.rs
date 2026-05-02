//! Fuzz harness — HyperPlonk compressed proof decompression.
//!
//! Session 114 — fuzzes
//! [`mosaic_hyperplonk::canonical::HyperPlonkProof::decompress_to_canonical_bytes`].
//!
//! Compressed HyperPlonk proofs have variable length:
//!   `MIN_COMPRESSED_LEN + 96 · sumcheck_rounds`
//! where `sumcheck_rounds` is read from the buffer at offset 128.
//! The decompression path calls `alt_bn128_compression(G1Decompress)`
//! 5 times (a, b, c, z, kzg_opening) and copies the Fr region as-is.
//!
//! Asserted invariant: panic-free for every byte sequence.
//! Returns `Ok(Vec<u8>)` only for valid layouts with on-curve points.
//! Length / round-counter / variant errors all surface as
//! `Err(OnChainError::*)` deterministically.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_hyperplonk::canonical::HyperPlonkProof;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = HyperPlonkProof::decompress_to_canonical_bytes(&backend, data);
});
