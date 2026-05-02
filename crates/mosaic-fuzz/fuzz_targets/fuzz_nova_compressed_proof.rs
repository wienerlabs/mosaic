//! Fuzz harness — Nova / HyperNova / ProtoStar compressed proof decompression.
//!
//! Session 114 — fuzzes
//! [`mosaic_nova::canonical::NovaFoldingProof::decompress_to_canonical_bytes`].
//!
//! Nova proof shape: 9 fixed G1 + variable `num_aux` G1 + Fr regions.
//! Compressed length:
//!   `compressed_len_for_shape(num_aux, n_public)`
//!   = 16 + (9 + num_aux) · 32 + Fr regions
//!
//! Decompression calls `alt_bn128_compression(G1Decompress)`
//! `(9 + num_aux)` times. Variant byte rejected for any value
//! outside `{0, 1, 2}`.
//!
//! Asserted invariant: panic-free. Returns `Ok(Vec<u8>)` only for
//! valid layouts with on-curve points + recognized variant.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_nova::canonical::NovaFoldingProof;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = NovaFoldingProof::decompress_to_canonical_bytes(&backend, data);
});
