//! Fuzz harness — HyperPlonk compressed VK decompression.
//!
//! Session 114 — fuzzes
//! [`mosaic_hyperplonk::canonical::HyperPlonkVerifyingKey::from_compressed_bytes`].
//!
//! Compressed HyperPlonk VKs are 424 bytes:
//!   `n_public (4) + num_variables (4) + compressed G2 (64) +
//!    8 × compressed G1 (32) + 3 × Fr (32) = 424`
//!
//! Decompression calls `alt_bn128_compression(G2Decompress)` once and
//! `alt_bn128_compression(G1Decompress)` 8 times.
//!
//! Asserted invariant: panic-free. Length errors surface as
//! `VerifyingKeyLengthMismatch`; off-curve / malformed bytes surface
//! as `AltBn128CompressionSyscallFailed`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_hyperplonk::canonical::HyperPlonkVerifyingKey;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = HyperPlonkVerifyingKey::from_compressed_bytes(&backend, data);
});
