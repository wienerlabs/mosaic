//! Fuzz harness — Nova compressed VK decompression.
//!
//! Session 114 — fuzzes
//! [`mosaic_nova::canonical::NovaFoldingVerifyingKey::from_compressed_bytes`].
//!
//! Compressed Nova VKs are 199 bytes:
//!   `1 (variant) + 2 (n_public) + 4 (n_constraints) + 64 (G2) +
//!    3 × 32 (G1) + 32 (cs_digest) = 199`
//!
//! Decompression calls `alt_bn128_compression(G2Decompress)` once and
//! `alt_bn128_compression(G1Decompress)` 3 times.
//!
//! Asserted invariant: panic-free. Variant byte must be in `{0, 1, 2}`
//! → otherwise `UnknownProofSystem`. Length errors surface as
//! `VerifyingKeyLengthMismatch`. Off-curve points surface as
//! `AltBn128CompressionSyscallFailed`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_nova::canonical::NovaFoldingVerifyingKey;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = NovaFoldingVerifyingKey::from_compressed_bytes(&backend, data);
});
