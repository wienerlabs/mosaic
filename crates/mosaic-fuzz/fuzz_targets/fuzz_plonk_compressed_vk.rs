//! Fuzz harness — KZG-PLONK compressed VK decoding.
//!
//! Session 111 — fuzzes session-110
//! `PlonkVerifyingKey::from_compressed_bytes`. Compressed PLONK VK
//! is exactly 424 bytes (8 G1 + 1 G2 + 3 Fr + 2 u32). No variable-
//! length tail (unlike Groth16's IC vector), so length validation
//! is a simple equality check. The parser performs:
//!   - 8 G1 decompressions (selectors q_M/L/R/O/C + perm σ_1/2/3)
//!   - 1 G2 decompression (X_2 SRS)
//!   - 3 raw 32-byte Fr field copies (k1, k2, omega)
//!   - 2 raw u32 LE reads (power, n_public)
//!
//! Asserted invariant: panic-free.
//!
//! Catches:
//!  - lengths ≠ 424
//!  - off-curve compressed points
//!  - syscall payload mishandling
//!
//! See v0.9.9-plonk-compressed for the wire-format spec.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_plonk::canonical::PlonkVerifyingKey;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = PlonkVerifyingKey::from_compressed_bytes(&backend, data);
});
