//! Fuzz harness — KZG-PLONK compressed proof decompression.
//!
//! Session 111 — fuzzes session-110
//! `PlonkProof::decompress_to_canonical_bytes`. Compressed PLONK
//! proofs are 480 bytes (9 G1 + 6 Fr). The decompression path
//! calls `alt_bn128_compression(G1Decompress)` 9 times and copies
//! the 6 Fr evals as-is.
//!
//! Asserted invariant: panic-free for every byte sequence.
//! Returns `Ok(Vec<u8>)` for valid 480-byte inputs with on-curve
//! compressed points, `Err(OnChainError::ProofLengthMismatch)` for
//! wrong-length inputs, and
//! `Err(OnChainError::AltBn128CompressionSyscallFailed)` for any
//! G1 commit that fails decompression.
//!
//! See v0.9.9-plonk-compressed for the wire-format spec.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_plonk::canonical::PlonkProof;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = PlonkProof::decompress_to_canonical_bytes(&backend, data);
});
