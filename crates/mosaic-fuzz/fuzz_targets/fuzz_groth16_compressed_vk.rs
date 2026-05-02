//! Fuzz harness — Groth16 compressed VK decoding.
//!
//! Session 111 — fuzzes the session-109
//! `Groth16VerifyingKey::from_compressed_bytes` API. The compressed
//! VK is a 32-byte α (G1) + 3 × 64-byte β/γ/δ (G2) + n × 32-byte IC
//! (G1) tail. The parser performs:
//!   - 1 G1 decompression (α)
//!   - 3 G2 decompressions (β, γ, δ)
//!   - n G1 decompressions (IC vector)
//! Any malformed input must surface as
//! `Err(OnChainError::VerifyingKeyLengthMismatch)` or
//! `Err(OnChainError::AltBn128CompressionSyscallFailed)` without
//! panicking.
//!
//! Catches:
//!  - non-multiple IC tail lengths (must reject pre-syscall)
//!  - off-curve x-coordinates (syscall rejects)
//!  - empty IC tail (Groth16 soundness requires ic.len ≥ 1)
//!  - very long IC vectors that exhaust allocation
//!
//! See v0.9.8-groth16-compressed for the wire-format spec.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_groth16::Groth16VerifyingKey;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = Groth16VerifyingKey::from_compressed_bytes(&backend, data);
});
