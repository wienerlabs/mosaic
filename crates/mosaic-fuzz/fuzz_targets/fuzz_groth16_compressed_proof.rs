//! Fuzz harness — Groth16 compressed proof decompression.
//!
//! Session 111 — fuzzes the session-109
//! `Groth16Proof::decompress_to_canonical_bytes` syscall surface.
//! Compressed Groth16 proofs are 128 bytes (2 G1 + 1 G2). The
//! decompression path calls `alt_bn128_compression(G1Decompress)`
//! twice and `alt_bn128_compression(G2Decompress)` once — any
//! malformed input must surface as `Err(OnChainError::*)` without
//! panicking.
//!
//! Asserted invariant: the function returns `Ok(_)` or `Err(_)` for
//! every byte sequence; any panic is a fuzzer-found bug.
//!
//! Catches:
//!  - syscall payload mishandling
//!  - off-curve x-coordinates that decompression must reject
//!  - sign-bit edge cases in compressed encoding
//!  - byte-slice boundary issues at the 32/64/32 split
//!
//! See `crates/mosaic-groth16/src/canonical.rs` for the function
//! under test and v0.9.8-groth16-compressed for the wire-format spec.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_groth16::Groth16Proof;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    // Either Ok(Vec<u8>) or Err(OnChainError) is acceptable;
    // a panic is a fuzzer find.
    let _ = Groth16Proof::decompress_to_canonical_bytes(&backend, data);
});
