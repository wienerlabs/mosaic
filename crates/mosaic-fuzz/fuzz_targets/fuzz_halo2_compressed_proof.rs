//! Fuzz harness — Halo2-KZG compressed proof decompression.
//!
//! Session 111 — fuzzes session-108
//! `Halo2KzgProof::decompress_to_canonical_bytes`. Compressed
//! Halo2 proofs have a variable-length structure driven by the
//! 5-counter header (n_advice, n_lookups, n_quotient, n_evals,
//! lookup_arity). The decompression path:
//!   - Validates header counters against MAX_* bounds.
//!   - Computes expected total length:
//!     `header + (n_advice + n_lookups + 1 + n_quotient + 2) × 32 + n_evals × 32`.
//!   - Iterates each G1 commit slot and calls
//!     `alt_bn128_compression(G1Decompress)`.
//!   - Copies Fr evaluations as-is.
//!
//! Asserted invariant: panic-free for every byte sequence.
//!
//! Catches:
//!  - header counters over MAX bounds (must reject pre-syscall)
//!  - usize overflow in `checked_mul` paths
//!  - off-curve compressed G1 points
//!  - byte-slice boundary issues at the variable-length payload
//!  - lookup_arity = 0 reinterpretation as DEFAULT_LOOKUP_ARITY = 1
//!
//! See v0.9.7-halo2-proof-compressed for the wire-format spec.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mosaic_core::syscall::host::HostBackend;
use mosaic_halo2::canonical::Halo2KzgProof;

fuzz_target!(|data: &[u8]| {
    let backend = HostBackend::new();
    let _ = Halo2KzgProof::decompress_to_canonical_bytes(&backend, data);
});
