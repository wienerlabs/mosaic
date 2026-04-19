//! # mosaic-core
//!
//! Foundational trait hierarchy and primitives for the **Mosaic** on-chain
//! proof verifier library on Solana. This crate is intentionally small: it
//! defines the public abstractions that every concrete verifier crate
//! ([`mosaic-groth16`], [`mosaic-plonk`], [`mosaic-stark`], [`mosaic-nova`])
//! implements, and the syscall-surface abstraction that lets host-side tests
//! and on-chain programs share verification code unmodified.
//!
//! ## Module map
//!
//! | Module | Role |
//! |---|---|
//! | [`error`] | Two-layer error model: deterministic on-chain `OnChainError` (repr-u32) and rich off-chain `DiagnosticError`. |
//! | [`proof_system`] | The `ProofSystem` trait + `ProofSystemId` discriminant enum used by the on-chain dispatcher. |
//! | [`codec`] | `ProofCodec` trait for format-tagged serialization (snarkjs, arkworks, gnark, halo2, plonky3). |
//! | [`transcript`] | `TranscriptHash` trait for Fiat-Shamir abstraction (Poseidon, Keccak, SHA-256). |
//! | [`syscall`] | `SyscallBackend` trait abstracting alt_bn128 group ops, compression, Poseidon, SHA-256, Keccak across host (arkworks) and SBF (syscalls). |
//! | [`bump`] | Stack-bounded bump arena allocator synchronized with `requested_heap_frame`. |
//!
//! ## Feature flags
//!
//! | Feature | Effect |
//! |---|---|
//! | `std` | Enables `std` library, `thiserror`-derived diagnostic errors. |
//! | `solana` | Enables `solana-program` syscall backend (required for SBF target). |
//! | `host-backend` | Enables arkworks-based software backend for host-side tests. Implies `std`. |
//! | `diagnostics` | Enables `tracing` instrumentation in error paths. Off-chain only. |
//! | `wasm` | Enables WASM-friendly path (no syscalls, host-backend only). |
//! | `formal-verify` | Reserved for future Kani/Creusot annotations. |
//!
//! ## Determinism contract
//!
//! Every code path reachable from an on-chain entrypoint must be deterministic
//! across the Agave, Firedancer, and Jito-Solana validator implementations.
//! Two validators returning different errors on the same input is a
//! consensus-failure attack vector — see [SIMD-0129][simd0129] and ADR-0002.
//!
//! [simd0129]: https://github.com/solana-foundation/solana-improvement-documents/pull/129

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod bump;
pub mod codec;
pub mod error;
pub mod proof_system;
pub mod syscall;
pub mod transcript;

pub use error::{MosaicError, OnChainError};
#[cfg(feature = "std")]
pub use error::DiagnosticError;
pub use proof_system::{ProofSystem, ProofSystemId};
pub use syscall::SyscallBackend;
pub use transcript::TranscriptHash;

/// Crate-wide `Result` alias parameterized by the on-chain deterministic error
/// type. Off-chain code that needs richer diagnostics should use
/// `Result<T, DiagnosticError>` explicitly.
pub type Result<T, E = OnChainError> = core::result::Result<T, E>;
