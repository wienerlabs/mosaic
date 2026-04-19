//! `TranscriptHash` trait — a Fiat-Shamir abstraction layered over the
//! syscall surface.
//!
//! Hash-based proof systems (PLONK, STARK) derive verifier challenges from a
//! transcript that absorbs the verifying key and the prover's commitments,
//! then squeezes pseudo-random field elements. Different systems pick
//! different hashes:
//!
//! - **Poseidon (BN254 scalar field, x⁵ S-box)** — Circom-compatible Groth16
//!   ecosystem; available via `sol_poseidon` syscall.
//! - **Keccak-256** — Ethereum-compatible (zkEVM, gnark default).
//! - **SHA-256** — STARK / FRI verifiers (Winterfell, Plonky3, Risc0).
//!
//! Implementations dispatch through [`crate::syscall::SyscallBackend`] so
//! that host tests use a software hash and on-chain code uses the syscall.

use crate::error::OnChainError;
use alloc::vec::Vec;

extern crate alloc;

/// Variants supported by Mosaic's transcript layer.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TranscriptKind {
    /// Poseidon over the BN254 scalar field, x⁵ S-box, Circom-compatible.
    PoseidonBn254 = 0x01,
    /// Keccak-256.
    Keccak256 = 0x02,
    /// SHA-256.
    Sha256 = 0x03,
}

/// A Fiat-Shamir transcript. Stateful: callers `absorb` data and then
/// `squeeze_challenge` for each verifier round.
pub trait TranscriptHash {
    /// The hash this transcript is built on.
    fn kind(&self) -> TranscriptKind;

    /// Absorb arbitrary bytes into the transcript state.
    fn absorb(&mut self, label: &'static [u8], data: &[u8]) -> Result<(), OnChainError>;

    /// Squeeze a challenge of `len` bytes from the current transcript state.
    fn squeeze_challenge(
        &mut self,
        label: &'static [u8],
        len: usize,
    ) -> Result<Vec<u8>, OnChainError>;
}
