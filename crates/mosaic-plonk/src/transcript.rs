//! Fiat-Shamir transcript scaffolding for PLONK challenge derivation.
//!
//! PLONK's canonical proof composition uses Keccak-256 by default
//! (gnark / arkworks) or Poseidon-BN254x5 when the outer circuit is
//! Circom-compatible. Both hashes are available via
//! [`mosaic_core::SyscallBackend`] — the verifier picks via this
//! transcript's [`Kind`] discriminant.
//!
//! ## Contract
//!
//! ```text
//! transcript = Transcript::new(kind, backend)
//! transcript.absorb(b"label-1", &bytes_1)
//! transcript.absorb(b"label-2", &bytes_2)
//! let challenge_fr = transcript.squeeze_challenge_fr()
//! ```
//!
//! ## Phase-1 status
//!
//! Scaffold only. The actual absorb / squeeze implementations are
//! tracked by [issue #1](https://github.com/wienerlabs/mosaic/issues/1);
//! this module defines the trait surface and error mapping so the
//! verifier skeleton compiles.

use mosaic_core::OnChainError;

/// Transcript hash choice.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Keccak-256 (gnark / arkworks default).
    Keccak256 = 0x02,
    /// Poseidon over BN254 scalar field, x⁵ S-box (Circom default).
    PoseidonBn254X5 = 0x01,
}

/// Fiat-Shamir transcript for PLONK rounds.
///
/// Phase 1 ships the shape; the verify path does not consume this
/// because `verify()` returns unimplemented.
pub struct Transcript<'b> {
    #[allow(dead_code)] // used when verifier lands; kept to fix the trait shape.
    kind: Kind,
    #[allow(dead_code)]
    backend: &'b dyn BackendHandle,
    #[allow(dead_code)]
    accumulated: alloc::vec::Vec<u8>,
}

/// Erased handle over [`mosaic_core::SyscallBackend`] so the transcript
/// doesn't take a generic parameter (simplifies `ProofSystem` dispatch).
///
/// Concrete implementations wrap a `SyscallBackend` and route
/// `sha256` / `keccak256` / `poseidon` calls through it.
pub trait BackendHandle {
    /// Hash a sequence of byte slices under the transcript's chosen
    /// scheme; output is a 32-byte field element representation.
    fn hash(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError>;
}

impl<'b> Transcript<'b> {
    /// Construct a fresh transcript.
    #[must_use]
    pub fn new(kind: Kind, backend: &'b dyn BackendHandle) -> Self {
        Self { kind, backend, accumulated: alloc::vec::Vec::new() }
    }

    /// Absorb labeled input bytes into the running transcript state.
    ///
    /// TODO(mosaic-001): actual absorb logic.
    pub fn absorb(
        &mut self,
        _label: &'static [u8],
        _data: &[u8],
    ) -> Result<(), OnChainError> {
        Err(OnChainError::UnimplementedProofSystem)
    }

    /// Squeeze a 32-byte field-element challenge from the transcript.
    ///
    /// TODO(mosaic-001): actual squeeze logic. Must reduce output mod the
    /// BN254 scalar field order `r` to produce a uniform challenge.
    pub fn squeeze_challenge_fr(&mut self) -> Result<[u8; 32], OnChainError> {
        Err(OnChainError::UnimplementedProofSystem)
    }
}
