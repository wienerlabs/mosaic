//! # mosaic-chunked
//!
//! Chunked proof upload protocol with rolling-hash commitment.
//!
//! ## Why
//!
//! Solana caps a single transaction's instruction data at **1232 bytes**.
//! That fits a Groth16 proof + small VK, but is far too small for:
//!
//! - PLONK proofs (~1.5–4 KB).
//! - STARK proofs (50–200 KB).
//! - IVC / folding-scheme transcripts (variable, often >10 KB).
//!
//! The chunked-upload protocol lets the client split a large proof into
//! 800-byte chunks (leaving headroom for instruction overhead), append them
//! across multiple transactions to a session PDA, then call
//! `commit_and_verify` in the final transaction with a precommitted
//! rolling-SHA-256 of all chunks. The PDA stores the running hash and the
//! assembled proof bytes.
//!
//! ## Determinism
//!
//! The rolling hash is `h_{i+1} = SHA-256(h_i || chunk_i_bytes)` with
//! `h_0 = SHA-256(domain_tag || total_len_le)`. This binds the chunk order
//! and the declared total length, preventing adversarial reordering.
//!
//! ## Phase-1 status
//!
//! Phase 1 ships the **data model + handler signatures + PDA layout** only.
//! The actual instruction-handler logic and the on-chain rent calculation
//! are tracked by TODO(mosaic-006).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use mosaic_core::OnChainError;

/// Maximum chunk payload size (bytes). 800 leaves headroom under 1232 for
/// instruction discriminator + chunk index + signature overhead.
pub const CHUNK_SIZE: usize = 800;

/// Domain separation tag absorbed into `h_0`. Bumping this constant
/// invalidates all in-flight upload sessions; do so only with a protocol
/// version bump documented in `AUDIT.md`.
pub const DOMAIN_TAG: &[u8; 16] = b"mosaic-chunked01";

/// PDA-stored session state. Stored under a deterministic seed:
/// `[b"mosaic-session", session_id.as_bytes()]`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ProofUploadSession {
    /// Stable session identifier supplied by the client (32-byte random nonce).
    pub session_id: [u8; 32],
    /// Total proof length the client has committed to upload.
    pub total_len: u32,
    /// Number of bytes appended so far.
    pub appended_len: u32,
    /// Number of chunks committed so far.
    pub chunks_committed: u16,
    /// Rolling SHA-256 over `(session_id || total_len_le || chunk_0 || chunk_1 || …)`.
    pub rolling_hash: [u8; 32],
    /// `true` once the session is finalized — no more `append_chunk` calls allowed.
    pub finalized: bool,
    /// Wire-format `ProofSystemId` byte; the verifier dispatch needs this in
    /// `commit_and_verify` to know which verifier to invoke.
    pub proof_system_id: u8,
    /// Assembled proof bytes (length grows with each `append_chunk`).
    pub assembled: Vec<u8>,
}

impl ProofUploadSession {
    /// Initialize a new session with the client-precommitted rolling-hash
    /// seed `h_0 = SHA-256(DOMAIN_TAG || session_id || total_len_le)`.
    pub fn initialize(
        session_id: [u8; 32],
        total_len: u32,
        proof_system_id: u8,
        h_0: [u8; 32],
    ) -> Self {
        Self {
            session_id,
            total_len,
            appended_len: 0,
            chunks_committed: 0,
            rolling_hash: h_0,
            finalized: false,
            proof_system_id,
            assembled: Vec::with_capacity(total_len as usize),
        }
    }

    /// Append one chunk to the session. The handler must invoke a SHA-256
    /// syscall to update `rolling_hash`.
    ///
    /// This method does **not** call the syscall itself — the on-chain
    /// program calls `mosaic_core::syscall::SyscallBackend::sha256` and
    /// passes the new digest in `next_hash`. This keeps the handler
    /// portable to non-Solana hosts during testing.
    pub fn append_chunk(
        &mut self,
        chunk: &[u8],
        next_hash: [u8; 32],
    ) -> Result<(), OnChainError> {
        if self.finalized {
            return Err(OnChainError::SessionAlreadyFinalized);
        }
        if chunk.len() > CHUNK_SIZE {
            return Err(OnChainError::ChunkOverflow);
        }
        let new_len = self
            .appended_len
            .checked_add(u32::try_from(chunk.len()).map_err(|_| OnChainError::ChunkOverflow)?)
            .ok_or(OnChainError::ChunkOverflow)?;
        if new_len > self.total_len {
            return Err(OnChainError::ChunkOverflow);
        }
        self.assembled.extend_from_slice(chunk);
        self.appended_len = new_len;
        self.chunks_committed = self
            .chunks_committed
            .checked_add(1)
            .ok_or(OnChainError::ChunkOverflow)?;
        self.rolling_hash = next_hash;
        Ok(())
    }

    /// Mark the session as finalized. Verifies that the assembled length
    /// matches the precommitted total. The actual rolling-hash equality
    /// check happens in the on-chain handler against the client-supplied
    /// final commitment.
    pub fn finalize(&mut self, expected_final_hash: [u8; 32]) -> Result<(), OnChainError> {
        if self.finalized {
            return Err(OnChainError::SessionAlreadyFinalized);
        }
        if self.appended_len != self.total_len {
            return Err(OnChainError::ChunkCommitmentMismatch);
        }
        if self.rolling_hash != expected_final_hash {
            return Err(OnChainError::ChunkCommitmentMismatch);
        }
        self.finalized = true;
        Ok(())
    }

    /// PDA seed material.
    #[must_use]
    pub fn pda_seeds(session_id: &[u8; 32]) -> [&[u8]; 2] {
        // `session_id` is captured by reference; the actual PDA derivation
        // (with bump) happens in `mosaic-program`.
        [b"mosaic-session", session_id]
    }
}

/// Instruction tags — wire-stable (single byte at offset 0 of the
/// instruction data).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChunkedInstructionTag {
    /// `initialize_session(session_id, total_len, proof_system_id, h_0)`.
    InitializeSession = 0x10,
    /// `append_chunk(chunk_index, chunk_bytes)`.
    AppendChunk = 0x11,
    /// `commit_and_verify(vk_account, public_inputs)`.
    CommitAndVerify = 0x12,
    /// `cancel_session()` — refund rent, drop assembled bytes.
    CancelSession = 0x13,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_then_finalize() {
        let mut session = ProofUploadSession::initialize([1; 32], 4, 0x01, [0; 32]);
        session.append_chunk(&[1, 2], [0xAA; 32]).unwrap();
        session.append_chunk(&[3, 4], [0xBB; 32]).unwrap();
        session.finalize([0xBB; 32]).unwrap();
        assert!(session.finalized);
        assert_eq!(session.assembled, alloc::vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_overflow() {
        let mut session = ProofUploadSession::initialize([0; 32], 2, 0x01, [0; 32]);
        assert!(matches!(
            session.append_chunk(&[1, 2, 3], [0; 32]),
            Err(OnChainError::ChunkOverflow),
        ));
    }
}
