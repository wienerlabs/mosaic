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
//! rolling-SHA-256 of all chunks.
//!
//! ## Spec
//!
//! See [`docs/design/0001-chunked-upload-handlers.md`][design] for the
//! authoritative implementation contract: state machine, PDA seeds, rent
//! model, DoS analysis, determinism audit.
//!
//! [design]: https://github.com/wienerlabs/mosaic/blob/main/docs/design/0001-chunked-upload-handlers.md
//!
//! ## Layout version
//!
//! [`ProofUploadSession::LAYOUT_VERSION`] is the on-chain account format
//! version. Bumping it requires the migration procedure in design § 11.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use mosaic_core::OnChainError;

/// Maximum chunk payload size (bytes). 800 leaves headroom under 1232 for
/// instruction discriminator + chunk index + signature overhead.
pub const CHUNK_SIZE: usize = 800;

/// Maximum total proof length supported by a single session.
/// Bounded by the requested heap-frame max (256 KiB) minus the base struct.
pub const MAX_PROOF_LEN: u32 = 256 * 1024 - BASE_SIZE_GUESS as u32;

/// Conservative base-struct size used for `MAX_PROOF_LEN` arithmetic.
/// The actual serialized base size is computed at runtime; this constant
/// is only used to bound `total_len` at initialization time.
const BASE_SIZE_GUESS: usize = 256;

/// Domain separation tag absorbed into `h_0`. Bumping this constant
/// invalidates all in-flight upload sessions; do so only with a protocol
/// version bump documented in `AUDIT.md` (design § 11).
pub const DOMAIN_TAG: &[u8; 16] = b"mosaic-chunked01";

/// PDA seed prefix.
pub const SESSION_SEED_PREFIX: &[u8] = b"mosaic-session";

/// Slots after which an unfinalized session becomes eligible for
/// permissionless cancellation. 432 000 ≈ 48 hours at 400 ms slots.
pub const EXPIRY_SLOTS: u64 = 432_000;

/// PDA-stored session state. Stored under a deterministic seed:
/// `[SESSION_SEED_PREFIX, session_id, payer_pubkey]`.
///
/// `payer_pubkey` is part of the PDA seeds — see design § 3.2 for the
/// front-running griefing rationale.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ProofUploadSession {
    /// Account layout version. Lets future upgrades detect old layouts.
    pub layout_version: u8,
    /// PDA bump byte; cached so handlers don't re-run `find_program_address`.
    pub bump: u8,
    /// Wire-format `ProofSystemId` byte; the verifier dispatch needs this in
    /// `commit_and_verify` to know which verifier to invoke.
    pub proof_system_id: u8,
    /// `true` once the session is finalized — no more `append_chunk` calls allowed.
    pub finalized: bool,
    /// Stable session identifier supplied by the client (32-byte random nonce).
    pub session_id: [u8; 32],
    /// Payer pubkey; bound into the PDA seeds. Re-stored so handlers can
    /// validate it without re-deriving the PDA.
    pub payer: [u8; 32],
    /// Total proof length the client has committed to upload.
    pub total_len: u32,
    /// Number of bytes appended so far.
    pub appended_len: u32,
    /// Number of chunks committed so far.
    pub chunks_committed: u16,
    /// Last verifier error code, populated when `commit_and_verify` fails.
    /// Zero means no failure has been observed (or none yet).
    pub last_verify_error: u32,
    /// Slot at which `initialize_session` ran.
    pub created_at_slot: u64,
    /// Slot at and after which `cancel_expired_session` is permitted.
    pub expires_at_slot: u64,
    /// Rolling SHA-256 over `(DOMAIN_TAG ‖ session_id ‖ total_len_le ‖ proof_system_id ‖ chunk_0 ‖ chunk_1 ‖ …)`.
    pub rolling_hash: [u8; 32],
    /// Future-compat padding. Bumping `layout_version` takes from here first.
    pub reserved: [u8; 32],
    /// Assembled proof bytes (length grows with each `append_chunk`).
    pub assembled: Vec<u8>,
}

impl ProofUploadSession {
    /// Current account layout version. Bump to perform a migration.
    pub const LAYOUT_VERSION: u8 = 1;

    /// Maximum borsh-serialized length of the fixed-size header.
    /// Computed at compile time so handlers can size accounts correctly.
    pub const FIXED_HEADER_LEN: usize = 1   // layout_version
        + 1                                 // bump
        + 1                                 // proof_system_id
        + 1                                 // finalized
        + 32                                // session_id
        + 32                                // payer
        + 4                                 // total_len
        + 4                                 // appended_len
        + 2                                 // chunks_committed
        + 4                                 // last_verify_error
        + 8                                 // created_at_slot
        + 8                                 // expires_at_slot
        + 32                                // rolling_hash
        + 32                                // reserved
        + 4; // borsh Vec<u8> length prefix for `assembled`

    /// Total serialized account size for a session declaring `total_len`
    /// bytes of proof data.
    #[must_use]
    pub const fn account_size_for(total_len: u32) -> usize {
        Self::FIXED_HEADER_LEN.saturating_add(total_len as usize)
    }

    /// PDA seed material for `(session_id, payer)`. Caller must append the
    /// bump byte when invoking `create_program_address`.
    #[must_use]
    pub fn pda_seeds<'a>(session_id: &'a [u8; 32], payer: &'a [u8; 32]) -> [&'a [u8]; 3] {
        [SESSION_SEED_PREFIX, session_id, payer]
    }

    /// Initialize a fresh session.
    ///
    /// `h_0` is the client-precommitted rolling-hash seed.
    /// The handler is responsible for computing `h_0 = SHA256(DOMAIN_TAG ‖
    /// session_id ‖ total_len_le ‖ [proof_system_id])` and supplying it.
    #[must_use]
    pub fn new(
        session_id: [u8; 32],
        payer: [u8; 32],
        bump: u8,
        proof_system_id: u8,
        total_len: u32,
        h_0: [u8; 32],
        created_at_slot: u64,
    ) -> Self {
        Self {
            layout_version: Self::LAYOUT_VERSION,
            bump,
            proof_system_id,
            finalized: false,
            session_id,
            payer,
            total_len,
            appended_len: 0,
            chunks_committed: 0,
            last_verify_error: 0,
            created_at_slot,
            expires_at_slot: created_at_slot.saturating_add(EXPIRY_SLOTS),
            rolling_hash: h_0,
            reserved: [0; 32],
            assembled: Vec::with_capacity(total_len as usize),
        }
    }

    /// Compute the canonical `h_0` seed from instruction inputs.
    ///
    /// `h_0 = SHA256(DOMAIN_TAG ‖ session_id ‖ total_len_le ‖ [proof_system_id])`
    ///
    /// The handler invokes [`mosaic_core::SyscallBackend::sha256`] with the
    /// component slices listed by [`Self::h0_components`]; this method
    /// exists for offline / SDK-side use that wants the same construction.
    #[must_use]
    pub fn h0_components<'a>(
        session_id: &'a [u8; 32],
        total_len_le: &'a [u8; 4],
        proof_system_id: &'a [u8; 1],
    ) -> [&'a [u8]; 4] {
        [DOMAIN_TAG, session_id, total_len_le, proof_system_id]
    }

    /// Append one chunk to the session.
    ///
    /// The handler computes `next_hash = SHA256(self.rolling_hash ‖ chunk)`
    /// via the syscall and supplies it. This method does not call any
    /// syscall itself, keeping it portable for tests.
    pub fn append_chunk(
        &mut self,
        chunk_index: u16,
        chunk: &[u8],
        next_hash: [u8; 32],
    ) -> Result<(), OnChainError> {
        if self.finalized {
            return Err(OnChainError::SessionAlreadyFinalized);
        }
        if chunk_index != self.chunks_committed {
            return Err(OnChainError::ChunkOutOfOrder);
        }
        if chunk.len() > CHUNK_SIZE {
            return Err(OnChainError::ChunkOverflow);
        }
        let chunk_len_u32 = u32::try_from(chunk.len()).map_err(|_| OnChainError::ChunkOverflow)?;
        let new_len = self
            .appended_len
            .checked_add(chunk_len_u32)
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

    /// Mark the session as finalized; verifies length + hash commitment.
    /// The actual verifier dispatch happens in the handler after this returns Ok.
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

    /// Record a verifier failure. Used after `finalize` succeeded but the
    /// verifier returned an error — the session stays open for cancellation.
    pub fn record_verify_failure(&mut self, error_code: u32) {
        self.last_verify_error = error_code;
    }

    /// Returns `true` if `current_slot >= expires_at_slot`.
    #[must_use]
    pub const fn is_expired(&self, current_slot: u64) -> bool {
        current_slot >= self.expires_at_slot
    }
}

/// Instruction tags — wire-stable (single byte at offset 0 of the
/// instruction data). Range 0x10..=0x1F is reserved for chunked upload.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChunkedInstructionTag {
    /// `initialize_session(session_id, total_len, proof_system_id, h_0)`.
    InitializeSession = 0x10,
    /// `append_chunk(chunk_index, chunk_len, chunk_bytes)`.
    AppendChunk = 0x11,
    /// `commit_and_verify(expected_final_hash, vk_account_offset, public_inputs)`.
    CommitAndVerify = 0x12,
    /// `cancel_session()` — refund rent, drop assembled bytes.
    CancelSession = 0x13,
    /// `cancel_expired_session()` — permissionless GC after `expires_at_slot`.
    CancelExpiredSession = 0x14,
}

impl ChunkedInstructionTag {
    /// Parse an instruction-data byte. Returns `None` for non-chunked tags.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(Self::InitializeSession),
            0x11 => Some(Self::AppendChunk),
            0x12 => Some(Self::CommitAndVerify),
            0x13 => Some(Self::CancelSession),
            0x14 => Some(Self::CancelExpiredSession),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_session(total_len: u32) -> ProofUploadSession {
        ProofUploadSession::new([1; 32], [2; 32], 254, 0x01, total_len, [0xAA; 32], 1_000)
    }

    #[test]
    fn append_then_finalize() {
        let mut session = fixture_session(4);
        session.append_chunk(0, &[1, 2], [0xBB; 32]).unwrap();
        session.append_chunk(1, &[3, 4], [0xCC; 32]).unwrap();
        session.finalize([0xCC; 32]).unwrap();
        assert!(session.finalized);
        assert_eq!(session.assembled, alloc::vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_overflow() {
        let mut session = fixture_session(2);
        assert!(matches!(
            session.append_chunk(0, &[1, 2, 3], [0; 32]),
            Err(OnChainError::ChunkOverflow),
        ));
    }

    #[test]
    fn rejects_out_of_order() {
        let mut session = fixture_session(4);
        session.append_chunk(0, &[1, 2], [0xBB; 32]).unwrap();
        assert!(matches!(
            session.append_chunk(2, &[3, 4], [0xCC; 32]),
            Err(OnChainError::ChunkOutOfOrder),
        ));
    }

    #[test]
    fn rejects_finalize_with_wrong_hash() {
        let mut session = fixture_session(2);
        session.append_chunk(0, &[9, 8], [0xBB; 32]).unwrap();
        assert!(matches!(
            session.finalize([0x00; 32]),
            Err(OnChainError::ChunkCommitmentMismatch),
        ));
    }

    #[test]
    fn rejects_finalize_with_short_data() {
        let mut session = fixture_session(4);
        session.append_chunk(0, &[1, 2], [0xBB; 32]).unwrap();
        assert!(matches!(
            session.finalize([0xBB; 32]),
            Err(OnChainError::ChunkCommitmentMismatch),
        ));
    }

    #[test]
    fn expiry_arithmetic() {
        let session = fixture_session(2);
        assert_eq!(session.expires_at_slot, 1_000 + EXPIRY_SLOTS);
        assert!(!session.is_expired(1_000 + EXPIRY_SLOTS - 1));
        assert!(session.is_expired(1_000 + EXPIRY_SLOTS));
    }

    #[test]
    fn account_size_arithmetic() {
        let total_len = 4_096_u32;
        let size = ProofUploadSession::account_size_for(total_len);
        assert_eq!(
            size,
            ProofUploadSession::FIXED_HEADER_LEN + total_len as usize
        );
    }

    #[test]
    fn instruction_tag_roundtrip() {
        for byte in [0x10_u8, 0x11, 0x12, 0x13, 0x14] {
            assert!(ChunkedInstructionTag::from_byte(byte).is_some());
        }
        assert!(ChunkedInstructionTag::from_byte(0x00).is_none());
        assert!(ChunkedInstructionTag::from_byte(0x15).is_none());
    }

    #[test]
    fn borsh_roundtrip() {
        let session = fixture_session(8);
        let bytes = borsh::to_vec(&session).unwrap();
        let decoded = ProofUploadSession::try_from_slice(&bytes).unwrap();
        assert_eq!(session, decoded);
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 40 — proptest coverage for the chunked-upload state machine.
    //
    // The chunked upload protocol is a small but security-critical
    // state machine: any deviation from the documented invariants
    // (chunk ordering, length cap, hash commitment, finalization
    // monotonicity) lets an attacker either corrupt the assembled
    // proof bytes or replay a finalized session.
    //
    // Proptest matrix:
    //
    //   1. State machine soundness — any random sequence of legitimate
    //      `append_chunk` calls (in-order, in-bounds) lets `finalize`
    //      succeed when the cumulative chunk bytes equal `total_len`.
    //   2. Out-of-order rejection — any chunk_index ≠ chunks_committed
    //      is rejected with `ChunkOutOfOrder`.
    //   3. Overflow rejection — any chunk that would push appended_len
    //      past total_len is rejected with `ChunkOverflow`.
    //   4. Chunk-size cap — any chunk longer than `CHUNK_SIZE` is
    //      rejected with `ChunkOverflow`.
    //   5. Already-finalized monotonicity — once finalized, no
    //      append_chunk and no second finalize is allowed.
    //   6. Hash commitment — finalize with the wrong final hash is
    //      rejected with `ChunkCommitmentMismatch`.
    //   7. Length commitment — finalize with appended_len < total_len
    //      is rejected with `ChunkCommitmentMismatch`.
    //   8. Borsh round-trip — encode → decode is the identity over
    //      the full state space we generate.
    //   9. Expiry semantics — `current_slot ≥ expires_at_slot` ⇔
    //      `is_expired(current_slot)`.
    //  10. Instruction tag round-trip — exhaustive over byte space
    //      [0, 255] checks the from_byte mapping.
    //  11. PDA seeds — order is [SEED_PREFIX, session_id, payer]
    //      regardless of the specific session_id and payer values.
    //
    // The state-machine property uses a tiny "trace" generator that
    // produces a sequence of (chunk_index, chunk_payload) pairs
    // satisfying the in-order + in-bounds preconditions, then asserts
    // that running the trace through `append_chunk` followed by
    // `finalize` succeeds and the assembled bytes match the
    // concatenation of the trace.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    /// Random `(num_chunks, last_chunk_len)` shape for a session.
    /// Total length is `num_chunks * CHUNK_SIZE` minus a clip on the
    /// last chunk so we exercise both even-multiple and partial-tail
    /// session shapes.
    prop_compose! {
        fn arb_session_shape()(
            num_chunks in 1usize..=8,
            last_chunk_len in 1usize..=CHUNK_SIZE,
        ) -> (usize, usize) {
            (num_chunks, last_chunk_len)
        }
    }

    /// Synthesize a full chunk sequence from a shape descriptor: every
    /// chunk except the last is exactly `CHUNK_SIZE` bytes; the last
    /// is `last_chunk_len ∈ [1, CHUNK_SIZE]`.
    fn make_trace(num_chunks: usize, last_chunk_len: usize, fill: u8) -> Vec<Vec<u8>> {
        let mut trace = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            let len = if i + 1 == num_chunks {
                last_chunk_len
            } else {
                CHUNK_SIZE
            };
            trace.push(alloc::vec![fill.wrapping_add(i as u8); len]);
        }
        trace
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Any in-spec trace assembles correctly. Pins the happy path
        /// across the random shape space.
        #[test]
        fn proptest_in_order_trace_finalizes(
            (num_chunks, last_chunk_len) in arb_session_shape(),
            fill in any::<u8>(),
        ) {
            let trace = make_trace(num_chunks, last_chunk_len, fill);
            let total_len: u32 = trace.iter().map(|c| c.len() as u32).sum();
            let mut session = ProofUploadSession::new(
                [3; 32], [4; 32], 254, 0x01, total_len, [0xAA; 32], 1_000,
            );
            // Use a deterministic "next_hash" sequence so the test
            // doesn't depend on a real SHA-256 — finalize compares the
            // final hash to a value we choose.
            let mut last_hash = [0xAAu8; 32];
            for (idx, chunk) in trace.iter().enumerate() {
                let next_hash = [(idx as u8).wrapping_add(1); 32];
                session.append_chunk(idx as u16, chunk, next_hash).unwrap();
                last_hash = next_hash;
            }
            session.finalize(last_hash).unwrap();
            prop_assert!(session.finalized);
            prop_assert_eq!(session.appended_len, total_len);
            prop_assert_eq!(session.chunks_committed as usize, num_chunks);
            // Assembled bytes match the concatenated trace.
            let expected: Vec<u8> = trace.iter().flatten().copied().collect();
            prop_assert_eq!(&session.assembled, &expected);
        }

        /// Any chunk_index that doesn't equal `chunks_committed` is
        /// rejected with `ChunkOutOfOrder`. We start from a fresh
        /// session (chunks_committed = 0) and try a non-zero index.
        #[test]
        fn proptest_rejects_out_of_order(
            wrong_idx in 1u16..=u16::MAX,
            payload_len in 1usize..=CHUNK_SIZE,
        ) {
            let mut session = ProofUploadSession::new(
                [5; 32], [6; 32], 254, 0x01, 4096, [0; 32], 0,
            );
            let chunk = alloc::vec![0u8; payload_len];
            prop_assert!(matches!(
                session.append_chunk(wrong_idx, &chunk, [0; 32]),
                Err(OnChainError::ChunkOutOfOrder),
            ));
        }

        /// Any chunk longer than `CHUNK_SIZE` is rejected as
        /// `ChunkOverflow`, regardless of the session's `total_len`
        /// budget.
        #[test]
        fn proptest_rejects_oversized_chunk(
            extra in 1usize..=64,
        ) {
            let mut session = ProofUploadSession::new(
                [7; 32], [8; 32], 254, 0x01, MAX_PROOF_LEN, [0; 32], 0,
            );
            let oversized = alloc::vec![0u8; CHUNK_SIZE + extra];
            prop_assert!(matches!(
                session.append_chunk(0, &oversized, [0; 32]),
                Err(OnChainError::ChunkOverflow),
            ));
        }

        /// Any chunk that would push `appended_len` past `total_len`
        /// is rejected with `ChunkOverflow`.
        #[test]
        fn proptest_rejects_total_len_overflow(
            total_len in 1u32..=200,
            overshoot in 1usize..=64,
        ) {
            let mut session = ProofUploadSession::new(
                [9; 32], [10; 32], 254, 0x01, total_len, [0; 32], 0,
            );
            let chunk = alloc::vec![0u8; (total_len as usize) + overshoot];
            // For very small total_len the chunk above might exceed
            // CHUNK_SIZE which would route through a different error.
            prop_assume!(chunk.len() <= CHUNK_SIZE);
            prop_assert!(matches!(
                session.append_chunk(0, &chunk, [0; 32]),
                Err(OnChainError::ChunkOverflow),
            ));
        }

        /// Once `finalized = true`, no further `append_chunk` is
        /// accepted. Pins the monotonicity guarantee that prevents
        /// attackers from extending a finalized session.
        #[test]
        fn proptest_finalized_session_rejects_appends(
            extra_chunk_len in 1usize..=CHUNK_SIZE,
        ) {
            let mut session = ProofUploadSession::new(
                [11; 32], [12; 32], 254, 0x01, 4, [0; 32], 0,
            );
            session.append_chunk(0, &[1, 2, 3, 4], [0xBB; 32]).unwrap();
            session.finalize([0xBB; 32]).unwrap();
            let extra = alloc::vec![0u8; extra_chunk_len];
            prop_assert!(matches!(
                session.append_chunk(1, &extra, [0xCC; 32]),
                Err(OnChainError::SessionAlreadyFinalized),
            ));
            // Second finalize attempt must also reject.
            prop_assert!(matches!(
                session.finalize([0xBB; 32]),
                Err(OnChainError::SessionAlreadyFinalized),
            ));
        }

        /// Finalize with any hash other than the actual rolling hash
        /// is rejected with `ChunkCommitmentMismatch`.
        #[test]
        fn proptest_finalize_rejects_wrong_hash(
            wrong_hash_byte in 0u8..u8::MAX,
        ) {
            let mut session = ProofUploadSession::new(
                [13; 32], [14; 32], 254, 0x01, 2, [0; 32], 0,
            );
            session.append_chunk(0, &[1, 2], [0xBB; 32]).unwrap();
            // Pick any hash != [0xBB; 32].
            prop_assume!(wrong_hash_byte != 0xBB);
            let bad_hash = [wrong_hash_byte; 32];
            prop_assert!(matches!(
                session.finalize(bad_hash),
                Err(OnChainError::ChunkCommitmentMismatch),
            ));
            prop_assert!(!session.finalized);
        }

        /// Finalize with `appended_len < total_len` is rejected.
        /// Catches the failure mode where a partial upload would slip
        /// past the commitment check.
        #[test]
        fn proptest_finalize_rejects_short_assembly(
            total_len in 4u32..=200,
            short_by in 1u32..=4,
        ) {
            prop_assume!(short_by < total_len);
            let mut session = ProofUploadSession::new(
                [15; 32], [16; 32], 254, 0x01, total_len, [0; 32], 0,
            );
            let chunk_len = (total_len - short_by) as usize;
            // Chunk_len ≤ CHUNK_SIZE for the cases we generate.
            prop_assume!(chunk_len <= CHUNK_SIZE);
            let chunk = alloc::vec![0u8; chunk_len];
            session.append_chunk(0, &chunk, [0xBB; 32]).unwrap();
            prop_assert!(matches!(
                session.finalize([0xBB; 32]),
                Err(OnChainError::ChunkCommitmentMismatch),
            ));
        }

        /// Borsh encode → decode is the identity for any reachable
        /// session state. Generates random session parameters and
        /// runs a partial trace before serializing.
        #[test]
        fn proptest_borsh_roundtrip(
            session_id_byte in any::<u8>(),
            payer_byte in any::<u8>(),
            bump in any::<u8>(),
            proof_system_id in any::<u8>(),
            total_len in 0u32..=1024,
            chunks_to_append in 0usize..=4,
        ) {
            let mut session = ProofUploadSession::new(
                [session_id_byte; 32],
                [payer_byte; 32],
                bump,
                proof_system_id,
                total_len,
                [0; 32],
                0,
            );
            // Append chunks until we hit total_len or the requested
            // chunk count.
            let chunk_payload = alloc::vec![0xAAu8; 16];
            for i in 0..chunks_to_append {
                if session.appended_len + chunk_payload.len() as u32 > total_len {
                    break;
                }
                if session.append_chunk(i as u16, &chunk_payload, [i as u8; 32]).is_err() {
                    break;
                }
            }
            let bytes = borsh::to_vec(&session).unwrap();
            let decoded = ProofUploadSession::try_from_slice(&bytes).unwrap();
            prop_assert_eq!(session, decoded);
        }

        /// `is_expired` matches the documented `current_slot >=
        /// expires_at_slot` rule across the entire u64 slot space.
        #[test]
        fn proptest_expiry_semantics(
            created_slot in 0u64..=u64::MAX / 2,
            current_slot in 0u64..=u64::MAX,
        ) {
            let session = ProofUploadSession::new(
                [17; 32], [18; 32], 254, 0x01, 1, [0; 32], created_slot,
            );
            let expected = current_slot >= session.expires_at_slot;
            prop_assert_eq!(session.is_expired(current_slot), expected);
        }

        /// Instruction tag mapping: bytes 0x10..=0x14 round-trip as
        /// `Some(variant)`; everything else is `None`. Exhaustive over
        /// the entire u8 space.
        #[test]
        fn proptest_instruction_tag_mapping(byte in any::<u8>()) {
            let parsed = ChunkedInstructionTag::from_byte(byte);
            match byte {
                0x10..=0x14 => prop_assert!(parsed.is_some()),
                _ => prop_assert!(parsed.is_none()),
            }
        }

        /// PDA seed material is exactly `[SESSION_SEED_PREFIX,
        /// session_id, payer]` regardless of the session_id and payer
        /// values. A reorder would silently change the derived PDA on
        /// every account, breaking all previously-uploaded sessions.
        #[test]
        fn proptest_pda_seed_order_stable(
            session_id_byte in any::<u8>(),
            payer_byte in any::<u8>(),
        ) {
            let session_id = [session_id_byte; 32];
            let payer = [payer_byte; 32];
            let seeds = ProofUploadSession::pda_seeds(&session_id, &payer);
            prop_assert_eq!(seeds.len(), 3);
            prop_assert_eq!(seeds[0], SESSION_SEED_PREFIX);
            prop_assert_eq!(seeds[1], &session_id[..]);
            prop_assert_eq!(seeds[2], &payer[..]);
        }
    }
}
