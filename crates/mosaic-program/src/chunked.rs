//! Chunked-upload instruction handlers.
//!
//! Implementation of the contract specified in
//! [`docs/design/0001-chunked-upload-handlers.md`][design]. Five handlers:
//!
//! - [`initialize_session`] (tag `0x10`)
//! - [`append_chunk`]       (tag `0x11`)
//! - [`commit_and_verify`]  (tag `0x12`)
//! - [`cancel_session`]     (tag `0x13`)
//! - [`cancel_expired_session`] (tag `0x14`)
//!
//! [design]: https://github.com/wienerlabs/mosaic/blob/main/docs/design/0001-chunked-upload-handlers.md

#![allow(deprecated)] // solana-program 2.x deprecates re-exports; see issue #52.

use alloc::format;
use borsh::BorshDeserialize;
use mosaic_chunked::{
    ChunkedInstructionTag, ProofUploadSession, CHUNK_SIZE, MAX_PROOF_LEN, SESSION_SEED_PREFIX,
};
use mosaic_core::{proof_system::ProofSystemId, OnChainError};
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult, msg,
    program::invoke_signed, program_error::ProgramError, pubkey::Pubkey, rent::Rent,
    system_instruction, system_program, sysvar::Sysvar,
};

use crate::dispatch_verify;
use mosaic_core::syscall::solana::SolanaSyscallBackend;
use mosaic_stark::FriStark;

/// Sub-dispatcher: read the chunked tag and route to a handler.
pub fn dispatch(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    instruction_data: &[u8],
) -> ProgramResult {
    let (tag, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let tag = ChunkedInstructionTag::from_byte(*tag).ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        ChunkedInstructionTag::InitializeSession => initialize_session(program_id, accounts, rest),
        ChunkedInstructionTag::AppendChunk => append_chunk(program_id, accounts, rest),
        ChunkedInstructionTag::CommitAndVerify => commit_and_verify(program_id, accounts, rest),
        ChunkedInstructionTag::CancelSession => cancel_session(program_id, accounts, rest),
        ChunkedInstructionTag::CancelExpiredSession => {
            cancel_expired_session(program_id, accounts, rest)
        },
        ChunkedInstructionTag::BeginStarkVerify => {
            begin_stark_verify(program_id, accounts, rest)
        },
        ChunkedInstructionTag::StarkVerifyStep => stark_verify_step(program_id, accounts, rest),
    }
}

// ---------- shared helpers ----------

/// Manual parser for a fixed-size byte slice; produces a clearer error than
/// borsh's `Io` for our specific failure mode.
fn read_array<const N: usize>(buf: &[u8], offset: usize) -> Result<[u8; N], ProgramError> {
    let end = offset
        .checked_add(N)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let slice = buf
        .get(offset..end)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, ProgramError> {
    Ok(u32::from_le_bytes(read_array::<4>(buf, offset)?))
}

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, ProgramError> {
    Ok(u16::from_le_bytes(read_array::<2>(buf, offset)?))
}

/// Validate that `session_pda` is owned by this program, derived from the
/// seeds we expect, and matches the payer recorded in the account.
fn load_session(
    program_id: &Pubkey,
    session_pda: &AccountInfo<'_>,
    payer_key: &Pubkey,
) -> Result<ProofUploadSession, ProgramError> {
    if session_pda.owner != program_id {
        msg!("mosaic: session PDA owner mismatch");
        return Err(ProgramError::IllegalOwner);
    }
    let data = session_pda.try_borrow_data()?;
    // `try_from_slice` is strict about trailing bytes; the account buffer is
    // pre-allocated to `account_size_for(total_len)`, so trailing zeros are
    // expected. `deserialize` consumes only what the schema needs.
    let session = ProofUploadSession::deserialize(&mut &data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if session.payer != payer_key.to_bytes() {
        msg!("mosaic: session payer mismatch");
        return Err(ProgramError::Custom(
            OnChainError::SessionContextMismatch.code(),
        ));
    }
    Ok(session)
}

/// Re-derive the session PDA from cached bump and assert it matches the
/// supplied account key. Cheap path (no `find_program_address`).
fn assert_session_pda(
    program_id: &Pubkey,
    session: &ProofUploadSession,
    session_pda_key: &Pubkey,
) -> Result<(), ProgramError> {
    let payer_pubkey = Pubkey::new_from_array(session.payer);
    let derived = Pubkey::create_program_address(
        &[
            SESSION_SEED_PREFIX,
            &session.session_id,
            payer_pubkey.as_ref(),
            &[session.bump],
        ],
        program_id,
    )
    .map_err(|_| ProgramError::InvalidSeeds)?;
    if &derived != session_pda_key {
        return Err(ProgramError::Custom(
            OnChainError::SessionContextMismatch.code(),
        ));
    }
    Ok(())
}

/// Persist `session` back to the PDA's account data buffer.
fn write_session(
    session_pda: &AccountInfo<'_>,
    session: &ProofUploadSession,
) -> Result<(), ProgramError> {
    let mut data = session_pda.try_borrow_mut_data()?;
    let serialized = borsh::to_vec(session).map_err(|_| ProgramError::InvalidAccountData)?;
    if serialized.len() > data.len() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..serialized.len()].copy_from_slice(&serialized);
    Ok(())
}

/// Close `session_pda` by transferring all lamports to `recipient` and
/// reassigning to the system program. Standard Solana close pattern.
fn close_session(
    session_pda: &AccountInfo<'_>,
    recipient: &AccountInfo<'_>,
) -> Result<(), ProgramError> {
    let session_lamports = session_pda.lamports();
    let recipient_lamports = recipient.lamports();
    **recipient.try_borrow_mut_lamports()? = recipient_lamports
        .checked_add(session_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **session_pda.try_borrow_mut_lamports()? = 0;
    session_pda.assign(&system_program::ID);
    // realloc to 0 isn't strictly required (the runtime drops zero-lamport
    // accounts at end-of-transaction) but it makes the close intent explicit.
    session_pda.realloc(0, false)?;
    Ok(())
}

// ---------- 0x10 InitializeSession ----------

/// Wire payload (after the tag byte):
/// `session_id: [u8;32] ‖ total_len: u32 LE ‖ proof_system_id: u8 ‖ h_0: [u8;32]`
fn initialize_session(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    payload: &[u8],
) -> ProgramResult {
    if payload.len() != 32 + 4 + 1 + 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let session_id = read_array::<32>(payload, 0)?;
    let total_len = read_u32_le(payload, 32)?;
    let proof_system_id = *payload
        .get(36)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let h_0 = read_array::<32>(payload, 37)?;

    if total_len == 0 {
        return Err(ProgramError::Custom(
            OnChainError::ProofLengthMismatch.code(),
        ));
    }
    if total_len > MAX_PROOF_LEN {
        return Err(ProgramError::Custom(OnChainError::ChunkOverflow.code()));
    }
    // Reject unknown proof systems early.
    let _ = ProofSystemId::from_byte(proof_system_id).map_err(ProgramError::from)?;

    let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let system_prog = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if system_prog.key != &system_program::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Derive the PDA and validate it matches the supplied account.
    let payer_bytes = payer.key.to_bytes();
    let (expected_pda, bump) = Pubkey::find_program_address(
        &[SESSION_SEED_PREFIX, &session_id, payer.key.as_ref()],
        program_id,
    );
    if &expected_pda != session_pda.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Reject if PDA already initialized as our session (idempotency guard).
    if session_pda.owner == program_id && !session_pda.data_is_empty() {
        return Err(ProgramError::Custom(
            OnChainError::SessionAlreadyInitialized.code(),
        ));
    }

    let space = ProofUploadSession::account_size_for(total_len);
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space);

    let create_ix = system_instruction::create_account(
        payer.key,
        session_pda.key,
        lamports,
        space as u64,
        program_id,
    );
    invoke_signed(
        &create_ix,
        &[payer.clone(), session_pda.clone(), system_prog.clone()],
        &[&[
            SESSION_SEED_PREFIX,
            &session_id,
            payer.key.as_ref(),
            &[bump],
        ]],
    )?;

    let clock = Clock::get()?;
    let session = ProofUploadSession::new(
        session_id,
        payer_bytes,
        bump,
        proof_system_id,
        total_len,
        h_0,
        clock.slot,
    );
    write_session(session_pda, &session)?;
    msg!(
        "mosaic: chunked init session ok, total_len={}, expires_at={}",
        total_len,
        session.expires_at_slot,
    );
    Ok(())
}

// ---------- 0x11 AppendChunk ----------

/// Wire payload (after the tag byte):
/// `chunk_index: u16 LE ‖ chunk_len: u16 LE ‖ chunk_bytes: [u8; chunk_len]`
fn append_chunk(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    payload: &[u8],
) -> ProgramResult {
    let chunk_index = read_u16_le(payload, 0)?;
    let chunk_len = read_u16_le(payload, 2)? as usize;
    if chunk_len > CHUNK_SIZE {
        return Err(ProgramError::Custom(OnChainError::ChunkOverflow.code()));
    }
    let chunk = payload
        .get(
            4..4_usize
                .checked_add(chunk_len)
                .ok_or(ProgramError::InvalidInstructionData)?,
        )
        .ok_or(ProgramError::InvalidInstructionData)?;

    let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut session = load_session(program_id, session_pda, payer.key)?;
    assert_session_pda(program_id, &session, session_pda.key)?;

    // Compute next rolling hash via the syscall.
    let next_hash = solana_program::hash::hashv(&[&session.rolling_hash, chunk]).to_bytes();

    session
        .append_chunk(chunk_index, chunk, next_hash)
        .map_err(ProgramError::from)?;
    write_session(session_pda, &session)?;
    Ok(())
}

// ---------- 0x12 CommitAndVerify ----------

/// Wire payload (after the tag byte):
/// `expected_final_hash: [u8;32] ‖ vk_account_offset: u32 LE ‖ public_inputs_len: u16 LE ‖ public_inputs_bytes`
fn commit_and_verify(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    payload: &[u8],
) -> ProgramResult {
    let expected_hash = read_array::<32>(payload, 0)?;
    let vk_offset = read_u32_le(payload, 32)? as usize;
    let pi_len = read_u16_le(payload, 36)? as usize;
    let pi_start: usize = 38;
    let pi_end = pi_start
        .checked_add(pi_len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let public_inputs = payload
        .get(pi_start..pi_end)
        .ok_or(ProgramError::InvalidInstructionData)?;

    let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let vk_account = accounts
        .get(vk_offset)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    let mut session = load_session(program_id, session_pda, payer.key)?;
    assert_session_pda(program_id, &session, session_pda.key)?;

    session
        .finalize(expected_hash)
        .map_err(ProgramError::from)?;
    write_session(session_pda, &session)?; // persist `finalized = true` defence-in-depth

    let proof_system_id =
        ProofSystemId::from_byte(session.proof_system_id).map_err(ProgramError::from)?;
    let vk_data = vk_account.try_borrow_data()?;

    match dispatch_verify(proof_system_id, &vk_data, &session.assembled, public_inputs) {
        Ok(()) => {
            drop(vk_data);
            msg!("mosaic: chunked verify ok, closing session");
            close_session(session_pda, payer)?;
            Ok(())
        },
        Err(err) => {
            drop(vk_data);
            session.record_verify_failure(err.code());
            write_session(session_pda, &session)?;
            msg!("mosaic: chunked verify failed, error=0x{:04X}", err.code());
            Err(ProgramError::from(err))
        },
    }
}

// ---------- 0x15 BeginStarkVerify ----------

/// Finalize the session, run the STARK setup gate (shape + PoW + OOD)
/// over the assembled proof, and record `num_queries` so the subsequent
/// [`stark_verify_step`] instructions can verify the queries in batches
/// that each fit under the 1.4M CU per-transaction cap (#76).
///
/// Payload: `expected_final_hash(32) ‖ vk_account_offset(u32 LE) ‖
/// public_inputs_len(u16 LE) ‖ public_inputs`. Same shape as
/// `commit_and_verify`.
fn begin_stark_verify(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    payload: &[u8],
) -> ProgramResult {
    let expected_hash = read_array::<32>(payload, 0)?;
    let vk_offset = read_u32_le(payload, 32)? as usize;
    let pi_len = read_u16_le(payload, 36)? as usize;
    let pi_start: usize = 38;
    let pi_end = pi_start
        .checked_add(pi_len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let public_inputs = payload
        .get(pi_start..pi_end)
        .ok_or(ProgramError::InvalidInstructionData)?;

    let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let vk_account = accounts
        .get(vk_offset)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    let mut session = load_session(program_id, session_pda, payer.key)?;
    assert_session_pda(program_id, &session, session_pda.key)?;

    let psid = ProofSystemId::from_byte(session.proof_system_id).map_err(ProgramError::from)?;
    if psid != ProofSystemId::FriStark {
        return Err(ProgramError::from(OnChainError::UnsupportedOperation));
    }

    if !session.finalized {
        session.finalize(expected_hash).map_err(ProgramError::from)?;
        write_session(session_pda, &session)?;
    }

    let backend = SolanaSyscallBackend::new();
    let v = FriStark::new(&backend);
    let vk_data = vk_account.try_borrow_data()?;
    let setup = FriStark::verify_setup(&v, &vk_data, &session.assembled, public_inputs);
    drop(vk_data);
    match setup {
        Ok(num_queries) => {
            session
                .stark_verify_begin(num_queries)
                .map_err(ProgramError::from)?;
            msg!("mosaic: stark verify begun, {} queries", num_queries);
            if session.stark_verify_complete() {
                close_session(session_pda, payer)?;
            } else {
                write_session(session_pda, &session)?;
            }
            Ok(())
        },
        Err(err) => {
            session.record_verify_failure(err.code());
            write_session(session_pda, &session)?;
            msg!("mosaic: stark setup failed, error=0x{:04X}", err.code());
            Err(ProgramError::from(err))
        },
    }
}

// ---------- 0x16 StarkVerifyStep ----------

/// Verify the next `batch` queries of a chunked STARK proof, advancing
/// the session cursor. When the final query passes, the session is
/// closed (rent refunded) and the proof is fully verified. A failing
/// query records the error and leaves the session open for inspection.
///
/// Payload: `vk_account_offset(u32 LE) ‖ public_inputs_len(u16 LE) ‖
/// public_inputs ‖ batch(u16 LE)`.
fn stark_verify_step(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    payload: &[u8],
) -> ProgramResult {
    let vk_offset = read_u32_le(payload, 0)? as usize;
    let pi_len = read_u16_le(payload, 4)? as usize;
    let pi_start: usize = 6;
    let pi_end = pi_start
        .checked_add(pi_len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let public_inputs = payload
        .get(pi_start..pi_end)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let batch = read_u16_le(payload, pi_end)?;

    let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let vk_account = accounts
        .get(vk_offset)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    let mut session = load_session(program_id, session_pda, payer.key)?;
    assert_session_pda(program_id, &session, session_pda.key)?;

    if !session.stark_verify.setup_done {
        return Err(ProgramError::from(OnChainError::StarkVerifyNotStarted));
    }
    if session.stark_verify_complete() {
        close_session(session_pda, payer)?;
        return Ok(());
    }

    let start = session.stark_verify.next_query;
    let num_queries = session.stark_verify.num_queries;
    let end = start.saturating_add(batch.max(1)).min(num_queries);

    let backend = SolanaSyscallBackend::new();
    let v = FriStark::new(&backend);
    let vk_data = vk_account.try_borrow_data()?;
    let r =
        FriStark::verify_query_range(&v, &vk_data, &session.assembled, public_inputs, start, end);
    drop(vk_data);
    match r {
        Ok(()) => {
            session.stark_verify_advance(end).map_err(ProgramError::from)?;
            if session.stark_verify_complete() {
                msg!("mosaic: stark verify complete, closing session");
                close_session(session_pda, payer)?;
            } else {
                msg!("mosaic: stark verify advanced to {}/{}", end, num_queries);
                write_session(session_pda, &session)?;
            }
            Ok(())
        },
        Err(err) => {
            session.record_verify_failure(err.code());
            write_session(session_pda, &session)?;
            msg!("mosaic: stark step failed, error=0x{:04X}", err.code());
            Err(ProgramError::from(err))
        },
    }
}

// ---------- 0x13 CancelSession ----------

fn cancel_session(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    _payload: &[u8],
) -> ProgramResult {
    let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let session = load_session(program_id, session_pda, payer.key)?;
    assert_session_pda(program_id, &session, session_pda.key)?;
    close_session(session_pda, payer)?;
    msg!("mosaic: session cancelled by payer");
    Ok(())
}

// ---------- 0x14 CancelExpiredSession (permissionless) ----------

fn cancel_expired_session(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    _payload: &[u8],
) -> ProgramResult {
    let caller = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let payer_account = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !caller.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Owner check (don't go through `load_session` because we don't bind
    // the caller to the session payer here).
    if session_pda.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let data = session_pda.try_borrow_data()?;
    let session = ProofUploadSession::deserialize(&mut &data[..])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    // Recipient must be the session's recorded payer; otherwise we'd let
    // the caller redirect the rent.
    if payer_account.key.to_bytes() != session.payer {
        return Err(ProgramError::Custom(
            OnChainError::SessionContextMismatch.code(),
        ));
    }
    assert_session_pda(program_id, &session, session_pda.key)?;

    let clock = Clock::get()?;
    if !session.is_expired(clock.slot) {
        return Err(ProgramError::Custom(OnChainError::SessionNotExpired.code()));
    }

    close_session(session_pda, payer_account)?;
    msg!("mosaic: expired session GC'd, rent refunded to payer");
    Ok(())
}
