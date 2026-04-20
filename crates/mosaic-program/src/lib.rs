//! # mosaic-program
//!
//! Reference Solana on-chain program for the Mosaic verifier suite.
//!
//! Top-level instruction dispatch:
//!
//! | Tag      | Operation |
//! |---|---|
//! | `0x01`   | `VerifyProof` (single transaction, ≤1232 B payload) |
//! | `0x10`   | `InitializeSession` (chunked upload) |
//! | `0x11`   | `AppendChunk` (chunked upload) |
//! | `0x12`   | `CommitAndVerify` (chunked upload) |
//! | `0x13`   | `CancelSession` (chunked upload) |
//! | `0x14`   | `CancelExpiredSession` (chunked upload, permissionless GC) |
//!
//! ## Compute budget
//!
//! Callers should request enough compute units up front:
//!
//! ```ignore
//! use solana_sdk::compute_budget::ComputeBudgetInstruction;
//! let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(200_000);
//! transaction.add(&cu_ix);
//! transaction.add(&verify_proof_ix);
//! ```
//!
//! See `docs/compute-unit-budget.md` for per-system targets.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![allow(unexpected_cfgs)]

extern crate alloc;

pub mod chunked;

use alloc::{format, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::solana::SolanaSyscallBackend,
    OnChainError,
};
use mosaic_groth16::Groth16Verifier;
use mosaic_halo2::Halo2KzgBn254;
use mosaic_hyperplonk::HyperPlonkKzgBn254;
use mosaic_plonk::PlonkKzgBn254;
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

/// On-chain program ID. Match against the Cargo metadata.
pub const PROGRAM_ID: Pubkey =
    solana_program::pubkey!("MosA1cVer1f1er11111111111111111111111111111");

/// Top-level instruction discriminant. Chunked-upload instructions use
/// the 0x10..=0x1F range and are dispatched separately (see [`chunked`]).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InstructionTag {
    /// Verify a single proof. Borsh payload: `VerifyProofData`.
    VerifyProof = 0x01,
    /// Verify N proofs sharing the same VK. Borsh payload:
    /// `VerifyProofBatchData`. Amortizes the pairing check via
    /// Bowe-Gabizon aggregation when the proof system supports it
    /// (Groth16); falls back to looped single-verify otherwise.
    VerifyProofBatch = 0x02,
}

/// Decoded `VerifyProof` payload.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct VerifyProofData {
    /// Proof system selector.
    pub proof_system_id: u8,
    /// Verifying key bytes (canonical format).
    pub vk: Vec<u8>,
    /// Proof bytes (canonical format).
    pub proof: Vec<u8>,
    /// Public inputs (canonical format).
    pub public_inputs: Vec<u8>,
}

/// Decoded `VerifyProofBatch` payload.
///
/// `proofs.len()` must equal `public_inputs.len()`. Empty batch is
/// accepted and succeeds trivially (matches `batch_verify` semantics).
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct VerifyProofBatchData {
    /// Proof system selector (applies to all proofs).
    pub proof_system_id: u8,
    /// Verifying key bytes shared by all N proofs.
    pub vk: Vec<u8>,
    /// N proof byte buffers in canonical format.
    pub proofs: Vec<Vec<u8>>,
    /// N public-input byte buffers. `public_inputs[i]` corresponds to
    /// `proofs[i]`.
    pub public_inputs: Vec<Vec<u8>>,
}

/// Top-level entrypoint.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    instruction_data: &[u8],
) -> ProgramResult {
    if program_id != &PROGRAM_ID {
        msg!("mosaic: program-id mismatch");
        return Err(ProgramError::IncorrectProgramId);
    }
    let (tag, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *tag {
        x if x == InstructionTag::VerifyProof as u8 => handle_verify_proof(rest),
        x if x == InstructionTag::VerifyProofBatch as u8 => handle_verify_proof_batch(rest),
        // Chunked-upload instructions: 0x10..=0x1F is reserved for this group.
        // Re-prepend the tag because the sub-dispatcher reads it again.
        x if (0x10..=0x1F).contains(&x) => chunked::dispatch(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn handle_verify_proof(data: &[u8]) -> ProgramResult {
    let payload = VerifyProofData::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let id = ProofSystemId::from_byte(payload.proof_system_id).map_err(ProgramError::from)?;
    msg!("mosaic: dispatch {}", id.slug());
    dispatch_verify(id, &payload.vk, &payload.proof, &payload.public_inputs)
        .map_err(ProgramError::from)
}

fn handle_verify_proof_batch(data: &[u8]) -> ProgramResult {
    let payload = VerifyProofBatchData::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    if payload.proofs.len() != payload.public_inputs.len() {
        return Err(OnChainError::PublicInputCountMismatch.into());
    }
    let id = ProofSystemId::from_byte(payload.proof_system_id).map_err(ProgramError::from)?;
    let proof_refs: Vec<&[u8]> = payload.proofs.iter().map(|v| v.as_slice()).collect();
    let pi_refs: Vec<&[u8]> = payload.public_inputs.iter().map(|v| v.as_slice()).collect();
    msg!("mosaic: batch {} n={}", id.slug(), payload.proofs.len());
    dispatch_verify_batch(id, &payload.vk, &proof_refs, &pi_refs).map_err(ProgramError::from)
}

/// Shared verifier-dispatch helper used by both `handle_verify_proof` and
/// `chunked::commit_and_verify`. Reads canonical bytes, picks the verifier,
/// invokes it against the Solana syscall backend.
pub(crate) fn dispatch_verify(
    id: ProofSystemId,
    vk: &[u8],
    proof: &[u8],
    public_inputs: &[u8],
) -> Result<(), OnChainError> {
    let backend = SolanaSyscallBackend::new();
    match id {
        ProofSystemId::Groth16Bn254 => {
            let v = Groth16Verifier::<_, false>::new(&backend);
            ProofSystem::verify(&v, vk, proof, public_inputs)
        },
        ProofSystemId::PlonkKzgBn254 => {
            let v = PlonkKzgBn254::new(&backend);
            PlonkKzgBn254::verify(&v, vk, proof, public_inputs)
        },
        ProofSystemId::HyperPlonkKzgBn254 => {
            // Phase-3 scaffold — currently returns UnimplementedProofSystem,
            // but wire-format checks run so layout regressions surface.
            let v = HyperPlonkKzgBn254::new(&backend);
            HyperPlonkKzgBn254::verify(&v, vk, proof, public_inputs)
        },
        ProofSystemId::Halo2KzgBn254 => {
            // Phase-3 scaffold — same shape as HyperPlonk above: wire-format
            // checks run so layout regressions surface before the real
            // verifier body lands.
            let v = Halo2KzgBn254::new(&backend);
            Halo2KzgBn254::verify(&v, vk, proof, public_inputs)
        },
        ProofSystemId::FriStark
        | ProofSystemId::Risc0Stark
        | ProofSystemId::NovaFolding
        | ProofSystemId::ProtoStarFolding => Err(OnChainError::UnimplementedProofSystem),
        // `ProofSystemId` is `#[non_exhaustive]`; new variants land via
        // ADR-0001 amendment and add their dispatch arms above.
        _ => Err(OnChainError::UnknownProofSystem),
    }
}

/// Batched dispatch counterpart to [`dispatch_verify`]. Only Groth16
/// has true amortization today; other systems would loop via the trait
/// default, which offers no CU savings — we return `UnsupportedOperation`
/// for them until per-system batch implementations land.
pub(crate) fn dispatch_verify_batch(
    id: ProofSystemId,
    vk: &[u8],
    proofs: &[&[u8]],
    public_inputs: &[&[u8]],
) -> Result<(), OnChainError> {
    let backend = SolanaSyscallBackend::new();
    match id {
        ProofSystemId::Groth16Bn254 => {
            let v = Groth16Verifier::<_, false>::new(&backend);
            ProofSystem::batch_verify(&v, vk, proofs, public_inputs)
        },
        // PLONK/Halo2/STARK/Nova don't amortize batch today. Explicit
        // UnsupportedOperation rather than silent looped fallback —
        // callers who want N independent verifications should send N
        // separate VerifyProof transactions.
        _ => Err(OnChainError::UnsupportedOperation),
    }
}
