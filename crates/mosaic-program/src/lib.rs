//! # mosaic-program
//!
//! Reference Solana on-chain program for the Mosaic verifier suite.
//!
//! Exposes a single `VerifyProof` instruction whose first data byte is a
//! [`ProofSystemId`] discriminant. Subsequent layout is system-specific.
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

use alloc::{format, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::solana::SolanaSyscallBackend,
    OnChainError,
};
use mosaic_groth16::Groth16Verifier;
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

/// Top-level instruction discriminant.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InstructionTag {
    /// Verify a single proof. Data layout: `tag || ProofSystemId || vk_len:u32 || vk || proof_len:u32 || proof || pi_len:u32 || pi`.
    VerifyProof = 0x01,
    /// Chunked-upload entry points share the prefix range 0x10..=0x1F (see `mosaic-chunked`).
    ChunkedSession = 0x10,
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

/// Top-level entrypoint.
pub fn process_instruction(
    program_id: &Pubkey,
    _accounts: &[AccountInfo<'_>],
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
        x if x == InstructionTag::ChunkedSession as u8 => {
            // TODO(mosaic-006): wire chunked-session handlers from `mosaic-chunked`.
            Err(ProgramError::Custom(OnChainError::UnimplementedProofSystem.code()))
        },
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn handle_verify_proof(data: &[u8]) -> ProgramResult {
    let payload = VerifyProofData::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let id = ProofSystemId::from_byte(payload.proof_system_id).map_err(ProgramError::from)?;
    msg!("mosaic: dispatch {}", id.slug());
    let backend = SolanaSyscallBackend::new();
    let result = match id {
        ProofSystemId::Groth16Bn254 => {
            let v = Groth16Verifier::<_, false>::new(&backend);
            ProofSystem::verify(&v, &payload.vk, &payload.proof, &payload.public_inputs)
        },
        // Phase 2/3 systems route to their stubs — they all return
        // `UnimplementedProofSystem` until their crates ship.
        ProofSystemId::PlonkKzgBn254
        | ProofSystemId::HyperPlonkKzgBn254
        | ProofSystemId::Halo2KzgBn254
        | ProofSystemId::FriStark
        | ProofSystemId::Risc0Stark
        | ProofSystemId::NovaFolding
        | ProofSystemId::ProtoStarFolding => Err(OnChainError::UnimplementedProofSystem),
        // `ProofSystemId` is `#[non_exhaustive]`; new variants land via
        // ADR-0001 amendment and add their dispatch arms above.
        _ => Err(OnChainError::UnknownProofSystem),
    };
    result.map_err(ProgramError::from)
}
