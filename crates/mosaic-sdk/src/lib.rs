//! # mosaic-sdk
//!
//! Client-side helpers for building `VerifyProof` transactions and running
//! pre-flight verification locally before paying the on-chain CU cost.
//!
//! Phase 1 ships:
//!
//! - [`build_verify_proof_ix`] — assemble a Solana `Instruction` from a
//!   [`VerifyRequest`].
//! - [`preflight`] — run host-backend verification against the same canonical
//!   bytes the program will see, surfacing failures locally.
//!
//! Phases 2/3 will add:
//!
//! - Chunked-upload session helpers.
//! - PLONK / STARK / Nova request builders.
//! - WASM/JS bindings (separate `mosaic-sdk-js` crate).

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use borsh::BorshSerialize;
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::host::HostBackend,
};
use mosaic_groth16::Groth16Verifier;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

/// Inputs to a single proof verification.
#[derive(Clone, Debug)]
pub struct VerifyRequest {
    /// On-chain program id.
    pub program_id: Pubkey,
    /// Proof system selector.
    pub proof_system: ProofSystemId,
    /// Canonical-format VK bytes.
    pub vk: Vec<u8>,
    /// Canonical-format proof bytes.
    pub proof: Vec<u8>,
    /// Canonical-format public inputs.
    pub public_inputs: Vec<u8>,
    /// Caller-provided account metas (none for the reference program).
    pub accounts: Vec<AccountMeta>,
}

/// Borsh-compatible payload mirroring `mosaic_program::VerifyProofData`.
/// We avoid a direct dependency on `mosaic-program` (which is `cdylib`)
/// to keep the SDK fully host-buildable.
#[derive(BorshSerialize)]
struct VerifyProofData {
    proof_system_id: u8,
    vk: Vec<u8>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

/// Build a `VerifyProof` instruction.
pub fn build_verify_proof_ix(req: &VerifyRequest) -> Result<Instruction> {
    let payload = VerifyProofData {
        proof_system_id: req.proof_system.as_byte(),
        vk: req.vk.clone(),
        proof: req.proof.clone(),
        public_inputs: req.public_inputs.clone(),
    };
    let mut data = Vec::with_capacity(1 + payload.vk.len() + payload.proof.len() + payload.public_inputs.len() + 16);
    data.push(0x01); // InstructionTag::VerifyProof
    payload.serialize(&mut data).context("borsh-serialize VerifyProofData")?;
    Ok(Instruction { program_id: req.program_id, accounts: req.accounts.clone(), data })
}

/// Pre-flight verification: run the same verifier on the host backend so the
/// caller catches mismatches before paying for the failed transaction.
pub fn preflight(req: &VerifyRequest) -> Result<()> {
    let backend = HostBackend::new();
    match req.proof_system {
        ProofSystemId::Groth16Bn254 => {
            let v = Groth16Verifier::<_, false>::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("preflight failed: {e}"))
        },
        other => Err(anyhow::anyhow!(
            "preflight not implemented for {} (Phase 2/3)",
            other.slug()
        )),
    }
}
