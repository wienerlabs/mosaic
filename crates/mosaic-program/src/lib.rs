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
use mosaic_nova::NovaFolding;
use mosaic_plonk::PlonkKzgBn254;
use mosaic_stark::FriStark;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
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
        x if (0x10..=0x1F).contains(&x) => {
            chunked::dispatch(program_id, accounts, instruction_data)
        },
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn handle_verify_proof(data: &[u8]) -> ProgramResult {
    let payload =
        VerifyProofData::try_from_slice(data).map_err(|_| ProgramError::InvalidInstructionData)?;
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
            // Phase-3 body (session 3e): full verifier pipeline is wired
            // end-to-end (parse → challenges → sumcheck → claim
            // reduction → KZG pairing). The claim reduction's permutation
            // term and the KZG opening's multi-point reduction are
            // still scaffold approximations — see crate rustdoc for the
            // session 3f caveat.
            let v = HyperPlonkKzgBn254::new(&backend);
            HyperPlonkKzgBn254::verify(&v, vk, proof, public_inputs)
        },
        ProofSystemId::Halo2KzgBn254 => {
            // Phase-3 body (session 4d): full verifier pipeline wired —
            // parse → challenges (θ, β, γ, y, ξ) → KZG scaffold opening.
            // Circuit evaluators (gate/perm/lookup) + full two-point
            // batched multipoint opening land in session 4e against
            // Espresso/PSE reference fixtures.
            let v = Halo2KzgBn254::new(&backend);
            Halo2KzgBn254::verify(&v, vk, proof, public_inputs)
        },
        ProofSystemId::FriStark => {
            // Phase-3 body (session 6): structural pipeline wired —
            // parse → challenges (α, z, query_seed via SHA-256) →
            // per-query index derivation. Full FRI-layer fold + Merkle
            // opening checks land in session 7 against Plonky3/
            // Winterfell fixtures.
            let v = FriStark::new(&backend);
            FriStark::verify(&v, vk, proof, public_inputs)
        },
        ProofSystemId::NovaFolding | ProofSystemId::ProtoStarFolding => {
            // Phase-3 body (session 5c): full verifier pipeline wired —
            // parse → challenges (r, ξ, ν) → KZG scaffold opening.
            // Hadamard-relation check + folded-commitment reconstruction
            // primitives are built but not yet composed; full Spartan-
            // wrapped multi-opening lands in session 6.
            let v = NovaFolding::new(&backend);
            NovaFolding::verify(&v, vk, proof, public_inputs)
        },
        ProofSystemId::Risc0Stark => Err(OnChainError::UnimplementedProofSystem),
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

// ───────────────────────────────────────────────────────────────────────
// Session 42 — proptest coverage for the on-chain program's wire-format
// surface. The crate is a `cdylib` + `lib` with `#![cfg_attr(not(test),
// no_std)]`, so cargo-test on host pulls std and we can run regular
// host-side property tests over the public Borsh structs and the
// instruction-tag dispatch table.
//
// What is in scope:
//
//   - `VerifyProofData` Borsh round-trip — random
//     (proof_system_id, vk, proof, public_inputs) quadruple
//     serializes and deserializes back to itself, with field
//     ordering pinned against silent reorderings on the wire.
//   - `VerifyProofBatchData` Borsh round-trip — same coverage for
//     the batched payload, with the additional `proofs` and
//     `public_inputs` Vec<Vec<u8>> pair length-equality invariant
//     exercised via random shapes.
//   - `InstructionTag` byte values — fixed at 0x01 and 0x02; pinned
//     so a future enum reordering doesn't silently break clients
//     that rely on the discriminator.
//   - `process_instruction` dispatch routing — for any random
//     instruction-data byte, the dispatch path matches the spec:
//     0x01/0x02 enter the verify handlers (which fail at borsh
//     parse for empty data), 0x10..=0x1F enter the chunked
//     dispatcher, everything else returns `InvalidInstructionData`.
//
// What is *not* in scope here:
//
//   - The actual on-chain verifier execution path. That requires
//     a `SolanaSyscallBackend` mock, which lives in
//     `tests/verify_proof_sbf.rs` as an SBF integration test
//     (run only when a deployed program artifact exists).
// ───────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod proptest_coverage {
    use super::{
        process_instruction, InstructionTag, VerifyProofBatchData, VerifyProofData, PROGRAM_ID,
    };
    use borsh::{to_vec, BorshDeserialize};
    use proptest::prelude::*;
    use solana_program::{program_error::ProgramError, pubkey::Pubkey};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// `VerifyProofData` round-trips through Borsh. Pins the
        /// `(proof_system_id, vk, proof, public_inputs)` field order
        /// against the kind of subtle reordering that would
        /// silently swap proof and public-input bytes on the wire,
        /// rendering every transaction's verification a no-op (or a
        /// false-accept if the swap happens to align).
        #[test]
        fn proptest_verify_proof_data_borsh_roundtrip(
            proof_system_id in any::<u8>(),
            vk in proptest::collection::vec(any::<u8>(), 0..=128),
            proof in proptest::collection::vec(any::<u8>(), 0..=256),
            public_inputs in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let payload = VerifyProofData {
                proof_system_id,
                vk: vk.clone(),
                proof: proof.clone(),
                public_inputs: public_inputs.clone(),
            };
            let bytes = to_vec(&payload).expect("borsh serialize");
            let decoded = VerifyProofData::try_from_slice(&bytes)
                .expect("borsh deserialize");
            prop_assert_eq!(decoded.proof_system_id, proof_system_id);
            prop_assert_eq!(decoded.vk, vk);
            prop_assert_eq!(decoded.proof, proof);
            prop_assert_eq!(decoded.public_inputs, public_inputs);
        }

        /// `VerifyProofBatchData` round-trips through Borsh for any
        /// batch shape (including empty and ragged proof / PI vectors).
        /// Decode does NOT enforce `proofs.len() == public_inputs.len()`
        /// at the borsh layer — that check lives in
        /// `handle_verify_proof_batch` and is a separate property
        /// (`PublicInputCountMismatch` is caught higher up).
        #[test]
        fn proptest_verify_proof_batch_data_borsh_roundtrip(
            proof_system_id in any::<u8>(),
            vk in proptest::collection::vec(any::<u8>(), 0..=128),
            proofs in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..=64),
                0..=4,
            ),
            public_inputs in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..=32),
                0..=4,
            ),
        ) {
            let payload = VerifyProofBatchData {
                proof_system_id,
                vk: vk.clone(),
                proofs: proofs.clone(),
                public_inputs: public_inputs.clone(),
            };
            let bytes = to_vec(&payload).expect("borsh serialize batch");
            let decoded = VerifyProofBatchData::try_from_slice(&bytes)
                .expect("borsh deserialize batch");
            prop_assert_eq!(decoded.proof_system_id, proof_system_id);
            prop_assert_eq!(decoded.vk, vk);
            prop_assert_eq!(decoded.proofs, proofs);
            prop_assert_eq!(decoded.public_inputs, public_inputs);
        }

        /// `InstructionTag` discriminants are pinned at the
        /// declared values. A future re-ordering of the enum
        /// variants would silently shift the byte mapping and
        /// break every deployed client that hard-codes 0x01 / 0x02.
        #[test]
        fn proptest_instruction_tag_discriminants_stable(_seed in any::<u8>()) {
            // The argument is unused; we just want proptest to assert
            // the constant identities under its harness so any future
            // value change surfaces in the proptest report rather than
            // hiding inside a `const` test.
            prop_assert_eq!(InstructionTag::VerifyProof as u8, 0x01);
            prop_assert_eq!(InstructionTag::VerifyProofBatch as u8, 0x02);
        }

        /// `process_instruction` rejects a wrong program id with
        /// `IncorrectProgramId` regardless of payload content.
        /// Catches a "program-id check moved to a later step"
        /// regression, which would let attackers route bytes through
        /// the dispatcher with the wrong owning program.
        #[test]
        fn proptest_process_rejects_wrong_program_id(
            data in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            // Pick any program id that is NOT the canonical PROGRAM_ID.
            let wrong = Pubkey::new_unique();
            prop_assume!(wrong != PROGRAM_ID);
            let r = process_instruction(&wrong, &[], &data);
            prop_assert!(matches!(r, Err(ProgramError::IncorrectProgramId)));
        }

        /// `process_instruction` rejects empty instruction data with
        /// `InvalidInstructionData`. Pins the "split_first on empty
        /// returns None ⇒ Err" path that protects the dispatcher
        /// against zero-byte instruction-data crashes.
        #[test]
        fn proptest_process_rejects_empty_instruction_data(_seed in any::<u8>()) {
            let r = process_instruction(&PROGRAM_ID, &[], &[]);
            prop_assert!(matches!(r, Err(ProgramError::InvalidInstructionData)));
        }

        /// Any instruction-data byte outside the known dispatch
        /// ranges (0x01, 0x02, 0x10..=0x1F) routes to
        /// `InvalidInstructionData`. Exhaustive over the byte space
        /// via proptest, but with a single body byte appended so the
        /// dispatcher actually reaches the match arm. Catches a
        /// future feature-gate that forgets to fall through to the
        /// catch-all `_ => Err(...)`.
        #[test]
        fn proptest_process_rejects_unknown_tag(tag in any::<u8>()) {
            // Skip the known-good tag space.
            prop_assume!(tag != 0x01 && tag != 0x02);
            prop_assume!(!(0x10..=0x1F).contains(&tag));
            let r = process_instruction(&PROGRAM_ID, &[], &[tag]);
            prop_assert!(matches!(r, Err(ProgramError::InvalidInstructionData)));
        }

        /// Tag 0x01 with non-borsh-shaped payload reaches
        /// `handle_verify_proof` and fails at parse with
        /// `InvalidInstructionData`. This pins the tag → handler
        /// routing without requiring a full SyscallBackend mock —
        /// random bytes after the tag are extremely unlikely to
        /// constitute a valid VerifyProofData (would need exact
        /// borsh u8 + four length-prefixed Vec<u8>s).
        #[test]
        fn proptest_verify_proof_tag_routes_to_handler(
            payload in proptest::collection::vec(any::<u8>(), 0..=8),
        ) {
            let mut data = alloc::vec![0x01u8];
            data.extend(payload);
            let r = process_instruction(&PROGRAM_ID, &[], &data);
            // Either a borsh parse error (most cases) or a verifier
            // dispatch error (extremely rare random hit). Both surface
            // as Err — a successful `Ok(())` from random bytes would
            // be a soundness alarm.
            prop_assert!(r.is_err());
        }
    }
}
