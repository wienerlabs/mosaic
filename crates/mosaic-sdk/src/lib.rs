//! # mosaic-sdk
//!
//! Client-side helpers for building `VerifyProof` transactions and running
//! pre-flight verification locally before paying the on-chain CU cost.
//!
//! ## What's here
//!
//! - [`VerifyRequest`] — proof-system-agnostic inputs to a single
//!   verification (VK bytes, proof bytes, public inputs, program id).
//! - [`build_verify_proof_ix`] — assemble a Solana `Instruction` from a
//!   [`VerifyRequest`].
//! - [`preflight`] — run host-backend verification against the same
//!   canonical bytes the program will see, surfacing failures locally
//!   rather than via a failed on-chain transaction. Groth16 is always
//!   available; Phase-3 systems opt in through Cargo features
//!   (`plonk`, `hyperplonk`, `halo2`, `nova`, `stark`, or `all-phase3`).
//! - [`build_chunked_stark_plan`] — assemble the full multi-transaction
//!   instruction sequence for a chunked FRI-STARK verification (#76),
//!   for proofs whose single-shot verify exceeds the 1.4M CU
//!   per-transaction cap.
//!
//! ## Feature matrix (session 33)
//!
//! | Feature | Adds | Compile-time dep |
//! |---|---|---|
//! | `default` | Groth16 preflight only | — |
//! | `plonk` | KZG-PLONK BN254 preflight | `mosaic-plonk` |
//! | `hyperplonk` | HyperPlonk-KZG preflight | `mosaic-hyperplonk` |
//! | `halo2` | Halo2-KZG preflight | `mosaic-halo2` |
//! | `nova` | Nova / HyperNova / ProtoStar preflight | `mosaic-nova` |
//! | `stark` | FRI-STARK preflight | `mosaic-stark` |
//! | `all-phase3` | All five Phase-3 systems | all above |
//!
//! For any non-enabled system, [`preflight`] returns an
//! `anyhow::Error` naming the feature needed.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use borsh::BorshSerialize;
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::host::HostBackend,
};
use mosaic_chunked::{
    ProofUploadSession, CHUNK_SIZE, DOMAIN_TAG, MAX_PROOF_LEN, SESSION_SEED_PREFIX,
};
use mosaic_groth16::Groth16Verifier;
use solana_sdk::{
    hash::hashv,
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

impl VerifyRequest {
    /// Start building a [`VerifyRequest`] with the given program id
    /// and proof system. Public inputs, VK, and proof default to
    /// empty; accounts default to none.
    ///
    /// Session-33 quality-of-life constructor — callers who used to
    /// build a struct literal with six named fields can now chain
    /// setters instead.
    #[must_use]
    pub fn builder(program_id: Pubkey, proof_system: ProofSystemId) -> Self {
        Self {
            program_id,
            proof_system,
            vk: Vec::new(),
            proof: Vec::new(),
            public_inputs: Vec::new(),
            accounts: Vec::new(),
        }
    }

    /// Set the verifying-key canonical bytes.
    #[must_use]
    pub fn with_vk(mut self, vk: Vec<u8>) -> Self {
        self.vk = vk;
        self
    }

    /// Set the proof canonical bytes.
    #[must_use]
    pub fn with_proof(mut self, proof: Vec<u8>) -> Self {
        self.proof = proof;
        self
    }

    /// Set the public-input canonical bytes.
    #[must_use]
    pub fn with_public_inputs(mut self, public_inputs: Vec<u8>) -> Self {
        self.public_inputs = public_inputs;
        self
    }

    /// Set the Solana account metas (no-op for the reference program
    /// which doesn't touch accounts).
    #[must_use]
    pub fn with_accounts(mut self, accounts: Vec<AccountMeta>) -> Self {
        self.accounts = accounts;
        self
    }
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
///
/// # Errors
///
/// - Borsh-serialization failure (effectively never for this payload
///   shape).
pub fn build_verify_proof_ix(req: &VerifyRequest) -> Result<Instruction> {
    let payload = VerifyProofData {
        proof_system_id: req.proof_system.as_byte(),
        vk: req.vk.clone(),
        proof: req.proof.clone(),
        public_inputs: req.public_inputs.clone(),
    };
    let mut data = Vec::with_capacity(
        1 + payload.vk.len() + payload.proof.len() + payload.public_inputs.len() + 16,
    );
    data.push(0x01); // InstructionTag::VerifyProof
    payload
        .serialize(&mut data)
        .context("borsh-serialize VerifyProofData")?;
    Ok(Instruction {
        program_id: req.program_id,
        accounts: req.accounts.clone(),
        data,
    })
}

/// Pre-flight verification: run the same verifier on the host backend
/// so the caller catches mismatches before paying for the failed
/// transaction.
///
/// Groth16 is always available. Phase-3 systems (PLONK, HyperPlonk,
/// Halo2, Nova, STARK) require their respective Cargo features;
/// without them, the matching `ProofSystemId` arm returns an error
/// naming the missing feature.
///
/// # Errors
///
/// - The underlying verifier's failure converted to
///   [`anyhow::Error`] (usually a [`mosaic_core::OnChainError`]).
/// - `"preflight not enabled for {slug}; add feature '{name}'"` when
///   the requested proof system's feature is disabled.
/// - `"unimplemented proof system"` for [`ProofSystemId::Risc0`] and
///   other variants without in-tree verifier crates.
pub fn preflight(req: &VerifyRequest) -> Result<()> {
    let backend = HostBackend::new();
    match req.proof_system {
        ProofSystemId::Groth16Bn254 => {
            let v = Groth16Verifier::<_, false>::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("groth16 preflight failed: {e}"))
        },
        #[cfg(feature = "plonk")]
        ProofSystemId::PlonkKzgBn254 => {
            use mosaic_plonk::PlonkKzgBn254;
            let v = PlonkKzgBn254::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("plonk preflight failed: {e}"))
        },
        #[cfg(not(feature = "plonk"))]
        ProofSystemId::PlonkKzgBn254 => Err(anyhow::anyhow!(
            "preflight not enabled for plonk_kzg_bn254; \
             add the 'plonk' feature to mosaic-sdk"
        )),
        #[cfg(feature = "hyperplonk")]
        ProofSystemId::HyperPlonkKzgBn254 => {
            use mosaic_hyperplonk::HyperPlonkKzgBn254;
            let v = HyperPlonkKzgBn254::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("hyperplonk preflight failed: {e}"))
        },
        #[cfg(not(feature = "hyperplonk"))]
        ProofSystemId::HyperPlonkKzgBn254 => Err(anyhow::anyhow!(
            "preflight not enabled for hyperplonk_kzg_bn254; \
             add the 'hyperplonk' feature to mosaic-sdk"
        )),
        #[cfg(feature = "halo2")]
        ProofSystemId::Halo2KzgBn254 => {
            use mosaic_halo2::Halo2KzgBn254;
            let v = Halo2KzgBn254::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("halo2 preflight failed: {e}"))
        },
        #[cfg(not(feature = "halo2"))]
        ProofSystemId::Halo2KzgBn254 => Err(anyhow::anyhow!(
            "preflight not enabled for halo2_kzg_bn254; \
             add the 'halo2' feature to mosaic-sdk"
        )),
        #[cfg(feature = "nova")]
        ProofSystemId::NovaFolding | ProofSystemId::ProtoStarFolding => {
            use mosaic_nova::NovaFolding;
            let v = NovaFolding::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("nova preflight failed: {e}"))
        },
        #[cfg(not(feature = "nova"))]
        ProofSystemId::NovaFolding | ProofSystemId::ProtoStarFolding => Err(anyhow::anyhow!(
            "preflight not enabled for nova_folding_bn254; \
             add the 'nova' feature to mosaic-sdk"
        )),
        #[cfg(feature = "stark")]
        ProofSystemId::FriStark => {
            use mosaic_stark::FriStark;
            let v = FriStark::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("stark preflight failed: {e}"))
        },
        #[cfg(not(feature = "stark"))]
        ProofSystemId::FriStark => Err(anyhow::anyhow!(
            "preflight not enabled for fri_stark; \
             add the 'stark' feature to mosaic-sdk"
        )),
        other => Err(anyhow::anyhow!(
            "preflight not implemented for {} (no in-tree verifier)",
            other.slug()
        )),
    }
}

// ---------------------------------------------------------------------
// Chunked STARK verification (#76)
// ---------------------------------------------------------------------

const PSID_FRI_STARK: u8 = 0x05;

/// Inputs for a chunked FRI-STARK verification (#76).
///
/// A production STARK proof exceeds Solana's 1.4M CU per-transaction
/// cap, so it is uploaded and verified across multiple transactions.
/// [`build_chunked_stark_plan`] turns these inputs into the ordered
/// instruction sequence a client submits.
#[derive(Clone, Debug)]
pub struct ChunkedStarkRequest {
    /// On-chain program id.
    pub program_id: Pubkey,
    /// Fee payer + session owner (signs every instruction).
    pub payer: Pubkey,
    /// 32-byte client nonce that names this upload session.
    pub session_id: [u8; 32],
    /// Account that holds the canonical VK bytes (read-only on chain).
    pub vk_account: Pubkey,
    /// Canonical FRI-STARK proof bytes.
    pub proof: Vec<u8>,
    /// Canonical public inputs.
    pub public_inputs: Vec<u8>,
    /// Queries to verify per `StarkVerifyStep`. Tune so one step's CU
    /// stays under the per-transaction cap; the verifier's per-query
    /// cost scales with FRI depth + layer count.
    pub queries_per_step: u16,
}

/// The ordered instructions for a chunked STARK verification, plus the
/// metadata a client needs to fund the session PDA.
#[derive(Clone, Debug)]
pub struct ChunkedStarkPlan {
    /// Derived session PDA holding the upload + verification state.
    pub session_pda: Pubkey,
    /// PDA bump.
    pub session_bump: u8,
    /// Rent-exempt account size to allocate for the session PDA.
    pub account_size: usize,
    /// Query count parsed from the proof header.
    pub num_queries: u16,
    /// `InitializeSession` (0x10).
    pub initialize: Instruction,
    /// `AppendChunk` (0x11) instructions, in order.
    pub appends: Vec<Instruction>,
    /// `BeginStarkVerify` (0x15) — finalize + setup gate.
    pub begin: Instruction,
    /// `StarkVerifyStep` (0x16) instructions; send each in its own
    /// transaction (each advances the cursor by `queries_per_step`,
    /// the handler clamping the final batch).
    pub steps: Vec<Instruction>,
}

impl ChunkedStarkPlan {
    /// A suggested grouping into transaction-sized instruction batches:
    /// `[initialize + appends + begin]` then one `[step]` per entry.
    ///
    /// For very large proofs the first group may exceed the ~1232-byte
    /// transaction packet limit; split the `appends` across additional
    /// transactions (begin must come after the last append).
    #[must_use]
    pub fn transaction_groups(&self) -> Vec<Vec<Instruction>> {
        let mut groups = Vec::with_capacity(1 + self.steps.len());
        let mut first = Vec::with_capacity(2 + self.appends.len());
        first.push(self.initialize.clone());
        first.extend(self.appends.iter().cloned());
        first.push(self.begin.clone());
        groups.push(first);
        for step in &self.steps {
            groups.push(vec![step.clone()]);
        }
        groups
    }
}

fn session_meta(payer: &Pubkey, session_pda: &Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*payer, true),
        AccountMeta::new(*session_pda, false),
    ]
}

/// Build the full instruction plan for chunked STARK verification (#76).
///
/// The returned plan uploads `proof` in [`CHUNK_SIZE`]-byte chunks, runs
/// the setup gate via `BeginStarkVerify`, then verifies the queries in
/// `queries_per_step` batches via `StarkVerifyStep`. The client submits
/// [`ChunkedStarkPlan::transaction_groups`] (or the individual
/// instructions) and funds the session PDA to `account_size`.
///
/// # Errors
///
/// - The proof is shorter than the 12-byte fixed header, or exceeds
///   [`MAX_PROOF_LEN`].
/// - `queries_per_step` is zero, or there are too many chunks / public
///   inputs to address with the wire-format integer widths.
pub fn build_chunked_stark_plan(req: &ChunkedStarkRequest) -> Result<ChunkedStarkPlan> {
    if req.queries_per_step == 0 {
        anyhow::bail!("queries_per_step must be >= 1");
    }
    if req.proof.len() < 12 {
        anyhow::bail!("proof too short to contain a STARK header");
    }
    let total_len = u32::try_from(req.proof.len())
        .ok()
        .filter(|&l| l <= MAX_PROOF_LEN)
        .context("proof exceeds MAX_PROOF_LEN")?;

    let num_queries = u16::from_le_bytes([req.proof[4], req.proof[5]]);
    let pi_len = u16::try_from(req.public_inputs.len()).context("public inputs too long")?;

    let (session_pda, session_bump) = Pubkey::find_program_address(
        &[SESSION_SEED_PREFIX, &req.session_id, req.payer.as_ref()],
        &req.program_id,
    );

    let h_0 = hashv(&[
        DOMAIN_TAG,
        &req.session_id,
        &total_len.to_le_bytes(),
        &[PSID_FRI_STARK],
    ])
    .to_bytes();

    let mut init_data = Vec::with_capacity(1 + 32 + 4 + 1 + 32);
    init_data.push(0x10);
    init_data.extend_from_slice(&req.session_id);
    init_data.extend_from_slice(&total_len.to_le_bytes());
    init_data.push(PSID_FRI_STARK);
    init_data.extend_from_slice(&h_0);
    let mut init_accounts = session_meta(&req.payer, &session_pda);
    init_accounts.push(AccountMeta::new_readonly(
        solana_sdk::system_program::ID,
        false,
    ));
    let initialize = Instruction {
        program_id: req.program_id,
        accounts: init_accounts,
        data: init_data,
    };

    let mut appends = Vec::new();
    let mut rolling = h_0;
    for (i, chunk) in req.proof.chunks(CHUNK_SIZE).enumerate() {
        let idx = u16::try_from(i).context("too many chunks for u16 index")?;
        let mut data = Vec::with_capacity(1 + 2 + 2 + chunk.len());
        data.push(0x11);
        data.extend_from_slice(&idx.to_le_bytes());
        data.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        data.extend_from_slice(chunk);
        appends.push(Instruction {
            program_id: req.program_id,
            accounts: session_meta(&req.payer, &session_pda),
            data,
        });
        rolling = hashv(&[&rolling, chunk]).to_bytes();
    }
    let final_hash = rolling;

    let mut verify_accounts = session_meta(&req.payer, &session_pda);
    verify_accounts.push(AccountMeta::new_readonly(req.vk_account, false));

    let mut begin_data = Vec::with_capacity(1 + 32 + 4 + 2 + req.public_inputs.len());
    begin_data.push(0x15);
    begin_data.extend_from_slice(&final_hash);
    begin_data.extend_from_slice(&2u32.to_le_bytes()); // vk at account index 2
    begin_data.extend_from_slice(&pi_len.to_le_bytes());
    begin_data.extend_from_slice(&req.public_inputs);
    let begin = Instruction {
        program_id: req.program_id,
        accounts: verify_accounts.clone(),
        data: begin_data,
    };

    // ceil(num_queries / batch) identical steps. A zero-query proof
    // completes at `begin`, so it needs no steps.
    let step_count = num_queries.div_ceil(req.queries_per_step);
    let mut steps = Vec::with_capacity(step_count as usize);
    for _ in 0..step_count {
        let mut data = Vec::with_capacity(1 + 4 + 2 + req.public_inputs.len() + 2);
        data.push(0x16);
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&pi_len.to_le_bytes());
        data.extend_from_slice(&req.public_inputs);
        data.extend_from_slice(&req.queries_per_step.to_le_bytes());
        steps.push(Instruction {
            program_id: req.program_id,
            accounts: verify_accounts.clone(),
            data,
        });
    }

    Ok(ChunkedStarkPlan {
        session_pda,
        session_bump,
        account_size: ProofUploadSession::account_size_for(total_len),
        num_queries,
        initialize,
        appends,
        begin,
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_stark_proof(len: usize, num_queries: u16) -> Vec<u8> {
        let mut p = vec![0u8; len.max(12)];
        p[4..6].copy_from_slice(&num_queries.to_le_bytes());
        p
    }

    fn stark_req(proof_len: usize, num_queries: u16, batch: u16) -> ChunkedStarkRequest {
        ChunkedStarkRequest {
            program_id: Pubkey::new_unique(),
            payer: Pubkey::new_unique(),
            session_id: [7u8; 32],
            vk_account: Pubkey::new_unique(),
            proof: synthetic_stark_proof(proof_len, num_queries),
            public_inputs: Vec::new(),
            queries_per_step: batch,
        }
    }

    #[test]
    fn chunked_stark_plan_parses_num_queries_and_tags() {
        let req = stark_req(500, 4, 2);
        let plan = build_chunked_stark_plan(&req).unwrap();
        assert_eq!(plan.num_queries, 4);
        assert_eq!(plan.initialize.data[0], 0x10);
        assert_eq!(plan.appends[0].data[0], 0x11);
        assert_eq!(plan.begin.data[0], 0x15);
        assert_eq!(plan.steps[0].data[0], 0x16);
        // begin vk_offset is account index 2.
        assert_eq!(&plan.begin.data[33..37], &2u32.to_le_bytes());
        assert_eq!(plan.begin.accounts.len(), 3);
        assert_eq!(plan.begin.accounts[2].pubkey, req.vk_account);
    }

    #[test]
    fn chunked_stark_plan_pda_and_account_size_match() {
        let req = stark_req(500, 4, 2);
        let plan = build_chunked_stark_plan(&req).unwrap();
        let (expected_pda, expected_bump) = Pubkey::find_program_address(
            &[SESSION_SEED_PREFIX, &req.session_id, req.payer.as_ref()],
            &req.program_id,
        );
        assert_eq!(plan.session_pda, expected_pda);
        assert_eq!(plan.session_bump, expected_bump);
        assert_eq!(
            plan.account_size,
            ProofUploadSession::account_size_for(req.proof.len() as u32)
        );
    }

    #[test]
    fn chunked_stark_plan_begin_hash_chains_correctly() {
        let req = stark_req(2000, 4, 2); // > CHUNK_SIZE → multiple chunks
        let plan = build_chunked_stark_plan(&req).unwrap();
        // Independently recompute the rolling hash the program checks.
        let total_len = req.proof.len() as u32;
        let mut rolling = hashv(&[
            DOMAIN_TAG,
            &req.session_id,
            &total_len.to_le_bytes(),
            &[PSID_FRI_STARK],
        ])
        .to_bytes();
        for chunk in req.proof.chunks(CHUNK_SIZE) {
            rolling = hashv(&[&rolling, chunk]).to_bytes();
        }
        // begin payload: tag(1) ‖ expected_hash(32) ‖ ...
        assert_eq!(&plan.begin.data[1..33], &rolling);
    }

    #[test]
    fn chunked_stark_plan_chunks_large_proof() {
        // 2000 bytes / 800 CHUNK_SIZE → 3 chunks.
        let req = stark_req(2000, 4, 2);
        let plan = build_chunked_stark_plan(&req).unwrap();
        assert_eq!(plan.appends.len(), 3);
        // chunk indices are sequential.
        assert_eq!(&plan.appends[0].data[1..3], &0u16.to_le_bytes());
        assert_eq!(&plan.appends[1].data[1..3], &1u16.to_le_bytes());
        assert_eq!(&plan.appends[2].data[1..3], &2u16.to_le_bytes());
    }

    #[test]
    fn chunked_stark_plan_step_count_is_ceil() {
        // 4 queries, batch 2 → 2 steps.
        assert_eq!(build_chunked_stark_plan(&stark_req(100, 4, 2)).unwrap().steps.len(), 2);
        // 5 queries, batch 2 → 3 steps (ceil).
        assert_eq!(build_chunked_stark_plan(&stark_req(100, 5, 2)).unwrap().steps.len(), 3);
        // 1 query, batch 8 → 1 step.
        assert_eq!(build_chunked_stark_plan(&stark_req(100, 1, 8)).unwrap().steps.len(), 1);
        // each step carries the batch size as the trailing u16.
        let plan = build_chunked_stark_plan(&stark_req(100, 5, 2)).unwrap();
        let d = &plan.steps[0].data;
        assert_eq!(&d[d.len() - 2..], &2u16.to_le_bytes());
    }

    #[test]
    fn chunked_stark_plan_zero_queries_has_no_steps() {
        // A zero-query proof completes at `begin`; no steps emitted.
        let plan = build_chunked_stark_plan(&stark_req(100, 0, 4)).unwrap();
        assert!(plan.steps.is_empty());
    }

    #[test]
    fn chunked_stark_plan_transaction_groups_shape() {
        let req = stark_req(2000, 4, 2);
        let plan = build_chunked_stark_plan(&req).unwrap();
        let groups = plan.transaction_groups();
        // 1 upload group + 2 step groups.
        assert_eq!(groups.len(), 3);
        // first group: init + 3 appends + begin = 5 instructions.
        assert_eq!(groups[0].len(), 1 + plan.appends.len() + 1);
        assert_eq!(groups[0][0].data[0], 0x10);
        assert_eq!(groups[0].last().unwrap().data[0], 0x15);
        assert_eq!(groups[1].len(), 1);
        assert_eq!(groups[1][0].data[0], 0x16);
    }

    #[test]
    fn chunked_stark_plan_rejects_bad_inputs() {
        // zero batch
        let mut req = stark_req(100, 4, 0);
        assert!(build_chunked_stark_plan(&req).is_err());
        // proof too short
        req = stark_req(4, 4, 2);
        req.proof = vec![0u8; 4];
        assert!(build_chunked_stark_plan(&req).is_err());
    }

    fn sample_request() -> VerifyRequest {
        VerifyRequest::builder(Pubkey::new_unique(), ProofSystemId::Groth16Bn254)
            .with_vk(vec![0u8; 64])
            .with_proof(vec![0u8; 64])
            .with_public_inputs(vec![0u8; 32])
    }

    #[test]
    fn builder_populates_fields() {
        let pk = Pubkey::new_unique();
        let req = VerifyRequest::builder(pk, ProofSystemId::Groth16Bn254)
            .with_vk(vec![1u8; 10])
            .with_proof(vec![2u8; 20])
            .with_public_inputs(vec![3u8; 30])
            .with_accounts(vec![]);
        assert_eq!(req.program_id, pk);
        assert_eq!(req.proof_system, ProofSystemId::Groth16Bn254);
        assert_eq!(req.vk.len(), 10);
        assert_eq!(req.proof.len(), 20);
        assert_eq!(req.public_inputs.len(), 30);
        assert!(req.accounts.is_empty());
    }

    #[test]
    fn build_ix_produces_verifyproof_tag() {
        let req = sample_request();
        let ix = build_verify_proof_ix(&req).unwrap();
        assert_eq!(ix.program_id, req.program_id);
        assert_eq!(ix.data[0], 0x01, "instruction tag must be VerifyProof");
    }

    #[test]
    fn preflight_groth16_surfaces_verifier_error() {
        // Malformed proof bytes → verifier returns an error which
        // preflight() wraps in anyhow.
        let req = sample_request();
        let r = preflight(&req);
        assert!(r.is_err(), "zero-byte proof should fail groth16 preflight");
    }

    #[cfg(not(feature = "plonk"))]
    #[test]
    fn preflight_plonk_without_feature_names_feature() {
        let req = VerifyRequest::builder(Pubkey::new_unique(), ProofSystemId::PlonkKzgBn254);
        let r = preflight(&req);
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("'plonk' feature"), "error: {msg}");
    }

    #[cfg(not(feature = "halo2"))]
    #[test]
    fn preflight_halo2_without_feature_names_feature() {
        let req = VerifyRequest::builder(Pubkey::new_unique(), ProofSystemId::Halo2KzgBn254);
        let r = preflight(&req);
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("'halo2' feature"), "error: {msg}");
    }

    #[cfg(not(feature = "nova"))]
    #[test]
    fn preflight_nova_without_feature_names_feature() {
        for id in [ProofSystemId::NovaFolding, ProofSystemId::ProtoStarFolding] {
            let req = VerifyRequest::builder(Pubkey::new_unique(), id);
            let r = preflight(&req);
            let msg = r.unwrap_err().to_string();
            assert!(msg.contains("'nova' feature"), "error: {msg}");
        }
    }

    #[cfg(all(feature = "plonk", feature = "halo2", feature = "nova"))]
    #[test]
    fn preflight_multi_feature_dispatches_correctly() {
        // With features enabled, each Phase-3 system routes to its
        // verifier. Malformed bytes still fail — but crucially, they
        // fail with a verifier-side error (not a "feature missing"
        // error). Assert the error message naming differs.
        for (id, expected_prefix) in [
            (ProofSystemId::PlonkKzgBn254, "plonk preflight failed"),
            (ProofSystemId::Halo2KzgBn254, "halo2 preflight failed"),
            (ProofSystemId::NovaFolding, "nova preflight failed"),
            (ProofSystemId::ProtoStarFolding, "nova preflight failed"),
        ] {
            let req = VerifyRequest::builder(Pubkey::new_unique(), id);
            let r = preflight(&req);
            let msg = r.unwrap_err().to_string();
            assert!(
                msg.starts_with(expected_prefix),
                "expected {expected_prefix:?}, got {msg:?}"
            );
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 41 — proptest coverage for the SDK surface.
    //
    // The SDK is the contract surface every client uses to build a
    // VerifyProof transaction. Bugs here surface as on-chain
    // mismatches: a wrong instruction tag, a swap between proof and
    // public inputs in the borsh payload, or a builder setter that
    // overwrites the wrong field — any of these silently routes the
    // wrong bytes to the program and burns the transaction's CU
    // budget for no result.
    //
    // Proptest matrix:
    //
    //   1. Builder setter independence — `with_vk(x)` only mutates
    //      `vk`; `with_proof(x)` only mutates `proof`; etc. Pins
    //      against a copy-paste error that would alias two setters.
    //   2. Setter idempotence — calling `with_vk(x)` twice equals
    //      calling it once with the second value (pure-replace, not
    //      append).
    //   3. Instruction tag — every built ix starts with byte 0x01
    //      (VerifyProof tag), independent of payload content.
    //   4. Borsh round-trip — random `(proof_system_id, vk, proof,
    //      public_inputs)` quadruple → build_verify_proof_ix →
    //      strip the leading tag → borsh-deserialize → equal to the
    //      original payload.
    //   5. Program id pass-through — the random program_id supplied
    //      to the builder appears verbatim on the resulting ix.
    //   6. Account metas pass-through — the supplied metas land on
    //      the ix unchanged in count and order.
    //   7. ProofSystemId byte mapping — `as_byte()` round-trips
    //      through `from_byte()` for every defined variant.
    // ───────────────────────────────────────────────────────────────────
    use borsh::BorshDeserialize;
    use proptest::prelude::*;

    /// Mirror of the private `VerifyProofData` shape so the
    /// deserialization side of the round-trip property has a public
    /// type to land on. The wire format is the same — both structs
    /// borsh-(de)serialize to identical bytes.
    #[derive(Debug, PartialEq, Eq, ::borsh::BorshDeserialize)]
    struct VerifyProofDataWire {
        proof_system_id: u8,
        vk: Vec<u8>,
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
    }

    prop_compose! {
        /// Random `VerifyRequest` over the workspace's defined
        /// `ProofSystemId` variants, with payload sizes capped to
        /// keep test wall-clock manageable.
        fn arb_request()(
            ps_byte in 0u8..6, // covers all currently-defined variants
            vk in proptest::collection::vec(any::<u8>(), 0..=128),
            proof in proptest::collection::vec(any::<u8>(), 0..=256),
            public_inputs in proptest::collection::vec(any::<u8>(), 0..=64),
        ) -> VerifyRequest {
            let proof_system = match ps_byte {
                0 => ProofSystemId::Groth16Bn254,
                1 => ProofSystemId::PlonkKzgBn254,
                2 => ProofSystemId::HyperPlonkKzgBn254,
                3 => ProofSystemId::Halo2KzgBn254,
                4 => ProofSystemId::NovaFolding,
                _ => ProofSystemId::FriStark,
            };
            VerifyRequest::builder(Pubkey::new_unique(), proof_system)
                .with_vk(vk)
                .with_proof(proof)
                .with_public_inputs(public_inputs)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Each `with_*` setter mutates only the named field. Pins
        /// against a copy-paste error where, say, `with_vk` would
        /// also clobber `proof`.
        #[test]
        fn proptest_builder_setters_are_independent(
            vk in proptest::collection::vec(any::<u8>(), 0..=64),
            proof in proptest::collection::vec(any::<u8>(), 0..=64),
            pi in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let pk = Pubkey::new_unique();
            let req = VerifyRequest::builder(pk, ProofSystemId::Groth16Bn254)
                .with_vk(vk.clone())
                .with_proof(proof.clone())
                .with_public_inputs(pi.clone());
            prop_assert_eq!(req.vk, vk);
            prop_assert_eq!(req.proof, proof);
            prop_assert_eq!(req.public_inputs, pi);
            prop_assert_eq!(req.program_id, pk);
            prop_assert!(req.accounts.is_empty());
        }

        /// Setter idempotence: calling `with_vk(x)` twice equals
        /// calling it once with `x`. Setters are pure replacements,
        /// not accumulators.
        #[test]
        fn proptest_builder_setters_pure_replace(
            v1 in proptest::collection::vec(any::<u8>(), 0..=64),
            v2 in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let pk = Pubkey::new_unique();
            let req = VerifyRequest::builder(pk, ProofSystemId::Groth16Bn254)
                .with_vk(v1)
                .with_vk(v2.clone());
            prop_assert_eq!(req.vk, v2);
        }

        /// Every instruction starts with byte 0x01 (VerifyProof tag),
        /// regardless of payload content. Pins against a future
        /// change that would tag-shift instructions silently.
        #[test]
        fn proptest_instruction_starts_with_verify_proof_tag(req in arb_request()) {
            let ix = build_verify_proof_ix(&req).unwrap();
            prop_assert!(!ix.data.is_empty());
            prop_assert_eq!(ix.data[0], 0x01);
        }

        /// Borsh round-trip: build_verify_proof_ix's payload (after
        /// stripping the leading instruction tag) decodes back to a
        /// struct with the same `proof_system_id`, `vk`, `proof`, and
        /// `public_inputs`. Pins the wire format against
        /// reorderings of the four fields, which would silently
        /// route the public inputs into the proof slot (or vice
        /// versa) on chain.
        #[test]
        fn proptest_borsh_payload_round_trip(req in arb_request()) {
            let ix = build_verify_proof_ix(&req).unwrap();
            let payload = &ix.data[1..]; // skip the VerifyProof tag
            let decoded = VerifyProofDataWire::try_from_slice(payload)
                .expect("borsh decode round-trip");
            prop_assert_eq!(decoded.proof_system_id, req.proof_system.as_byte());
            prop_assert_eq!(decoded.vk, req.vk);
            prop_assert_eq!(decoded.proof, req.proof);
            prop_assert_eq!(decoded.public_inputs, req.public_inputs);
        }

        /// Program id passes through verbatim from the builder to
        /// the resulting instruction.
        #[test]
        fn proptest_program_id_passes_through(req in arb_request()) {
            let ix = build_verify_proof_ix(&req).unwrap();
            prop_assert_eq!(ix.program_id, req.program_id);
        }

        /// Account metas pass through verbatim. Generates a small
        /// random account list with mixed signer/writable bits.
        #[test]
        fn proptest_account_metas_pass_through(
            n_accounts in 0usize..=4,
        ) {
            let pk = Pubkey::new_unique();
            let metas: Vec<AccountMeta> = (0..n_accounts)
                .map(|i| {
                    let signer = (i & 1) == 0;
                    let writable = (i & 2) == 0;
                    if writable {
                        AccountMeta::new(Pubkey::new_unique(), signer)
                    } else {
                        AccountMeta::new_readonly(Pubkey::new_unique(), signer)
                    }
                })
                .collect();
            let req = VerifyRequest::builder(pk, ProofSystemId::Groth16Bn254)
                .with_accounts(metas.clone());
            let ix = build_verify_proof_ix(&req).unwrap();
            prop_assert_eq!(ix.accounts.len(), metas.len());
            for (a, b) in ix.accounts.iter().zip(metas.iter()) {
                prop_assert_eq!(a.pubkey, b.pubkey);
                prop_assert_eq!(a.is_signer, b.is_signer);
                prop_assert_eq!(a.is_writable, b.is_writable);
            }
        }

        /// `ProofSystemId::as_byte()` round-trips through
        /// `ProofSystemId::from_byte()` for every variant currently
        /// known to the SDK. Catches a regression where adding a
        /// new variant skips registering it in the byte map.
        #[test]
        fn proptest_proof_system_id_byte_round_trip(ps_byte in 0u8..6) {
            let ps = match ps_byte {
                0 => ProofSystemId::Groth16Bn254,
                1 => ProofSystemId::PlonkKzgBn254,
                2 => ProofSystemId::HyperPlonkKzgBn254,
                3 => ProofSystemId::Halo2KzgBn254,
                4 => ProofSystemId::NovaFolding,
                _ => ProofSystemId::FriStark,
            };
            let byte = ps.as_byte();
            let parsed = ProofSystemId::from_byte(byte)
                .expect("known variant byte parses");
            prop_assert_eq!(parsed, ps);
        }
    }
}
