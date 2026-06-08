//! End-to-end SBF integration test for chunked STARK verification (#76).
//!
//! Drives the full multi-transaction flow against the real
//! `solana-program-test` VM: upload a valid depth-zero 4-query FRI-STARK
//! proof via the chunked-upload instructions, then verify it across
//! separate transactions using `BeginStarkVerify` (0x15) +
//! `StarkVerifyStep` (0x16). Success closes the session PDA (rent
//! refunded), which is the on-chain signal that every query verified.
//!
//! This proves the resumable verifier (`FriStark::verify_setup` /
//! `verify_query_range`) and the session checkpoint cursor compose
//! correctly across transaction boundaries, which is the whole point of
//! chunked execution: a production STARK exceeds the 1.4M CU per-tx cap.
//!
//! Self-skips when the SBF artifact is missing, like `verify_proof_sbf`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use borsh::BorshDeserialize;
use mosaic_chunked::{ProofUploadSession, CHUNK_SIZE, DOMAIN_TAG, SESSION_SEED_PREFIX};
use mosaic_program::PROGRAM_ID;
use solana_program_test::{processor, BanksClient, ProgramTest};
use solana_sdk::{
    account::Account,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};
use std::path::PathBuf;

const PSID_FRI_STARK: u8 = 0x05;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn sbf_ready() -> bool {
    if std::env::var_os("BPF_OUT_DIR").is_none() && std::env::var_os("SBF_OUT_DIR").is_none() {
        eprintln!("skipping chunked_stark: BPF_OUT_DIR / SBF_OUT_DIR not set");
        return false;
    }
    let so = workspace_root().join("target/deploy/mosaic_program.so");
    if !so.exists() {
        eprintln!("skipping chunked_stark: {so:?} not built; run cargo build-sbf");
        return false;
    }
    true
}

/// Spin up the VM with a pre-seeded account holding the VK bytes.
async fn setup_with_vk(vk_bytes: &[u8]) -> (BanksClient, Keypair, Pubkey, solana_sdk::hash::Hash) {
    let mut pt = ProgramTest::new(
        "mosaic_program",
        PROGRAM_ID,
        processor!(mosaic_program::process_instruction),
    );
    let vk_pubkey = Pubkey::new_unique();
    pt.add_account(
        vk_pubkey,
        Account {
            lamports: 1_000_000_000,
            data: vk_bytes.to_vec(),
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let (banks, payer, blockhash) = pt.start().await;
    (banks, payer, vk_pubkey, blockhash)
}

fn compute_h0(session_id: &[u8; 32], total_len: u32, proof_system_id: u8) -> [u8; 32] {
    hashv(&[
        DOMAIN_TAG,
        session_id,
        &total_len.to_le_bytes(),
        &[proof_system_id],
    ])
    .to_bytes()
}

fn compute_next_hash(prev: &[u8; 32], chunk: &[u8]) -> [u8; 32] {
    hashv(&[prev, chunk]).to_bytes()
}

fn derive_session_pda(session_id: &[u8; 32], payer: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SESSION_SEED_PREFIX, session_id, payer.as_ref()],
        &PROGRAM_ID,
    )
}

fn init_ix(
    payer: &Pubkey,
    session_pda: &Pubkey,
    session_id: &[u8; 32],
    total_len: u32,
    h_0: &[u8; 32],
) -> Instruction {
    let mut data = Vec::new();
    data.push(0x10);
    data.extend_from_slice(session_id);
    data.extend_from_slice(&total_len.to_le_bytes());
    data.push(PSID_FRI_STARK);
    data.extend_from_slice(h_0);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*session_pda, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

fn append_ix(payer: &Pubkey, session_pda: &Pubkey, chunk_index: u16, chunk: &[u8]) -> Instruction {
    let mut data = Vec::new();
    data.push(0x11);
    data.extend_from_slice(&chunk_index.to_le_bytes());
    data.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_le_bytes());
    data.extend_from_slice(chunk);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*session_pda, false),
        ],
        data,
    }
}

fn begin_ix(
    payer: &Pubkey,
    session_pda: &Pubkey,
    vk: &Pubkey,
    expected_hash: &[u8; 32],
) -> Instruction {
    let mut data = Vec::new();
    data.push(0x15);
    data.extend_from_slice(expected_hash);
    data.extend_from_slice(&2u32.to_le_bytes()); // vk_offset = account index 2
    data.extend_from_slice(&0u16.to_le_bytes()); // pi_len = 0
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*session_pda, false),
            AccountMeta::new_readonly(*vk, false),
        ],
        data,
    }
}

fn step_ix(payer: &Pubkey, session_pda: &Pubkey, vk: &Pubkey, batch: u16) -> Instruction {
    let mut data = Vec::new();
    data.push(0x16);
    data.extend_from_slice(&2u32.to_le_bytes()); // vk_offset
    data.extend_from_slice(&0u16.to_le_bytes()); // pi_len = 0
    data.extend_from_slice(&batch.to_le_bytes());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*session_pda, false),
            AccountMeta::new_readonly(*vk, false),
        ],
        data,
    }
}

/// Valid depth-zero 4-query Goldilocks STARK proof + VK + (empty) public
/// inputs. Mirrors `verify_proof_sbf::fri_stark_scaffold`: at depth 0 the
/// Merkle path is empty so each query's leaf equals the commitment when
/// both are filled with the same byte.
fn stark_scaffold() -> (Vec<u8>, Vec<u8>) {
    use mosaic_stark::canonical::{
        sizes::{DIGEST_LEN, FIXED_HEADER_LEN, POW_NONCE_LEN},
        FriStarkVerifyingKey, StarkFieldId, FRI_LAYER_OPENING_LEN,
    };

    let field_id = StarkFieldId::Goldilocks;
    let log_blowup: u8 = 0;
    let num_fri_layers: u8 = 0;
    let num_queries: u16 = 4;
    let trace_log_height: u16 = 0;
    let trace_width: u32 = 32;
    let leaf_fill: u8 = 0xAB;

    let vk = FriStarkVerifyingKey {
        field_id,
        trace_width,
        trace_log_height,
        log_blowup,
        air_hash: [0u8; 32],
        omega_g: [0u8; 8],
    }
    .to_bytes();

    let ood_bytes = 10 * field_id.field_elem_bytes();
    let final_bytes = 4 * field_id.field_elem_bytes();
    let depth = (trace_log_height as usize) + (log_blowup as usize);
    let per_query = 2 * (DIGEST_LEN + depth * DIGEST_LEN);
    let query_bytes = (num_queries as usize) * per_query;
    let fri_openings_bytes =
        (num_queries as usize) * (num_fri_layers as usize) * FRI_LAYER_OPENING_LEN;
    let auth_paths_bytes = (num_queries as usize) * (num_fri_layers as usize) * 2 * depth * DIGEST_LEN;

    let total = FIXED_HEADER_LEN
        + 2 * DIGEST_LEN
        + (num_fri_layers as usize) * DIGEST_LEN
        + 4
        + ood_bytes
        + 4
        + final_bytes
        + 4
        + query_bytes
        + 4
        + fri_openings_bytes
        + 4
        + auth_paths_bytes
        + POW_NONCE_LEN;

    let mut proof = vec![0u8; total];
    proof[0] = field_id as u8;
    proof[1] = log_blowup;
    proof[2] = num_fri_layers;
    proof[3] = 0;
    proof[4..6].copy_from_slice(&num_queries.to_le_bytes());
    proof[6..8].copy_from_slice(&trace_log_height.to_le_bytes());
    proof[8..12].copy_from_slice(&trace_width.to_le_bytes());

    let trace_off = FIXED_HEADER_LEN;
    let constraint_off = trace_off + DIGEST_LEN;
    for byte in proof[trace_off..trace_off + DIGEST_LEN].iter_mut() {
        *byte = leaf_fill;
    }
    for byte in proof[constraint_off..constraint_off + DIGEST_LEN].iter_mut() {
        *byte = leaf_fill;
    }

    let mut off = FIXED_HEADER_LEN + 2 * DIGEST_LEN + (num_fri_layers as usize) * DIGEST_LEN;
    proof[off..off + 4].copy_from_slice(&(ood_bytes as u32).to_le_bytes());
    off += 4 + ood_bytes;
    proof[off..off + 4].copy_from_slice(&(final_bytes as u32).to_le_bytes());
    off += 4 + final_bytes;
    proof[off..off + 4].copy_from_slice(&(query_bytes as u32).to_le_bytes());
    off += 4;
    for byte in proof[off..off + query_bytes].iter_mut() {
        *byte = leaf_fill;
    }
    off += query_bytes;
    proof[off..off + 4].copy_from_slice(&(fri_openings_bytes as u32).to_le_bytes());
    off += 4 + fri_openings_bytes;
    proof[off..off + 4].copy_from_slice(&(auth_paths_bytes as u32).to_le_bytes());

    (vk, proof)
}

/// Append the proof in CHUNK_SIZE pieces, returning the final rolling
/// hash that `BeginStarkVerify` checks against.
fn append_all(
    payer: &Pubkey,
    session_pda: &Pubkey,
    proof: &[u8],
    h_0: &[u8; 32],
) -> (Vec<Instruction>, [u8; 32]) {
    let mut ixs = Vec::new();
    let mut rolling = *h_0;
    for (i, chunk) in proof.chunks(CHUNK_SIZE).enumerate() {
        ixs.push(append_ix(payer, session_pda, i as u16, chunk));
        rolling = compute_next_hash(&rolling, chunk);
    }
    (ixs, rolling)
}

#[tokio::test]
async fn chunked_stark_verifies_across_transactions() {
    if !sbf_ready() {
        return;
    }
    let (vk, proof) = stark_scaffold();
    let (banks, payer, vk_pubkey, blockhash) = setup_with_vk(&vk).await;

    let session_id = [0x5A_u8; 32];
    let total_len = proof.len() as u32;
    let h_0 = compute_h0(&session_id, total_len, PSID_FRI_STARK);
    let (session_pda, _bump) = derive_session_pda(&session_id, &payer.pubkey());

    // Transaction 1: initialize + upload + begin (setup + record num_queries).
    let init = init_ix(&payer.pubkey(), &session_pda, &session_id, total_len, &h_0);
    let (appends, final_hash) = append_all(&payer.pubkey(), &session_pda, &proof, &h_0);
    let begin = begin_ix(&payer.pubkey(), &session_pda, &vk_pubkey, &final_hash);

    let mut ixs = vec![init];
    ixs.extend(appends);
    ixs.push(begin);
    let tx1 = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[&payer], blockhash);
    banks.process_transaction(tx1).await.expect("tx1 init+upload+begin");

    // The session persists with the verification cursor at 0/4.
    let acct = banks.get_account(session_pda).await.unwrap().unwrap();
    let session = ProofUploadSession::try_from_slice(&acct.data).unwrap();
    assert!(session.finalized);
    assert!(session.stark_verify.setup_done);
    assert_eq!(session.stark_verify.num_queries, 4);
    assert_eq!(session.stark_verify.next_query, 0);
    assert!(!session.stark_verify_complete());

    // Transaction 2: verify queries 0..2 (batch 2). Distinct batch
    // values across tx2/tx3 keep the instruction data -- and therefore
    // the signatures -- distinct so a single recent blockhash suffices.
    let tx2 = Transaction::new_signed_with_payer(
        &[step_ix(&payer.pubkey(), &session_pda, &vk_pubkey, 2)],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    banks.process_transaction(tx2).await.expect("tx2 step 0..2");

    let acct = banks.get_account(session_pda).await.unwrap().unwrap();
    let session = ProofUploadSession::try_from_slice(&acct.data).unwrap();
    assert_eq!(session.stark_verify.next_query, 2);
    assert!(!session.stark_verify_complete());

    // Transaction 3: verify the remaining queries (batch 5 clamps to 4)
    // → complete → session closed.
    let tx3 = Transaction::new_signed_with_payer(
        &[step_ix(&payer.pubkey(), &session_pda, &vk_pubkey, 5)],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    banks.process_transaction(tx3).await.expect("tx3 step 2..4");

    // Completion closes the session PDA (rent refunded).
    assert!(
        banks.get_account(session_pda).await.unwrap().is_none(),
        "session should be closed once every query verified",
    );
}

#[tokio::test]
async fn stark_step_before_begin_is_rejected() {
    if !sbf_ready() {
        return;
    }
    let (vk, proof) = stark_scaffold();
    let (banks, payer, vk_pubkey, blockhash) = setup_with_vk(&vk).await;

    let session_id = [0x33_u8; 32];
    let total_len = proof.len() as u32;
    let h_0 = compute_h0(&session_id, total_len, PSID_FRI_STARK);
    let (session_pda, _bump) = derive_session_pda(&session_id, &payer.pubkey());

    let init = init_ix(&payer.pubkey(), &session_pda, &session_id, total_len, &h_0);
    let (appends, _final_hash) = append_all(&payer.pubkey(), &session_pda, &proof, &h_0);
    let step = step_ix(&payer.pubkey(), &session_pda, &vk_pubkey, 4);

    let mut ixs = vec![init];
    ixs.extend(appends);
    ixs.push(step);
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[&payer], blockhash);
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    // OnChainError::StarkVerifyNotStarted = 0x0038 = Custom(56).
    assert!(
        s.contains("Custom(56)") || s.contains("0x38"),
        "step before begin should be StarkVerifyNotStarted, got: {s}",
    );
}
