//! Integration tests for the chunked-upload instruction handlers.
//!
//! Spins up `solana-program-test` with `mosaic-program` loaded as a builtin,
//! then exercises the full state machine and security gates documented in
//! `docs/design/0001-chunked-upload-handlers.md`.
//!
//! Test matrix:
//!
//! | Test                                | Asserts                                              |
//! |---|---|
//! | `init_then_cancel`                  | Happy path init + cancel; rent refunded.             |
//! | `append_chunk_advances_state`       | Two chunks, state machine reaches Open w/ length.    |
//! | `wrong_payer_rejected`              | Bob can't append to Alice's session.                 |
//! | `out_of_order_chunk_rejected`       | `chunk_index` mismatch returns `ChunkOutOfOrder`.    |
//! | `commit_with_wrong_hash_rejected`   | Hash mismatch returns `ChunkCommitmentMismatch`.     |
//! | `cancel_expired_before_expiry`      | Permissionless GC rejected pre-expiry.               |
//! | `double_init_rejected`              | Re-init on same PDA returns `SessionAlreadyInit`.    |

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use borsh::BorshDeserialize;
use mosaic_chunked::{ProofUploadSession, DOMAIN_TAG, SESSION_SEED_PREFIX};
use mosaic_program::PROGRAM_ID;
use solana_program_test::{processor, BanksClient, ProgramTest};
use solana_sdk::{
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

const PROOF_SYSTEM_GROTH16: u8 = 0x01;

/// Spin up the test environment.
async fn setup() -> (BanksClient, Keypair, solana_sdk::hash::Hash) {
    let pt = ProgramTest::new(
        "mosaic_program",
        PROGRAM_ID,
        processor!(mosaic_program::process_instruction),
    );
    pt.start().await
}

/// Compute the canonical `h_0` seed.
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

fn build_initialize_session_ix(
    payer: &Pubkey,
    session_pda: &Pubkey,
    session_id: &[u8; 32],
    total_len: u32,
    proof_system_id: u8,
    h_0: &[u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 32 + 4 + 1 + 32);
    data.push(0x10); // InitializeSession tag
    data.extend_from_slice(session_id);
    data.extend_from_slice(&total_len.to_le_bytes());
    data.push(proof_system_id);
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

fn build_append_chunk_ix(
    payer: &Pubkey,
    session_pda: &Pubkey,
    chunk_index: u16,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + 2 + 2 + chunk.len());
    data.push(0x11); // AppendChunk tag
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

fn build_cancel_session_ix(payer: &Pubkey, session_pda: &Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*session_pda, false),
        ],
        data: vec![0x13],
    }
}

fn build_cancel_expired_ix(
    caller: &Pubkey,
    session_pda: &Pubkey,
    payer_account: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*caller, true),
            AccountMeta::new(*session_pda, false),
            AccountMeta::new(*payer_account, false),
        ],
        data: vec![0x14],
    }
}

fn build_commit_and_verify_ix(
    payer: &Pubkey,
    session_pda: &Pubkey,
    vk_account: &Pubkey,
    expected_final_hash: &[u8; 32],
    public_inputs: &[u8],
) -> Instruction {
    // accounts: [payer, session_pda, vk_account] → vk_account_offset = 2
    let vk_offset: u32 = 2;
    let pi_len = u16::try_from(public_inputs.len()).unwrap();
    let mut data = Vec::with_capacity(1 + 32 + 4 + 2 + public_inputs.len());
    data.push(0x12); // CommitAndVerify tag
    data.extend_from_slice(expected_final_hash);
    data.extend_from_slice(&vk_offset.to_le_bytes());
    data.extend_from_slice(&pi_len.to_le_bytes());
    data.extend_from_slice(public_inputs);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*session_pda, false),
            AccountMeta::new_readonly(*vk_account, false),
        ],
        data,
    }
}

#[tokio::test]
async fn init_then_cancel_refunds_rent() {
    let (mut banks, payer, recent_blockhash) = setup().await;
    let session_id = [11_u8; 32];
    let total_len = 1024_u32;
    let h_0 = compute_h0(&session_id, total_len, PROOF_SYSTEM_GROTH16);
    let (session_pda, _bump) = derive_session_pda(&session_id, &payer.pubkey());

    let payer_initial_lamports = banks
        .get_account(payer.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;

    let init_ix = build_initialize_session_ix(
        &payer.pubkey(),
        &session_pda,
        &session_id,
        total_len,
        PROOF_SYSTEM_GROTH16,
        &h_0,
    );
    let cancel_ix = build_cancel_session_ix(&payer.pubkey(), &session_pda);

    let tx = Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks.process_transaction(tx).await.unwrap();

    // Account exists with the expected layout.
    let account = banks.get_account(session_pda).await.unwrap().unwrap();
    assert_eq!(account.owner, PROGRAM_ID);
    let session = ProofUploadSession::deserialize(&mut &account.data[..]).unwrap();
    assert_eq!(session.layout_version, ProofUploadSession::LAYOUT_VERSION);
    assert_eq!(session.total_len, total_len);
    assert_eq!(session.appended_len, 0);
    assert_eq!(session.proof_system_id, PROOF_SYSTEM_GROTH16);
    assert!(!session.finalized);

    // Payer paid rent; we'll check that cancel refunds it.
    let recent_blockhash = banks.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[cancel_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    banks.process_transaction(tx).await.unwrap();

    // Session PDA closed (account doesn't exist).
    assert!(banks.get_account(session_pda).await.unwrap().is_none());

    // Net loss is just two transaction fees (5_000 each by default), not rent.
    let payer_final_lamports = banks
        .get_account(payer.pubkey())
        .await
        .unwrap()
        .unwrap()
        .lamports;
    let net_cost = payer_initial_lamports - payer_final_lamports;
    assert!(
        net_cost < 50_000,
        "rent should be refunded; net cost {net_cost} too high",
    );
}

#[tokio::test]
async fn append_chunk_advances_state() {
    let (mut banks, payer, blockhash) = setup().await;
    let session_id = [22_u8; 32];
    let total_len = 4_u32;
    let h_0 = compute_h0(&session_id, total_len, PROOF_SYSTEM_GROTH16);
    let (session_pda, _bump) = derive_session_pda(&session_id, &payer.pubkey());

    let init_ix = build_initialize_session_ix(
        &payer.pubkey(),
        &session_pda,
        &session_id,
        total_len,
        PROOF_SYSTEM_GROTH16,
        &h_0,
    );
    let chunk1 = [1u8, 2];
    let append1_ix = build_append_chunk_ix(&payer.pubkey(), &session_pda, 0, &chunk1);
    let chunk2 = [3u8, 4];
    let append2_ix = build_append_chunk_ix(&payer.pubkey(), &session_pda, 1, &chunk2);

    let tx = Transaction::new_signed_with_payer(
        &[init_ix, append1_ix, append2_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    banks.process_transaction(tx).await.unwrap();

    let account = banks.get_account(session_pda).await.unwrap().unwrap();
    let session = ProofUploadSession::deserialize(&mut &account.data[..]).unwrap();
    assert_eq!(session.appended_len, 4);
    assert_eq!(session.chunks_committed, 2);
    assert_eq!(&session.assembled, &[1, 2, 3, 4]);

    let h_1 = compute_next_hash(&h_0, &chunk1);
    let h_2 = compute_next_hash(&h_1, &chunk2);
    assert_eq!(session.rolling_hash, h_2);
}

#[tokio::test]
async fn wrong_payer_rejected() {
    let (mut banks, alice, blockhash) = setup().await;
    let bob = Keypair::new();

    let session_id = [33_u8; 32];
    let total_len = 4_u32;
    let h_0 = compute_h0(&session_id, total_len, PROOF_SYSTEM_GROTH16);
    let (session_pda, _bump) = derive_session_pda(&session_id, &alice.pubkey());

    // Fund Bob so he can sign tx (but not pay rent for someone else's account).
    let fund_bob_ix =
        solana_sdk::system_instruction::transfer(&alice.pubkey(), &bob.pubkey(), 10_000_000);
    let init_ix = build_initialize_session_ix(
        &alice.pubkey(),
        &session_pda,
        &session_id,
        total_len,
        PROOF_SYSTEM_GROTH16,
        &h_0,
    );
    let tx = Transaction::new_signed_with_payer(
        &[fund_bob_ix, init_ix],
        Some(&alice.pubkey()),
        &[&alice],
        blockhash,
    );
    banks.process_transaction(tx).await.unwrap();

    // Bob tries to append to Alice's session.
    let blockhash2 = banks.get_latest_blockhash().await.unwrap();
    let bad_ix = build_append_chunk_ix(&bob.pubkey(), &session_pda, 0, &[7, 7]);
    let tx =
        Transaction::new_signed_with_payer(&[bad_ix], Some(&bob.pubkey()), &[&bob], blockhash2);
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains("Custom(52)") || s.contains("0x34"),
        "expected SessionContextMismatch (0x34), got: {s}",
    );
}

#[tokio::test]
async fn out_of_order_chunk_rejected() {
    let (mut banks, payer, blockhash) = setup().await;
    let session_id = [44_u8; 32];
    let total_len = 4_u32;
    let h_0 = compute_h0(&session_id, total_len, PROOF_SYSTEM_GROTH16);
    let (session_pda, _bump) = derive_session_pda(&session_id, &payer.pubkey());

    let init_ix = build_initialize_session_ix(
        &payer.pubkey(),
        &session_pda,
        &session_id,
        total_len,
        PROOF_SYSTEM_GROTH16,
        &h_0,
    );
    // Skip index 0; supply index 2.
    let bad_ix = build_append_chunk_ix(&payer.pubkey(), &session_pda, 2, &[1, 2]);
    let tx = Transaction::new_signed_with_payer(
        &[init_ix, bad_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains("Custom(48)") || s.contains("0x30"),
        "expected ChunkOutOfOrder (0x30), got: {s}",
    );
}

#[tokio::test]
async fn commit_with_wrong_hash_rejected() {
    let (mut banks, payer, blockhash) = setup().await;
    let session_id = [55_u8; 32];
    let total_len = 2_u32;
    let h_0 = compute_h0(&session_id, total_len, PROOF_SYSTEM_GROTH16);
    let (session_pda, _bump) = derive_session_pda(&session_id, &payer.pubkey());

    // Create a sham VK account (won't be reached because hash check fails first).
    let vk_keypair = Keypair::new();
    let vk_lamports = 1_000_000;
    let create_vk = solana_sdk::system_instruction::create_account(
        &payer.pubkey(),
        &vk_keypair.pubkey(),
        vk_lamports,
        16,
        &system_program::ID,
    );

    let init_ix = build_initialize_session_ix(
        &payer.pubkey(),
        &session_pda,
        &session_id,
        total_len,
        PROOF_SYSTEM_GROTH16,
        &h_0,
    );
    let chunk = [9u8, 9];
    let append_ix = build_append_chunk_ix(&payer.pubkey(), &session_pda, 0, &chunk);
    let wrong_hash = [0xFF; 32];
    let bad_commit = build_commit_and_verify_ix(
        &payer.pubkey(),
        &session_pda,
        &vk_keypair.pubkey(),
        &wrong_hash,
        &[],
    );

    let tx = Transaction::new_signed_with_payer(
        &[create_vk, init_ix, append_ix, bad_commit],
        Some(&payer.pubkey()),
        &[&payer, &vk_keypair],
        blockhash,
    );
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains("Custom(49)") || s.contains("0x31"),
        "expected ChunkCommitmentMismatch (0x31), got: {s}",
    );
}

#[tokio::test]
async fn cancel_expired_before_expiry_rejected() {
    let (mut banks, payer, blockhash) = setup().await;
    let session_id = [66_u8; 32];
    let total_len = 4_u32;
    let h_0 = compute_h0(&session_id, total_len, PROOF_SYSTEM_GROTH16);
    let (session_pda, _bump) = derive_session_pda(&session_id, &payer.pubkey());

    let init_ix = build_initialize_session_ix(
        &payer.pubkey(),
        &session_pda,
        &session_id,
        total_len,
        PROOF_SYSTEM_GROTH16,
        &h_0,
    );
    // Try permissionless GC immediately (caller is also payer here, just for simplicity).
    let bad_gc = build_cancel_expired_ix(&payer.pubkey(), &session_pda, &payer.pubkey());

    let tx = Transaction::new_signed_with_payer(
        &[init_ix, bad_gc],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains("Custom(54)") || s.contains("0x36"),
        "expected SessionNotExpired (0x36), got: {s}",
    );
}

#[tokio::test]
async fn double_init_rejected() {
    let (mut banks, payer, blockhash) = setup().await;
    let session_id = [77_u8; 32];
    let total_len = 4_u32;
    let h_0 = compute_h0(&session_id, total_len, PROOF_SYSTEM_GROTH16);
    let (session_pda, _bump) = derive_session_pda(&session_id, &payer.pubkey());

    let init_ix = build_initialize_session_ix(
        &payer.pubkey(),
        &session_pda,
        &session_id,
        total_len,
        PROOF_SYSTEM_GROTH16,
        &h_0,
    );
    let init_ix_again = init_ix.clone();

    let tx = Transaction::new_signed_with_payer(
        &[init_ix, init_ix_again],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    // Either our SessionAlreadyInitialized or the system_program's
    // "account already in use" rejection is acceptable — both indicate the
    // double-init is rejected. We accept both.
    assert!(
        s.contains("Custom(53)")
            || s.contains("0x35")
            || s.contains("AccountAlreadyInUse")
            || s.contains("InvalidAccountData"),
        "expected double-init rejection, got: {s}",
    );
}
