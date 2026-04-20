//! Integration test: load the real SBF ELF + verify a real Groth16 proof.
//!
//! This test differs from `chunked_handlers.rs` (which uses
//! `processor!(process_instruction)` to load native code). Here we load
//! the actual `target/deploy/mosaic_program.so` bytecode, matching how
//! the program will execute on devnet / mainnet.
//!
//! Run with:
//!
//! ```text
//! cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml
//! BPF_OUT_DIR=target/deploy cargo test -p mosaic-program --test verify_proof_sbf
//! ```
//!
//! CI wires both env vars in `.github/workflows/ci.yml`. Skipped
//! gracefully with a log line if the SBF artifact is missing — this
//! keeps `cargo test --workspace` green even when nobody has run
//! `cargo build-sbf` yet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use borsh::BorshSerialize;
use solana_program_test::{BanksClient, ProgramTest};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};
use std::{fs, path::PathBuf};

const PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("MosA1cVer1f1er11111111111111111111111111111");

#[derive(BorshSerialize)]
struct VerifyProofData {
    proof_system_id: u8,
    vk: Vec<u8>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fixture(name: &str) -> Vec<u8> {
    let p = workspace_root()
        .join("tests/fixtures/groth16/mul-circuit/canonical")
        .join(name);
    fs::read(&p).unwrap_or_else(|_| panic!("missing fixture {p:?}"))
}

fn sbf_ready() -> bool {
    if std::env::var_os("BPF_OUT_DIR").is_none() && std::env::var_os("SBF_OUT_DIR").is_none() {
        eprintln!("skipping: BPF_OUT_DIR / SBF_OUT_DIR not set");
        return false;
    }
    let so = workspace_root().join("target/deploy/mosaic_program.so");
    if !so.exists() {
        eprintln!("skipping: {so:?} not built; run cargo build-sbf first");
        return false;
    }
    true
}

async fn setup() -> (BanksClient, Keypair, solana_sdk::hash::Hash) {
    let mut pt = ProgramTest::default();
    pt.add_program("mosaic_program", PROGRAM_ID, None); // None → load .so
    pt.start().await
}

fn build_verify_ix(vk: &[u8], proof: &[u8], public_inputs: &[u8]) -> Instruction {
    let payload = VerifyProofData {
        proof_system_id: 0x01, // Groth16Bn254
        vk: vk.to_vec(),
        proof: proof.to_vec(),
        public_inputs: public_inputs.to_vec(),
    };
    let mut data = Vec::with_capacity(1 + 1 + vk.len() + proof.len() + public_inputs.len() + 16);
    data.push(0x01); // InstructionTag::VerifyProof
    borsh::to_writer(&mut data, &payload).unwrap();
    Instruction { program_id: PROGRAM_ID, accounts: Vec::<AccountMeta>::new(), data }
}

fn extract_cu(logs: &[String]) -> Option<u64> {
    let needle = format!("Program {PROGRAM_ID} consumed ");
    logs.iter()
        .filter_map(|l| l.strip_prefix(&needle))
        .filter_map(|r| r.split_whitespace().next())
        .filter_map(|n| n.parse::<u64>().ok())
        .next()
}

/// End-to-end: load `mosaic_program.so`, submit VerifyProof with the
/// mul-circuit fixture, assert success + CU within tolerance of the
/// baseline pinned in `mosaic-bench::bpf_bench`.
#[tokio::test]
async fn sbf_verify_proof_succeeds_on_valid_groth16() {
    if !sbf_ready() {
        return;
    }

    let (banks, payer, blockhash) = setup().await;
    let mut banks = banks;

    let vk = fixture("vk.bin");
    let proof = fixture("proof.bin");
    let pi = fixture("public_inputs.bin");

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(300_000);
    let verify_ix = build_verify_ix(&vk, &proof, &pi);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    let meta = banks.process_transaction_with_metadata(tx).await.unwrap();
    assert!(
        meta.result.is_ok(),
        "valid Groth16 proof must verify on-chain: {:?}\nlogs:\n{}",
        meta.result,
        meta.metadata
            .as_ref()
            .map(|m| m.log_messages.join("\n"))
            .unwrap_or_default(),
    );

    let logs = meta.metadata.expect("metadata").log_messages;
    let cu = extract_cu(&logs).expect("CU line in logs");

    // Baseline pinned in mosaic-bench::bpf_bench::TARGETS[0] at 80_296.
    // Allow ±10% tolerance here (bench uses 5%) to avoid flaky failures
    // across Solana runtime patch versions. Regressions beyond this are
    // still caught by bpf-bench in CI.
    const BASELINE: u64 = 80_296;
    let upper = BASELINE + BASELINE / 10;
    let lower = BASELINE - BASELINE / 10;
    assert!(
        (lower..=upper).contains(&cu),
        "CU drift beyond ±10%: measured {cu}, baseline {BASELINE}; investigate",
    );

    // Program log dispatch line should appear.
    assert!(
        logs.iter().any(|l| l.contains("mosaic: dispatch groth16_bn254")),
        "expected dispatch log line, got:\n{}",
        logs.join("\n"),
    );
}

/// Tampered proof: flip one bit in proof.a.x, expect a `PairingCheckFailed`
/// (0x20) or `AltBn128SyscallFailed` (0x40) program error — both are valid
/// rejections depending on whether the syscall deems the point off-curve.
#[tokio::test]
async fn sbf_rejects_tampered_proof() {
    if !sbf_ready() {
        return;
    }

    let (banks, payer, blockhash) = setup().await;
    let mut banks = banks;

    let vk = fixture("vk.bin");
    let mut proof = fixture("proof.bin");
    proof[0] ^= 0x01; // flip low bit of proof.a.x byte 0
    let pi = fixture("public_inputs.bin");

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(300_000);
    let verify_ix = build_verify_ix(&vk, &proof, &pi);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains("Custom(32)") || s.contains("0x20")
            || s.contains("Custom(64)") || s.contains("0x40")
            || s.contains("Custom(6)")  || s.contains("0x6"),
        "expected PairingCheckFailed / AltBn128SyscallFailed / PointNotOnCurve, got: {s}",
    );
}
