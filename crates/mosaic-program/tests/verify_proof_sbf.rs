//! Integration tests: load `mosaic_program.so` and exercise every
//! `ProofSystemId` dispatch arm the on-chain program supports.
//!
//! Up to session 112 only Groth16 had end-to-end SBF coverage. Audit
//! firms expect runtime evidence that **every** declared verifier
//! dispatches under the real Solana runtime and either (a) verifies a
//! real-world proof, or (b) accepts the verifier crate's own
//! scaffold-acceptance fixture. This file delivers (a) for Groth16 +
//! KZG-PLONK and (b) for the four Phase-3 verifiers (HyperPlonk,
//! Halo2, Nova/HyperNova, FRI-STARK) plus negative coverage for
//! Risc0Stark (`UnimplementedProofSystem`) and unknown bytes
//! (`UnknownProofSystem`).
//!
//! ## Fixture provenance
//!
//! - `groth16/mul-circuit/canonical/{vk,proof,public_inputs}.bin`
//!   produced by snarkjs over a CIRCOM `mul` circuit; verified
//!   independently against arkworks ([`tests/differential`]).
//! - `plonk/mul-circuit/canonical/{vk,proof,public_inputs}.bin`
//!   produced by snarkjs PLONK 0.7.6; differential-tested in the
//!   same harness.
//! - HyperPlonk / Halo2 / Nova / FRI-STARK: scaffold-acceptance
//!   fixtures constructed in this file, mirroring the
//!   `crates/mosaic-{system}/src/verifier.rs::tests::full_pipeline_*
//!   _accepts` builders byte-for-byte. Real prover-emitted fixtures
//!   land in session 118 + per-vendor differential harnesses.
//!
//! ## Why an SBF integration test instead of the host-side suite
//!
//! The `mosaic_program::dispatch_verify` function is exercised by
//! ~150 host tests already. What those don't cover is the
//! Borsh-decode → discriminant-parse → SBF VM execution path against
//! the `solana-program-test` runtime, which is what mainnet validators
//! will actually run. A bug in the dispatcher's instruction-tag layout
//! (e.g. session 113's previously-swapped Nova/FriStark byte mapping)
//! is invisible to host tests and only surfaces here.
//!
//! ## Compute-unit ceilings
//!
//! Solana caps a single transaction at
//! `solana_program_runtime::execution_budget::MAX_COMPUTE_UNIT_LIMIT
//! = 1_400_000`. Every test below requests ≤ 1.4 M CU. The real
//! FRI-STARK scaffold currently estimated by `bpf-bench` at ~7.8 M CU
//! cannot fit in a single tx — for SBF integration coverage we
//! therefore use the verifier crate's smaller `(num_fri=0, num_q=4,
//! log_h=0, log_blowup=0)` depth-zero shape that fits comfortably.
//! Production STARK proofs will be split across `mosaic-chunked`
//! sessions; the chunked pipeline has its own integration coverage in
//! `chunked_handlers.rs`.
//!
//! Run locally:
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

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("MosA1cVer1f1er11111111111111111111111111111");

// ProofSystemId byte mapping — single source of truth is
// `mosaic_core::proof_system::ProofSystemId`. Mirrored here as `u8`
// constants so this file doesn't take a dependency on `mosaic-core`
// just for the discriminants.
const PSID_GROTH16: u8 = 0x01;
const PSID_PLONK_KZG: u8 = 0x02;
const PSID_HYPERPLONK_KZG: u8 = 0x03;
const PSID_HALO2_KZG: u8 = 0x04;
const PSID_FRI_STARK: u8 = 0x05;
const PSID_RISC0_STARK: u8 = 0x06;
const PSID_NOVA_FOLDING: u8 = 0x07;
const PSID_PROTOSTAR_FOLDING: u8 = 0x08;
const PSID_UNKNOWN: u8 = 0xFE;

// `OnChainError::UnimplementedProofSystem = 0x0011`,
// `OnChainError::UnknownProofSystem = 0x0010` — see
// `mosaic_core::error`. These map to `ProgramError::Custom(code)`.
const ERR_UNKNOWN_PROOF_SYSTEM: u32 = 0x0010;
const ERR_UNIMPLEMENTED_PROOF_SYSTEM: u32 = 0x0011;

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

/// Read a canonical fixture from `tests/fixtures/<system>/mul-circuit/canonical/<name>`.
fn fixture(system: &str, name: &str) -> Vec<u8> {
    let p = workspace_root()
        .join("tests/fixtures")
        .join(system)
        .join("mul-circuit/canonical")
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

/// Build a `VerifyProof` instruction with arbitrary `proof_system_id`.
/// The dispatcher reads the byte and routes to the corresponding
/// verifier; an unknown byte produces `OnChainError::UnknownProofSystem`.
fn build_verify_ix(
    proof_system_id: u8,
    vk: &[u8],
    proof: &[u8],
    public_inputs: &[u8],
) -> Instruction {
    let payload = VerifyProofData {
        proof_system_id,
        vk: vk.to_vec(),
        proof: proof.to_vec(),
        public_inputs: public_inputs.to_vec(),
    };
    let mut data = Vec::with_capacity(1 + 1 + vk.len() + proof.len() + public_inputs.len() + 16);
    data.push(0x01); // InstructionTag::VerifyProof
    borsh::to_writer(&mut data, &payload).unwrap();
    Instruction {
        program_id: PROGRAM_ID,
        accounts: Vec::<AccountMeta>::new(),
        data,
    }
}

fn extract_cu(logs: &[String]) -> Option<u64> {
    let needle = format!("Program {PROGRAM_ID} consumed ");
    logs.iter()
        .filter_map(|l| l.strip_prefix(&needle))
        .filter_map(|r| r.split_whitespace().next())
        .filter_map(|n| n.parse::<u64>().ok())
        .next()
}

/// Assert the program emitted a `mosaic: dispatch <slug>` log line —
/// the dispatcher prints one per `VerifyProof` for audit attribution.
fn assert_dispatch_log(logs: &[String], slug: &str) {
    let needle = format!("mosaic: dispatch {slug}");
    assert!(
        logs.iter().any(|l| l.contains(&needle)),
        "expected dispatch log line `{needle}`, got:\n{}",
        logs.join("\n"),
    );
}

/// Submit a verify-proof transaction and return the (result, logs)
/// tuple. Caller decides whether to assert success or extract a
/// specific failure code.
///
/// `BanksClient` methods take `&self` (not `&mut`) — see
/// `solana-banks-client::BanksClient::process_transaction_with_metadata`
/// — so this helper takes a shared reference too.
async fn submit(
    banks: &BanksClient,
    payer: &Keypair,
    blockhash: solana_sdk::hash::Hash,
    cu_limit: u32,
    proof_system_id: u8,
    vk: &[u8],
    proof: &[u8],
    public_inputs: &[u8],
) -> (
    Result<(), solana_sdk::transaction::TransactionError>,
    Vec<String>,
) {
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(cu_limit);
    let verify_ix = build_verify_ix(proof_system_id, vk, proof, public_inputs);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    let meta = banks.process_transaction_with_metadata(tx).await.unwrap();
    let logs = meta
        .metadata
        .map(|m| m.log_messages)
        .unwrap_or_default();
    (meta.result, logs)
}

// ─────────────────────────────────────────────────────────────────────────
// Phase-3 scaffold-acceptance fixture builders.
//
// Each builder mirrors the corresponding verifier crate's own
// `tests::full_pipeline_zero_proof_accepts` (or equivalent) builder
// byte-for-byte. These shapes pass every gate the verifier currently
// enforces, so the SBF integration test exercises the full pipeline:
// parse → challenges → identity check → KZG/Merkle verification.
//
// When real prover-emitted fixtures land in `tests/fixtures/*/canonical/`
// (planned session 118), the integration tests below switch to those
// fixtures via the standard `fixture(system, name)` helper.
// ─────────────────────────────────────────────────────────────────────────

/// Build the HyperPlonk scaffold-acceptance fixture: 10 sumcheck rounds
/// (`num_variables = 10`), `n_public = 1`, all wire / selector / σ
/// commitments zero, real G2 generator. Mirrors
/// `mosaic_hyperplonk::verifier::tests::dummy_proof_bytes_10_rounds`.
fn hyperplonk_scaffold() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use mosaic_hyperplonk::canonical::{
        sizes::{FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN, G1_LEN, SUMCHECK_POLY_LEN},
        HyperPlonkVerifyingKey,
    };
    use mosaic_zk_primitives::g1_consts::g2_generator_bytes;

    let vk = HyperPlonkVerifyingKey {
        n_public: 1,
        num_variables: 10,
        x2_g2: g2_generator_bytes(),
        q_m_g1: [0; G1_LEN],
        q_l_g1: [0; G1_LEN],
        q_r_g1: [0; G1_LEN],
        q_o_g1: [0; G1_LEN],
        q_c_g1: [0; G1_LEN],
        sigma_1_g1: [0; G1_LEN],
        sigma_2_g1: [0; G1_LEN],
        sigma_3_g1: [0; G1_LEN],
        k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
        k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
        k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
    }
    .to_bytes();

    let polys_len = 10 * SUMCHECK_POLY_LEN;
    let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
    let mut proof = vec![0u8; total];
    proof[256..260].copy_from_slice(&10u32.to_le_bytes());

    let public_inputs = vec![0u8; FR_LEN];
    (vk, proof, public_inputs)
}

/// Build the Halo2 scaffold-acceptance fixture: 5 advice columns,
/// 0 lookup (legacy implicit-1 mode), 3 quotient chunks, 19 evaluation
/// slots, `LOOKUP_M = 1` so the lookup expression evaluates to zero
/// on the all-zero wire bundle. Mirrors
/// `mosaic_halo2::verifier::tests::dummy_proof_bytes_typical`.
fn halo2_scaffold() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use mosaic_halo2::canonical::{
        sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN},
        Halo2KzgVerifyingKey,
    };
    use mosaic_zk_primitives::field::fr_be_from_u64;
    use mosaic_zk_primitives::g1_consts::g2_generator_bytes;

    let mut x2_g2 = [0u8; G2_LEN];
    x2_g2.copy_from_slice(&g2_generator_bytes());

    let vk = Halo2KzgVerifyingKey {
        k: 10,
        n_instances: 1,
        n_advice: 5,
        n_fixed: 2,
        x2_g2,
        omega_fr: [0u8; FR_LEN],
        fixed_commits: vec![0; 2 * G1_LEN],
        permutation_commits: vec![0; 5 * G1_LEN],
    }
    .to_bytes();

    let n_advice = 5u32;
    let n_lookups = 0u32;
    let n_quotient = 3u32;
    let n_evals = 19u32;
    let total = FIXED_HEADER_LEN
        + (n_advice as usize) * G1_LEN
        + (n_lookups as usize) * G1_LEN
        + G1_LEN
        + (n_quotient as usize) * G1_LEN
        + (n_evals as usize) * FR_LEN
        + 2 * G1_LEN;
    let mut proof = vec![0u8; total];
    proof[0..4].copy_from_slice(&n_advice.to_le_bytes());
    proof[4..8].copy_from_slice(&n_lookups.to_le_bytes());
    proof[8..12].copy_from_slice(&n_quotient.to_le_bytes());
    proof[12..16].copy_from_slice(&n_evals.to_le_bytes());

    // LOOKUP_M = idx 15 in the evaluation bundle. Setting m = 1 (Fr
    // canonical big-endian = 0x00..01) makes the lookup expression
    // 1/θ - 1/θ = 0 on all-zero input/table — same trick the verifier's
    // own scaffold-accept test uses.
    let evals_off = FIXED_HEADER_LEN
        + (n_advice as usize) * G1_LEN
        + (n_lookups as usize) * G1_LEN
        + G1_LEN
        + (n_quotient as usize) * G1_LEN;
    let m_off = evals_off + 15 * FR_LEN;
    let one_be = fr_be_from_u64(1);
    proof[m_off..m_off + FR_LEN].copy_from_slice(&one_be);

    let public_inputs = vec![0u8; FR_LEN];
    (vk, proof, public_inputs)
}

/// Build the Nova scaffold-acceptance fixture: variant = Nova,
/// `n_public = 4`, `num_aux_commits = 0`. All commits zero except
/// `x2_g2` which is the real G2 generator. Mirrors
/// `mosaic_nova::verifier::tests::proof_bytes` at the
/// `(Nova, num_aux=0, n_public=4)` shape.
fn nova_scaffold() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use mosaic_nova::canonical::{
        sizes::{
            FIXED_COMMITS_LEN, FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN, HADAMARD_EVALS_LEN,
            OPENING_LEN, SCALAR_LEN, W_EVAL_LEN,
        },
        FoldingVariant, NovaFoldingVerifyingKey,
    };
    use mosaic_zk_primitives::g1_consts::g2_generator_bytes;

    let mut x2_g2 = [0u8; G2_LEN];
    x2_g2.copy_from_slice(&g2_generator_bytes());

    let vk = NovaFoldingVerifyingKey {
        variant: FoldingVariant::Nova,
        n_public: 4,
        n_constraints: 1024,
        x2_g2,
        a_comm: [0u8; G1_LEN],
        b_comm: [0u8; G1_LEN],
        c_comm: [0u8; G1_LEN],
        cs_digest: [0u8; 32],
    }
    .to_bytes();

    // header(16) + E/W/T (3·G1) + u (Fr) + 4 base commits (G1) +
    // Hadamard bundle (4·Fr) + w_eval (Fr) + 0 aux + 4·Fr PI +
    // 2·G1 KZG opening.
    let pi_len = 4 * FR_LEN;
    let total = FIXED_HEADER_LEN
        + FIXED_COMMITS_LEN
        + SCALAR_LEN
        + 4 * G1_LEN
        + HADAMARD_EVALS_LEN
        + W_EVAL_LEN
        + pi_len
        + OPENING_LEN;
    let mut proof = vec![0u8; total];
    proof[0] = FoldingVariant::Nova as u8;
    proof[1] = 0; // num_aux_commits
    proof[2..4].copy_from_slice(&4u16.to_le_bytes()); // n_public

    let public_inputs = vec![0u8; pi_len];
    (vk, proof, public_inputs)
}

/// Build the FRI-STARK scaffold-acceptance fixture at the smallest
/// passing shape:
///   `(field=Goldilocks, num_fri=0, num_q=4, log_h=0, width=32, log_blowup=0)`.
///
/// At `log_h = log_blowup = 0` the Merkle depth is zero, i.e. each
/// query response is just the leaf which equals the root. By filling
/// both `trace_commitment` and `constraint_commitment` with the same
/// byte pattern as the per-query leaves (`0xAB`), every query trivially
/// verifies. This is exactly the shape used by
/// `mosaic_stark::verifier::tests::full_pipeline_accepts_depth_zero_merkle_both_commits`.
///
/// The larger shape used by `bpf-bench` (8 queries × 4 FRI layers ×
/// `log_h=10`) consumes ~7.8 M CU, exceeding the 1.4 M per-tx cap;
/// production STARK proofs MUST be chunked via `mosaic-chunked`.
fn fri_stark_scaffold() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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
    let depth = (trace_log_height as usize) + (log_blowup as usize); // == 0
    let per_query = 2 * (DIGEST_LEN + depth * DIGEST_LEN);
    let query_bytes = (num_queries as usize) * per_query;
    let fri_openings_bytes =
        (num_queries as usize) * (num_fri_layers as usize) * FRI_LAYER_OPENING_LEN;
    let auth_paths_bytes =
        (num_queries as usize) * (num_fri_layers as usize) * 2 * depth * DIGEST_LEN;

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
    // Fixed header: field_id ‖ log_blowup ‖ num_fri ‖ pow_bits ‖
    //               num_q (LE) ‖ log_h (LE) ‖ width (LE).
    proof[0] = field_id as u8;
    proof[1] = log_blowup;
    proof[2] = num_fri_layers;
    proof[3] = 0; // pow_bits
    proof[4..6].copy_from_slice(&num_queries.to_le_bytes());
    proof[6..8].copy_from_slice(&trace_log_height.to_le_bytes());
    proof[8..12].copy_from_slice(&trace_width.to_le_bytes());

    // trace_commitment + constraint_commitment at depth 0 must equal
    // the per-query leaves for the dual-Merkle check to pass.
    let trace_off = FIXED_HEADER_LEN;
    let constraint_off = trace_off + DIGEST_LEN;
    for byte in proof[trace_off..trace_off + DIGEST_LEN].iter_mut() {
        *byte = leaf_fill;
    }
    for byte in proof[constraint_off..constraint_off + DIGEST_LEN].iter_mut() {
        *byte = leaf_fill;
    }

    // Length prefixes for the variable tails. At num_fri=0 there are
    // no FRI commits / openings / auth paths, so prefixes go to 0.
    let mut off = FIXED_HEADER_LEN + 2 * DIGEST_LEN + (num_fri_layers as usize) * DIGEST_LEN;
    proof[off..off + 4].copy_from_slice(&(ood_bytes as u32).to_le_bytes());
    off += 4 + ood_bytes;
    proof[off..off + 4].copy_from_slice(&(final_bytes as u32).to_le_bytes());
    off += 4 + final_bytes;
    proof[off..off + 4].copy_from_slice(&(query_bytes as u32).to_le_bytes());
    off += 4;
    // Fill query_responses with the same leaf_fill pattern so each
    // 32-byte chunk forms a depth-0 leaf == root.
    for byte in proof[off..off + query_bytes].iter_mut() {
        *byte = leaf_fill;
    }
    off += query_bytes;
    proof[off..off + 4].copy_from_slice(&(fri_openings_bytes as u32).to_le_bytes());
    off += 4 + fri_openings_bytes;
    proof[off..off + 4].copy_from_slice(&(auth_paths_bytes as u32).to_le_bytes());
    // pow_nonce: trailing 8 bytes default to 0 (no PoW required at pow_bits=0).

    let public_inputs = Vec::new();
    (vk, proof, public_inputs)
}

// ─────────────────────────────────────────────────────────────────────────
// Tests — every dispatch arm covered, kept in canonical-byte order.
// ─────────────────────────────────────────────────────────────────────────

/// End-to-end: load `mosaic_program.so`, submit VerifyProof with the
/// mul-circuit fixture, assert success + CU within tolerance of the
/// baseline pinned in `mosaic-bench::bpf_bench`.
#[tokio::test]
async fn sbf_verify_proof_succeeds_on_valid_groth16() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    let vk = fixture("groth16", "vk.bin");
    let proof = fixture("groth16", "proof.bin");
    let pi = fixture("groth16", "public_inputs.bin");

    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        300_000,
        PSID_GROTH16,
        &vk,
        &proof,
        &pi,
    )
    .await;
    assert!(
        result.is_ok(),
        "valid Groth16 proof must verify on-chain: {:?}\nlogs:\n{}",
        result,
        logs.join("\n"),
    );

    let cu = extract_cu(&logs).expect("CU line in logs");

    // Baseline pinned in `mosaic-bench::bpf_bench::TARGETS[0]` at
    // 83 574 (2026-04-23 re-measurement). ±10% tolerance here vs the
    // 5% tolerance in bpf-bench: this test is a smoke gate, the
    // tighter tolerance lives where the regression dashboard reads.
    const BASELINE: u64 = 83_574;
    let upper = BASELINE + BASELINE / 10;
    let lower = BASELINE - BASELINE / 10;
    assert!(
        (lower..=upper).contains(&cu),
        "CU drift beyond ±10%: measured {cu}, baseline {BASELINE}; investigate",
    );

    assert_dispatch_log(&logs, "groth16_bn254");
}

/// Tampered Groth16 proof: flip one bit in `proof.a.x`, expect either
/// `PairingCheckFailed` (0x20), `AltBn128SyscallFailed` (0x40), or
/// `PointNotOnCurve` (0x06) — all are valid rejections depending on
/// whether the syscall deems the point off-curve before pairing.
#[tokio::test]
async fn sbf_rejects_tampered_groth16_proof() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    let vk = fixture("groth16", "vk.bin");
    let mut proof = fixture("groth16", "proof.bin");
    proof[0] ^= 0x01; // flip low bit of proof.a.x byte 0
    let pi = fixture("groth16", "public_inputs.bin");

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(300_000);
    let verify_ix = build_verify_ix(PSID_GROTH16, &vk, &proof, &pi);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains("Custom(32)")
            || s.contains("0x20")
            || s.contains("Custom(64)")
            || s.contains("0x40")
            || s.contains("Custom(6)")
            || s.contains("0x6"),
        "expected PairingCheckFailed / AltBn128SyscallFailed / PointNotOnCurve, got: {s}",
    );
}

/// PLONK end-to-end with the snarkjs PLONK 0.7.6 mul-circuit fixture.
/// Asserts dispatch + acceptance + CU within tolerance of the
/// `bpf-bench` baseline (968 457 CU at the v0.5.0 opt-level="z" profile).
#[tokio::test]
async fn sbf_verify_proof_succeeds_on_valid_plonk() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    let vk = fixture("plonk", "vk.bin");
    let proof = fixture("plonk", "proof.bin");
    let pi = fixture("plonk", "public_inputs.bin");

    // Request near-max CU; the baseline is ~968K with hard cap 1_100K
    // and the runtime caps at 1_400K — leave a small safety margin.
    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        1_300_000,
        PSID_PLONK_KZG,
        &vk,
        &proof,
        &pi,
    )
    .await;
    assert!(
        result.is_ok(),
        "valid PLONK proof must verify on-chain: {:?}\nlogs:\n{}",
        result,
        logs.join("\n"),
    );

    let cu = extract_cu(&logs).expect("CU line in logs");
    // Generous ±15% tolerance — PLONK's polynomial-heavy path drifts
    // more than Groth16's pairing-dominated path under codegen
    // updates. Tight regression tracking lives in bpf-bench.
    const BASELINE: u64 = 968_457;
    let upper = BASELINE + (BASELINE * 15) / 100;
    let lower = BASELINE - (BASELINE * 15) / 100;
    assert!(
        (lower..=upper).contains(&cu),
        "PLONK CU drift beyond ±15%: measured {cu}, baseline {BASELINE}; investigate",
    );

    assert_dispatch_log(&logs, "plonk_kzg_bn254");
}

/// HyperPlonk scaffold-acceptance fixture dispatches end-to-end and
/// the verifier accepts. Mirrors the host-side
/// `mosaic_hyperplonk::verifier::tests::full_pipeline_zero_proof_accepts`
/// expectation under the real SBF runtime.
#[tokio::test]
async fn sbf_dispatches_hyperplonk_kzg_scaffold() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;
    let (vk, proof, pi) = hyperplonk_scaffold();

    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        1_200_000, // bpf-bench targets 800K hard cap; allow headroom
        PSID_HYPERPLONK_KZG,
        &vk,
        &proof,
        &pi,
    )
    .await;
    assert!(
        result.is_ok(),
        "HyperPlonk scaffold should accept on-chain: {:?}\nlogs:\n{}",
        result,
        logs.join("\n"),
    );
    assert_dispatch_log(&logs, "hyperplonk_kzg_bn254");
}

/// Halo2 scaffold-acceptance fixture dispatches end-to-end and the
/// verifier accepts. Mirrors
/// `mosaic_halo2::verifier::tests::full_pipeline_zero_proof_accepts`.
#[tokio::test]
async fn sbf_dispatches_halo2_kzg_scaffold() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;
    let (vk, proof, pi) = halo2_scaffold();

    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        1_200_000, // bpf-bench targets 760K hard cap; allow headroom
        PSID_HALO2_KZG,
        &vk,
        &proof,
        &pi,
    )
    .await;
    assert!(
        result.is_ok(),
        "Halo2 scaffold should accept on-chain: {:?}\nlogs:\n{}",
        result,
        logs.join("\n"),
    );
    assert_dispatch_log(&logs, "halo2_kzg_bn254");
}

/// FRI-STARK scaffold-acceptance fixture (smallest passing shape:
/// `num_fri=0, num_q=4, log_h=0, log_blowup=0`) dispatches end-to-end
/// and the verifier accepts. Mirrors
/// `mosaic_stark::verifier::tests::full_pipeline_accepts_depth_zero_merkle_both_commits`.
///
/// Production STARK proofs at the `bpf-bench` shape (8 queries × 4
/// FRI layers × `log_h=10`) consume ~7.8 M CU and require chunked
/// dispatch via `mosaic-chunked`.
#[tokio::test]
async fn sbf_dispatches_fri_stark_scaffold() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;
    let (vk, proof, pi) = fri_stark_scaffold();

    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        400_000, // depth-zero Merkle is cheap; ≤200K typical
        PSID_FRI_STARK,
        &vk,
        &proof,
        &pi,
    )
    .await;
    assert!(
        result.is_ok(),
        "FRI-STARK depth-zero scaffold should accept on-chain: {:?}\nlogs:\n{}",
        result,
        logs.join("\n"),
    );
    assert_dispatch_log(&logs, "fri_stark");
}

/// Risc0 STARK is declared in `ProofSystemId` but currently routes to
/// `OnChainError::UnimplementedProofSystem`. The dispatcher MUST
/// surface a deterministic `ProgramError::Custom(0x0011)` rather than
/// silently accepting or panicking — auditors flag any non-deterministic
/// rejection path.
#[tokio::test]
async fn sbf_risc0_returns_unimplemented_proof_system() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    // Borsh requires a non-empty payload but the dispatcher rejects
    // on the discriminant before reading vk/proof/pi.
    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        100_000,
        PSID_RISC0_STARK,
        &[0u8; 16],
        &[0u8; 16],
        &[0u8; 16],
    )
    .await;
    let err = result.expect_err("Risc0 dispatch must reject");
    let s = format!("{err:?}");
    assert!(
        s.contains(&format!("Custom({ERR_UNIMPLEMENTED_PROOF_SYSTEM})"))
            || s.contains("Custom(17)")
            || s.contains("0x11"),
        "expected UnimplementedProofSystem (0x{ERR_UNIMPLEMENTED_PROOF_SYSTEM:04x}), got: {s}\nlogs:\n{}",
        logs.join("\n"),
    );
}

/// ProtoStarFolding (0x08) shares the Nova verifier per the dispatcher
/// (see `mosaic_program::dispatch_verify`). A scaffold-shaped Nova
/// proof must therefore accept under the ProtoStar discriminant too —
/// confirming the dispatch alias is wired and not a stub.
#[tokio::test]
async fn sbf_dispatches_protostar_via_nova_verifier() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;
    let (vk, proof, pi) = nova_scaffold();

    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        1_300_000,
        PSID_PROTOSTAR_FOLDING,
        &vk,
        &proof,
        &pi,
    )
    .await;
    assert!(
        result.is_ok(),
        "ProtoStar should dispatch through Nova verifier: {:?}\nlogs:\n{}",
        result,
        logs.join("\n"),
    );
    // Dispatch slug is `nova_folding` because the verifier is shared;
    // the discriminant log line is emitted by `ProofSystemId::slug()`
    // for the resolved arm.
    assert_dispatch_log(&logs, "nova_folding");
}

/// Nova scaffold-acceptance fixture under the canonical Nova
/// discriminant (0x07). Same fixture as the ProtoStar test above,
/// different discriminant — exercising both routes guards against a
/// future arm-split where ProtoStar gains its own verifier.
#[tokio::test]
async fn sbf_dispatches_nova_folding_scaffold() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;
    let (vk, proof, pi) = nova_scaffold();

    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        1_300_000,
        PSID_NOVA_FOLDING,
        &vk,
        &proof,
        &pi,
    )
    .await;
    assert!(
        result.is_ok(),
        "Nova scaffold should accept on-chain: {:?}\nlogs:\n{}",
        result,
        logs.join("\n"),
    );
    assert_dispatch_log(&logs, "nova_folding");
}

/// An unknown `ProofSystemId` byte must surface as
/// `OnChainError::UnknownProofSystem` (0x0010). This protects the
/// dispatcher's stability promise: future variants land via the
/// `#[non_exhaustive]` enum, and unknown bytes never silently fall
/// through to the next arm.
#[tokio::test]
async fn sbf_unknown_proof_system_rejected() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    let (result, logs) = submit(
        &banks,
        &payer,
        blockhash,
        100_000,
        PSID_UNKNOWN,
        &[0u8; 16],
        &[0u8; 16],
        &[0u8; 16],
    )
    .await;
    let err = result.expect_err("unknown proof system must reject");
    let s = format!("{err:?}");
    assert!(
        s.contains(&format!("Custom({ERR_UNKNOWN_PROOF_SYSTEM})"))
            || s.contains("Custom(16)")
            || s.contains("0x10"),
        "expected UnknownProofSystem (0x{ERR_UNKNOWN_PROOF_SYSTEM:04x}), got: {s}\nlogs:\n{}",
        logs.join("\n"),
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Session 116 — VerifyCompressedProof instruction (`0x03`).
//
// The compressed-proof path decompresses VK + proof on chain via the
// `sol_alt_bn128_compression` syscall, then dispatches to the
// existing `dispatch_verify`. Public inputs pass through unchanged.
//
// SBF runtime evidence covers:
//   - Happy path: real Groth16 mul-circuit fixture, compress on host
//     → submit compressed → on-chain decompress + verify.
//   - FRI-STARK rejection: STARK has no BN254 curve points; the
//     dispatcher must surface `UnsupportedOperation` (0x18)
//     deterministically rather than attempting a malformed compress.
// ─────────────────────────────────────────────────────────────────────────

#[derive(BorshSerialize)]
struct VerifyCompressedProofData {
    proof_system_id: u8,
    compressed_vk: Vec<u8>,
    compressed_proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

/// `OnChainError::UnsupportedOperation = 0x0018` — see `mosaic_core::error`.
const ERR_UNSUPPORTED_OPERATION: u32 = 0x0018;

fn build_verify_compressed_ix(
    proof_system_id: u8,
    compressed_vk: &[u8],
    compressed_proof: &[u8],
    public_inputs: &[u8],
) -> Instruction {
    let payload = VerifyCompressedProofData {
        proof_system_id,
        compressed_vk: compressed_vk.to_vec(),
        compressed_proof: compressed_proof.to_vec(),
        public_inputs: public_inputs.to_vec(),
    };
    let mut data = Vec::with_capacity(
        1 + 1 + compressed_vk.len() + compressed_proof.len() + public_inputs.len() + 16,
    );
    data.push(0x03); // InstructionTag::VerifyCompressedProof
    borsh::to_writer(&mut data, &payload).unwrap();
    Instruction {
        program_id: PROGRAM_ID,
        accounts: Vec::<AccountMeta>::new(),
        data,
    }
}

/// Compress the canonical Groth16 mul-circuit fixture host-side, then
/// submit via `VerifyCompressedProof`. Asserts:
///   1. The transaction succeeds end-to-end (compress on host →
///      decompress on chain → verify).
///   2. The dispatcher emits the `mosaic: dispatch_compressed groth16_bn254`
///      log line (audit attribution evidence).
///   3. CU consumption falls within tolerance of the *added*
///      decompression overhead vs the canonical baseline.
#[tokio::test]
async fn sbf_verify_compressed_groth16_succeeds() {
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_groth16::canonical::{Groth16Proof, Groth16VerifyingKey};

    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    // Read canonical fixtures + compress host-side.
    let canonical_vk = fixture("groth16", "vk.bin");
    let canonical_proof = fixture("groth16", "proof.bin");
    let pi = fixture("groth16", "public_inputs.bin");
    let host = HostBackend::new();
    let vk_struct = Groth16VerifyingKey::from_bytes(&canonical_vk).expect("parse canonical vk");
    let compressed_vk = vk_struct.to_compressed_bytes(&host).expect("compress vk");
    let compressed_proof = Groth16Proof::compress_from_canonical_bytes(&host, &canonical_proof)
        .expect("compress proof");

    // Sanity: compressed sizes match the documented 50 % saving.
    assert!(
        compressed_proof.len() < canonical_proof.len(),
        "compressed proof must be smaller than canonical: {} < {}",
        compressed_proof.len(),
        canonical_proof.len(),
    );

    // Submit compressed → on-chain decompress → verify.
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(300_000);
    let verify_ix =
        build_verify_compressed_ix(PSID_GROTH16, &compressed_vk, &compressed_proof, &pi);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let meta = banks.process_transaction_with_metadata(tx).await.unwrap();
    let logs = meta
        .metadata
        .map(|m| m.log_messages)
        .unwrap_or_default();
    assert!(
        meta.result.is_ok(),
        "compressed Groth16 must verify on-chain: {:?}\nlogs:\n{}",
        meta.result,
        logs.join("\n"),
    );

    // Dispatcher emits the compressed-path slug — distinct from the
    // canonical-path `mosaic: dispatch <slug>` for audit attribution.
    let needle = "mosaic: dispatch_compressed groth16_bn254";
    assert!(
        logs.iter().any(|l| l.contains(needle)),
        "expected dispatch_compressed log line `{needle}`, got:\n{}",
        logs.join("\n"),
    );

    // CU should be larger than the canonical baseline (83 574) due to
    // decompression overhead: ~10 K per G1 × 5 + ~12 K per G2 × 3 ≈
    // ~86 K added. Total ~170 K. Use a generous +100 % upper bound to
    // avoid flaky failures across syscall-cost-schedule revisions.
    let cu = extract_cu(&logs).expect("CU line in logs");
    assert!(
        cu > 83_574 && cu < 300_000,
        "compressed Groth16 CU {cu} should fall in (83K, 300K) range",
    );
}

/// FRI-STARK has no BN254 curve points. The dispatcher must reject
/// `VerifyCompressedProof` for it deterministically with
/// `OnChainError::UnsupportedOperation` (0x0018) — surfacing a clean
/// error to callers instead of attempting a malformed decompression
/// that would fail at the syscall layer with a less-informative code.
#[tokio::test]
async fn sbf_verify_compressed_rejects_fri_stark() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(100_000);
    let verify_ix = build_verify_compressed_ix(
        PSID_FRI_STARK,
        &[0u8; 64],
        &[0u8; 64],
        &[0u8; 32],
    );
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains(&format!("Custom({ERR_UNSUPPORTED_OPERATION})"))
            || s.contains("Custom(24)")
            || s.contains("0x18"),
        "expected UnsupportedOperation (0x{ERR_UNSUPPORTED_OPERATION:04x}), got: {s}",
    );
}

/// Risc0Stark dispatch arm in `VerifyCompressedProof` matches the
/// canonical `VerifyProof` arm: returns `UnimplementedProofSystem`
/// (0x0011). Confirms the negative-path matrix is consistent across
/// both instruction tags.
#[tokio::test]
async fn sbf_verify_compressed_rejects_risc0_unimplemented() {
    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(100_000);
    let verify_ix = build_verify_compressed_ix(
        PSID_RISC0_STARK,
        &[0u8; 64],
        &[0u8; 64],
        &[0u8; 32],
    );
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let err = banks.process_transaction(tx).await.unwrap_err();
    let s = format!("{err:?}");
    assert!(
        s.contains(&format!("Custom({ERR_UNIMPLEMENTED_PROOF_SYSTEM})"))
            || s.contains("Custom(17)")
            || s.contains("0x11"),
        "expected UnimplementedProofSystem (0x{ERR_UNIMPLEMENTED_PROOF_SYSTEM:04x}), got: {s}",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Session 120 — VerifyCompressedProof (0x03) coverage for the remaining
// four BN254 verifiers.
//
// Up to session 116 the on-chain `VerifyCompressedProof` instruction
// had only a Groth16 happy-path SBF integration test (plus two
// rejection paths for FriStark / Risc0). The four other BN254
// verifiers (PLONK, HyperPlonk, Halo2, Nova) have compression APIs
// shipped at v0.9.7–v0.9.13 but no SBF runtime evidence that the
// compressed-path dispatch arm accepts them on chain.
//
// This sweep closes that gap: one happy-path test per remaining
// BN254 verifier, exercising
//
//     compress host-side → submit `VerifyCompressedProof` →
//     dispatcher decompresses on chain → existing verify path runs.
//
// For Phase-3 scaffolds the canonical-path equivalents are already
// covered (sbf_dispatches_*_scaffold tests at line ~644 onwards).
// These new tests reuse the same scaffold builders + the existing
// `compress_from_canonical_bytes` helpers from each verifier crate.
// ─────────────────────────────────────────────────────────────────────────

/// PLONK end-to-end through the compressed dispatch arm. Real snarkjs
/// PLONK 0.7.6 mul-circuit fixture; host-side compression; on-chain
/// decompression; on-chain verify.
#[tokio::test]
async fn sbf_verify_compressed_plonk_succeeds() {
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_plonk::canonical::{PlonkProof, PlonkVerifyingKey};

    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;

    let canonical_vk = fixture("plonk", "vk.bin");
    let canonical_proof = fixture("plonk", "proof.bin");
    let pi = fixture("plonk", "public_inputs.bin");

    let host = HostBackend::new();
    let vk_struct = PlonkVerifyingKey::from_bytes(&canonical_vk).expect("parse vk");
    let compressed_vk = vk_struct.to_compressed_bytes(&host).expect("compress vk");
    let compressed_proof =
        PlonkProof::compress_from_canonical_bytes(&host, &canonical_proof)
            .expect("compress proof");

    assert!(
        compressed_proof.len() < canonical_proof.len(),
        "compressed PLONK proof must shrink: {} ≥ {}",
        compressed_proof.len(),
        canonical_proof.len(),
    );

    // Per CHANGELOG v0.9.10: PLONK proof 768 → 480 B = 37.5 %.
    // Per CHANGELOG v0.9.10: PLONK VK 744 → 424 B = 43 %.
    assert_eq!(compressed_proof.len(), 480, "PLONK proof size drift");
    assert_eq!(compressed_vk.len(), 424, "PLONK VK size drift");

    // PLONK canonical-path baseline 968 457 CU. Compression adds
    // ~92 K (8 G1 + 1 G2 decompress). Request 1.3 M with headroom.
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_300_000);
    let verify_ix =
        build_verify_compressed_ix(PSID_PLONK_KZG, &compressed_vk, &compressed_proof, &pi);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let meta = banks.process_transaction_with_metadata(tx).await.unwrap();
    let logs = meta.metadata.map(|m| m.log_messages).unwrap_or_default();
    assert!(
        meta.result.is_ok(),
        "compressed PLONK must verify on-chain: {:?}\nlogs:\n{}",
        meta.result,
        logs.join("\n"),
    );

    let needle = "mosaic: dispatch_compressed plonk_kzg_bn254";
    assert!(
        logs.iter().any(|l| l.contains(needle)),
        "expected `{needle}`, got:\n{}",
        logs.join("\n"),
    );
}

/// HyperPlonk scaffold-acceptance fixture round-tripped through the
/// compressed dispatch arm.
#[tokio::test]
async fn sbf_verify_compressed_hyperplonk_scaffold_succeeds() {
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_hyperplonk::canonical::{HyperPlonkProof, HyperPlonkVerifyingKey};

    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;
    let (canonical_vk, canonical_proof, pi) = hyperplonk_scaffold();

    let host = HostBackend::new();
    let compressed_vk =
        HyperPlonkVerifyingKey::to_compressed_bytes(&host, &canonical_vk)
            .expect("compress vk");
    let compressed_proof =
        HyperPlonkProof::compress_from_canonical_bytes(&host, &canonical_proof)
            .expect("compress proof");

    assert!(
        compressed_vk.len() < canonical_vk.len(),
        "compressed HyperPlonk VK must shrink",
    );
    assert!(
        compressed_proof.len() < canonical_proof.len(),
        "compressed HyperPlonk proof must shrink",
    );

    // HyperPlonk canonical-path bpf-bench cap = 660 K. Compression
    // adds ~92 K (12 G1 + 1 G2 decompress). 1.3 M with headroom.
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_300_000);
    let verify_ix = build_verify_compressed_ix(
        PSID_HYPERPLONK_KZG,
        &compressed_vk,
        &compressed_proof,
        &pi,
    );
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let meta = banks.process_transaction_with_metadata(tx).await.unwrap();
    let logs = meta.metadata.map(|m| m.log_messages).unwrap_or_default();
    assert!(
        meta.result.is_ok(),
        "compressed HyperPlonk scaffold must verify on-chain: {:?}\nlogs:\n{}",
        meta.result,
        logs.join("\n"),
    );

    let needle = "mosaic: dispatch_compressed hyperplonk_kzg_bn254";
    assert!(
        logs.iter().any(|l| l.contains(needle)),
        "expected `{needle}`, got:\n{}",
        logs.join("\n"),
    );
}

/// Halo2 scaffold-acceptance fixture round-tripped through the
/// compressed dispatch arm.
#[tokio::test]
async fn sbf_verify_compressed_halo2_scaffold_succeeds() {
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_halo2::canonical::{Halo2KzgProof, Halo2KzgVerifyingKey};

    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;
    let (canonical_vk, canonical_proof, pi) = halo2_scaffold();

    let host = HostBackend::new();
    let vk_struct = Halo2KzgVerifyingKey::from_bytes(&canonical_vk).expect("parse vk");
    let compressed_vk = vk_struct.to_compressed_bytes(&host).expect("compress vk");
    let compressed_proof =
        Halo2KzgProof::compress_from_canonical_bytes(&host, &canonical_proof)
            .expect("compress proof");

    assert!(
        compressed_vk.len() < canonical_vk.len(),
        "compressed Halo2 VK must shrink",
    );
    assert!(
        compressed_proof.len() < canonical_proof.len(),
        "compressed Halo2 proof must shrink",
    );

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_300_000);
    let verify_ix = build_verify_compressed_ix(
        PSID_HALO2_KZG,
        &compressed_vk,
        &compressed_proof,
        &pi,
    );
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let meta = banks.process_transaction_with_metadata(tx).await.unwrap();
    let logs = meta.metadata.map(|m| m.log_messages).unwrap_or_default();
    assert!(
        meta.result.is_ok(),
        "compressed Halo2 scaffold must verify on-chain: {:?}\nlogs:\n{}",
        meta.result,
        logs.join("\n"),
    );

    let needle = "mosaic: dispatch_compressed halo2_kzg_bn254";
    assert!(
        logs.iter().any(|l| l.contains(needle)),
        "expected `{needle}`, got:\n{}",
        logs.join("\n"),
    );
}

/// Nova scaffold-acceptance fixture round-tripped through the
/// compressed dispatch arm. ProtoStar shares the dispatch path
/// (alias) so this also exercises 0x08 indirectly.
#[tokio::test]
async fn sbf_verify_compressed_nova_scaffold_succeeds() {
    use mosaic_core::syscall::host::HostBackend;
    use mosaic_nova::canonical::{NovaFoldingProof, NovaFoldingVerifyingKey};

    if !sbf_ready() {
        return;
    }
    let (banks, payer, blockhash) = setup().await;
    let (canonical_vk, canonical_proof, pi) = nova_scaffold();

    let host = HostBackend::new();
    let compressed_vk =
        NovaFoldingVerifyingKey::to_compressed_bytes(&host, &canonical_vk)
            .expect("compress vk");
    let compressed_proof =
        NovaFoldingProof::compress_from_canonical_bytes(&host, &canonical_proof)
            .expect("compress proof");

    assert!(
        compressed_vk.len() < canonical_vk.len(),
        "compressed Nova VK must shrink",
    );
    assert!(
        compressed_proof.len() < canonical_proof.len(),
        "compressed Nova proof must shrink",
    );

    // Nova canonical-path bpf-bench cap = 1.15 M. Compression adds
    // ~110 K (13 G1 + 1 G2 decompress at default shape). 1.4 M (tx cap).
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let verify_ix = build_verify_compressed_ix(
        PSID_NOVA_FOLDING,
        &compressed_vk,
        &compressed_proof,
        &pi,
    );
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let meta = banks.process_transaction_with_metadata(tx).await.unwrap();
    let logs = meta.metadata.map(|m| m.log_messages).unwrap_or_default();
    assert!(
        meta.result.is_ok(),
        "compressed Nova scaffold must verify on-chain: {:?}\nlogs:\n{}",
        meta.result,
        logs.join("\n"),
    );

    let needle = "mosaic: dispatch_compressed nova_folding";
    assert!(
        logs.iter().any(|l| l.contains(needle)),
        "expected `{needle}`, got:\n{}",
        logs.join("\n"),
    );
}
