//! Cross-validator determinism harness — T-5 mitigation (issue #70).
//!
//! A Solana program that produces different results on different
//! validators breaks consensus. A verifier that consumes different CU
//! on different validators breaks fee markets. For a ZK verifier the
//! risk surface is the `alt_bn128` syscall family, whose behaviour is
//! gated behind runtime features that activate independently across the
//! validator set during a rollout window:
//!
//!   - `enable_alt_bn128_syscall`                     (base syscalls)
//!   - `simplify_alt_bn128_syscall_error_codes`       (SIMD-0129)
//!   - `enable_alt_bn128_compression_syscall`         (compression)
//!   - `fix_alt_bn128_multiplication_input_length`    (SIMD-0222)
//!
//! This harness runs the same fixtures under several `FeatureSet`
//! personas — modelling validators at different points of the feature
//! rollout — and asserts:
//!
//!   1. RESULT determinism: a given proof produces the same accept /
//!      reject verdict on every persona that has the base syscall.
//!   2. CU determinism: a given valid proof consumes byte-identical
//!      compute units on every such persona.
//!   3. INTRA-persona determinism: re-running the same proof in the
//!      same persona N times yields identical (result, CU) each time.
//!   4. GRACEFUL degradation: on a persona without the base syscall the
//!      program fails cleanly (never silently accepts).
//!
//! Run locally (same gating as `verify_proof_sbf.rs`):
//!
//! ```text
//! cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml
//! BPF_OUT_DIR=target/deploy cargo test -p mosaic-program --test cross_validator_determinism -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program_test::{BanksClient, ProgramTest};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};
use std::{collections::BTreeMap, fs, path::PathBuf};

const PROGRAM_ID: Pubkey = solana_sdk::pubkey!("MosA1cVer1f1er11111111111111111111111111111");

const PSID_GROTH16: u8 = 0x01;
const PSID_PLONK_KZG: u8 = 0x02;

const FEAT_ENABLE_ALT_BN128: Pubkey =
    solana_sdk::pubkey!("A16q37opZdQMCbe5qJ6xpBB9usykfv8jZaMkxvZQi4GJ");
const FEAT_SIMPLIFY_ERROR_CODES: Pubkey =
    solana_sdk::pubkey!("JDn5q3GBeqzvUa7z67BbmVHVdE3EbUAjvFep3weR3jxX");
const FEAT_ENABLE_COMPRESSION: Pubkey =
    solana_sdk::pubkey!("EJJewYSddEEtSZHiqugnvhQHiWyZKjkFDQASd7oKSagn");
const FEAT_FIX_MUL_INPUT_LEN: Pubkey =
    solana_sdk::pubkey!("bn2puAyxUx6JUabAxYdKdJ5QHbNNmKw8dCGuGCyRrFN");

#[derive(BorshSerialize, BorshDeserialize)]
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
        eprintln!("skipping cross_validator_determinism: BPF_OUT_DIR / SBF_OUT_DIR not set");
        return false;
    }
    let so = workspace_root().join("target/deploy/mosaic_program.so");
    if !so.exists() {
        eprintln!("skipping cross_validator_determinism: {so:?} not built; run cargo build-sbf");
        return false;
    }
    true
}

#[derive(Clone)]
struct Persona {
    name: &'static str,
    deactivate: Vec<Pubkey>,
    has_base_syscall: bool,
}

fn personas() -> Vec<Persona> {
    vec![
        Persona {
            name: "modern_mainnet",
            deactivate: vec![],
            has_base_syscall: true,
        },
        Persona {
            name: "no_simd_0129_error_codes",
            deactivate: vec![FEAT_SIMPLIFY_ERROR_CODES],
            has_base_syscall: true,
        },
        Persona {
            name: "no_simd_0222_mul_len",
            deactivate: vec![FEAT_FIX_MUL_INPUT_LEN],
            has_base_syscall: true,
        },
        Persona {
            name: "no_compression_syscall",
            deactivate: vec![FEAT_ENABLE_COMPRESSION],
            has_base_syscall: true,
        },
        Persona {
            name: "legacy_pre_simd_0129_0222",
            deactivate: vec![FEAT_SIMPLIFY_ERROR_CODES, FEAT_FIX_MUL_INPUT_LEN],
            has_base_syscall: true,
        },
        Persona {
            name: "ancient_no_base_syscall",
            deactivate: vec![
                FEAT_ENABLE_ALT_BN128,
                FEAT_SIMPLIFY_ERROR_CODES,
                FEAT_ENABLE_COMPRESSION,
                FEAT_FIX_MUL_INPUT_LEN,
            ],
            has_base_syscall: false,
        },
    ]
}

async fn boot(persona: &Persona) -> (BanksClient, Keypair, solana_sdk::hash::Hash) {
    let mut pt = ProgramTest::default();
    pt.add_program("mosaic_program", PROGRAM_ID, None);
    for feat in &persona.deactivate {
        pt.deactivate_feature(*feat);
    }
    pt.start().await
}

fn build_verify_ix(proof_system_id: u8, vk: &[u8], proof: &[u8], pi: &[u8]) -> Instruction {
    let payload = VerifyProofData {
        proof_system_id,
        vk: vk.to_vec(),
        proof: proof.to_vec(),
        public_inputs: pi.to_vec(),
    };
    let mut data = Vec::with_capacity(2 + vk.len() + proof.len() + pi.len() + 16);
    data.push(0x01);
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Observation {
    accepted: bool,
    cu: Option<u64>,
}

async fn observe(
    banks: &BanksClient,
    payer: &Keypair,
    blockhash: solana_sdk::hash::Hash,
    cu_limit: u32,
    psid: u8,
    vk: &[u8],
    proof: &[u8],
    pi: &[u8],
) -> Observation {
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(cu_limit);
    let verify_ix = build_verify_ix(psid, vk, proof, pi);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    let meta = banks.process_transaction_with_metadata(tx).await.unwrap();
    let logs = meta.metadata.map(|m| m.log_messages).unwrap_or_default();
    Observation {
        accepted: meta.result.is_ok(),
        cu: extract_cu(&logs),
    }
}

#[derive(Clone)]
struct Workload {
    name: &'static str,
    psid: u8,
    cu_limit: u32,
    vk: Vec<u8>,
    proof: Vec<u8>,
    pi: Vec<u8>,
    expect_accept: bool,
}

fn workloads() -> Vec<Workload> {
    let g_vk = fixture("groth16", "vk.bin");
    let g_proof = fixture("groth16", "proof.bin");
    let g_pi = fixture("groth16", "public_inputs.bin");

    let mut g_proof_tampered = g_proof.clone();
    g_proof_tampered[0] ^= 0x01;

    let p_vk = fixture("plonk", "vk.bin");
    let p_proof = fixture("plonk", "proof.bin");
    let p_pi = fixture("plonk", "public_inputs.bin");

    vec![
        Workload {
            name: "groth16_valid",
            psid: PSID_GROTH16,
            cu_limit: 400_000,
            vk: g_vk.clone(),
            proof: g_proof,
            pi: g_pi.clone(),
            expect_accept: true,
        },
        Workload {
            name: "groth16_tampered",
            psid: PSID_GROTH16,
            cu_limit: 400_000,
            vk: g_vk,
            proof: g_proof_tampered,
            pi: g_pi,
            expect_accept: false,
        },
        Workload {
            name: "plonk_valid",
            psid: PSID_PLONK_KZG,
            cu_limit: 1_400_000,
            vk: p_vk,
            proof: p_proof,
            pi: p_pi,
            expect_accept: true,
        },
    ]
}

#[test]
fn host_borsh_roundtrip_sanity() {
    use borsh::BorshDeserialize;
    let vk = fixture("groth16", "vk.bin");
    let proof = fixture("groth16", "proof.bin");
    let pi = fixture("groth16", "public_inputs.bin");
    let ix = build_verify_ix(PSID_GROTH16, &vk, &proof, &pi);
    eprintln!(
        "instruction data len = {} (tag + psid + 3 vecs). vk={} proof={} pi={}",
        ix.data.len(),
        vk.len(),
        proof.len(),
        pi.len()
    );
    eprintln!("first 16 bytes: {:02x?}", &ix.data[..16.min(ix.data.len())]);
    let rest = &ix.data[1..];
    let decoded = VerifyProofData::try_from_slice(rest).expect("host borsh decode");
    assert_eq!(decoded.proof_system_id, PSID_GROTH16);
    assert_eq!(decoded.vk.len(), vk.len());
    assert_eq!(decoded.proof.len(), proof.len());
    assert_eq!(decoded.public_inputs.len(), pi.len());
    eprintln!("host borsh roundtrip OK");
}

#[tokio::test]
async fn cross_validator_result_and_cu_determinism() {
    if !sbf_ready() {
        return;
    }

    let personas = personas();
    let workloads = workloads();

    let mut matrix: BTreeMap<&'static str, BTreeMap<&'static str, Observation>> = BTreeMap::new();

    for persona in &personas {
        let (banks, payer, blockhash) = boot(persona).await;
        let mut row: BTreeMap<&'static str, Observation> = BTreeMap::new();
        for w in &workloads {
            let obs = observe(
                &banks, &payer, blockhash, w.cu_limit, w.psid, &w.vk, &w.proof, &w.pi,
            )
            .await;
            row.insert(w.name, obs);
        }
        matrix.insert(persona.name, row);
    }

    eprintln!("\n=== cross-validator determinism matrix ===");
    eprint!("{:<30}", "persona");
    for w in &workloads {
        eprint!("{:<26}", w.name);
    }
    eprintln!();
    for persona in &personas {
        eprint!("{:<30}", persona.name);
        for w in &workloads {
            let obs = matrix[persona.name][w.name];
            let verdict = if obs.accepted { "accept" } else { "reject" };
            let cu = obs.cu.map(|c| c.to_string()).unwrap_or_else(|| "—".into());
            eprint!("{:<26}", format!("{verdict}/{cu}cu"));
        }
        eprintln!();
    }
    eprintln!();

    let base_personas: Vec<&Persona> = personas.iter().filter(|p| p.has_base_syscall).collect();

    for w in &workloads {
        let reference = matrix[base_personas[0].name][w.name];

        assert_eq!(
            reference.accepted, w.expect_accept,
            "workload {} on reference persona {}: expected accept={}, got {}",
            w.name, base_personas[0].name, w.expect_accept, reference.accepted
        );

        for persona in &base_personas {
            let obs = matrix[persona.name][w.name];
            assert_eq!(
                obs.accepted, reference.accepted,
                "RESULT DIVERGENCE: workload {} accepted={} on {} but {} on reference {}",
                w.name, obs.accepted, persona.name, reference.accepted, base_personas[0].name
            );

            if w.expect_accept {
                assert_eq!(
                    obs.cu, reference.cu,
                    "CU DIVERGENCE: workload {} consumed {:?} on {} but {:?} on reference {} — \
                     fee-market nondeterminism across the validator set",
                    w.name, obs.cu, persona.name, reference.cu, base_personas[0].name
                );
            }
        }
    }

    let ancient = personas.iter().find(|p| !p.has_base_syscall).unwrap();
    for w in &workloads {
        let obs = matrix[ancient.name][w.name];
        assert!(
            !obs.accepted,
            "GRACEFUL-DEGRADATION VIOLATION: workload {} was ACCEPTED on {} which lacks the \
             alt_bn128 base syscall — a verifier must never accept when the curve syscall is \
             unavailable",
            w.name, ancient.name
        );
    }

    eprintln!(
        "cross-validator determinism OK: {} workloads × {} base personas, all results + CU \
         identical; ancient persona degraded gracefully.",
        workloads.len(),
        base_personas.len()
    );
}

#[tokio::test]
async fn intra_persona_repeat_determinism() {
    if !sbf_ready() {
        return;
    }

    const REPEATS: usize = 5;
    let w = workloads()
        .into_iter()
        .find(|w| w.name == "groth16_valid")
        .unwrap();

    let persona = Persona {
        name: "modern_mainnet",
        deactivate: vec![],
        has_base_syscall: true,
    };
    let (banks, payer, blockhash) = boot(&persona).await;

    let mut seen: Vec<Observation> = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let obs = observe(
            &banks, &payer, blockhash, w.cu_limit, w.psid, &w.vk, &w.proof, &w.pi,
        )
        .await;
        seen.push(obs);
    }

    let first = seen[0];
    assert!(first.accepted, "groth16_valid should accept on modern mainnet");
    for (i, obs) in seen.iter().enumerate() {
        assert_eq!(
            *obs, first,
            "INTRA-PERSONA NONDETERMINISM: repeat {i} produced {obs:?} but first was {first:?}"
        );
    }

    eprintln!(
        "intra-persona determinism OK: {REPEATS} identical runs of groth16_valid \
         (accept, {:?} CU each).",
        first.cu
    );
}

#[tokio::test]
async fn plonk_cu_stable_across_error_code_features() {
    if !sbf_ready() {
        return;
    }

    let w = workloads()
        .into_iter()
        .find(|w| w.name == "plonk_valid")
        .unwrap();

    let with_simd = Persona {
        name: "with_simd_0129",
        deactivate: vec![],
        has_base_syscall: true,
    };
    let without_simd = Persona {
        name: "without_simd_0129",
        deactivate: vec![FEAT_SIMPLIFY_ERROR_CODES],
        has_base_syscall: true,
    };

    let (b1, p1, h1) = boot(&with_simd).await;
    let o1 = observe(&b1, &p1, h1, w.cu_limit, w.psid, &w.vk, &w.proof, &w.pi).await;

    let (b2, p2, h2) = boot(&without_simd).await;
    let o2 = observe(&b2, &p2, h2, w.cu_limit, w.psid, &w.vk, &w.proof, &w.pi).await;

    assert!(o1.accepted && o2.accepted, "plonk_valid should accept on both");
    assert_eq!(
        o1.cu, o2.cu,
        "PLONK CU changed with SIMD-0129 error-code simplification: {:?} vs {:?}",
        o1.cu, o2.cu
    );

    eprintln!(
        "PLONK CU stable across SIMD-0129: {:?} CU with and without the feature.",
        o1.cu
    );
}
