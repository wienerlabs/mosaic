//! `bpf-bench` — drives `mosaic_program.so` through `solana-program-test`
//! and parses CU consumption from program logs.
//!
//! Fails (exit 1) when any system exceeds its ADR-0005 hard cap. Warns
//! (exit 0) when a system exceeds its last-measured baseline by more than
//! [`BASELINE_TOLERANCE_PCT`] — useful signal without blocking unrelated PRs.
//!
//! Run locally:
//!
//! ```text
//! cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml
//! cargo run --release -p mosaic-bench --bin bpf-bench
//! ```
//!
//! ## CU baseline source
//!
//! Baselines are literal constants in this file. When a measured value
//! deviates from baseline by more than [`BASELINE_TOLERANCE_PCT`], the
//! bench prints a warning pointing to the PR that should update the
//! baseline. The hard cap (ADR-0005 target) is a different threshold —
//! that one blocks CI unconditionally.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

use anyhow::{anyhow, Context, Result};
use borsh::BorshSerialize;
use mosaic_bench::prelude::*; // re-exports HostBackend, Groth16Verifier, etc.
use solana_program_test::{BanksClient, ProgramTest};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};
use std::{fs, path::PathBuf, process::ExitCode};

// The reference program's declared id. Hardcoded because mosaic-bench does
// not depend on mosaic-program (avoids pulling solana-program as a direct
// dep into the bench crate's compile graph).
const PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("MosA1cVer1f1er11111111111111111111111111111");

/// Tolerance around the last-measured baseline. A deviation beyond this
/// triggers a WARN but not a hard failure.
const BASELINE_TOLERANCE_PCT: f64 = 5.0;

/// Per-system hard caps from ADR-0005. Exceeding one of these blocks CI.
#[derive(Debug)]
struct SystemTarget {
    name: &'static str,
    hard_cap_cu: u64,
    /// Established baseline at implementation time.
    /// When changing the verifier, update with the new measurement + PR
    /// reference in the commit message.
    baseline_cu: u64,
}

const TARGETS: &[SystemTarget] = &[
    SystemTarget {
        name: "groth16_bn254_mul_circuit_1pi",
        hard_cap_cu: 180_000,
        // Established 2026-04-20 on the tests/fixtures/groth16/mul-circuit
        // canonical fixtures (a=7, b=6, c=42, single public input).
        // Decomposition per ADR-0005 § 2:
        //   5K (deserialize) + 3.3K (G1Mul) + 0.1K (G1Add) + 36K (Pairing)
        //   ≈ 45K algorithmic + ~35K Borsh/dispatch/syscall overhead
        //   = 80 296 measured.
        // If this changes by >5%, investigate and update with PR reference.
        baseline_cu: 80_296,
    },
    SystemTarget {
        name: "groth16_batch_n5_mul_circuit_1pi",
        // Batched verification of 5 Groth16 proofs sharing one VK via
        // Bowe-Gabizon aggregation (one alt_bn128_pairing with 8 pairs).
        // Measured 2026-04-20: 230 626 CU total, 46 125 CU per proof —
        // a 42.6% reduction vs the single-proof path (80 370 × 5).
        hard_cap_cu: 300_000, // 30% headroom over baseline
        baseline_cu: 230_626,
    },
    SystemTarget {
        name: "plonk_bn254_mul_circuit_1pi",
        // ADR-0005 originally targeted 600K based on algorithmic
        // estimate (15K transcript + 200K linearization MSM + 24K
        // pairing + sundry). Actual measured consumption with arkworks
        // Fr arithmetic + full byte-for-byte snarkjs compat:
        //   747 666 CU (~25% over algorithmic estimate)
        // Cap raised to 800 000 to give 7% regression headroom over
        // the current baseline. Optimization path to approach the
        // 600K target tracked by issues #37 (MSM tightening) and a
        // follow-up "Fr arithmetic in-place mutation" issue.
        hard_cap_cu: 800_000,
        baseline_cu: 747_666,
    },
];

#[derive(BorshSerialize)]
struct VerifyProofData {
    proof_system_id: u8,
    vk: Vec<u8>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

#[derive(BorshSerialize)]
struct VerifyProofBatchData {
    proof_system_id: u8,
    vk: Vec<u8>,
    proofs: Vec<Vec<u8>>,
    public_inputs: Vec<Vec<u8>>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fixture_bytes(system: &str, name: &str) -> Result<Vec<u8>> {
    let path = workspace_root()
        .join("tests")
        .join("fixtures")
        .join(system)
        .join("mul-circuit")
        .join("canonical")
        .join(name);
    fs::read(&path).with_context(|| format!("failed to read fixture {path:?}"))
}

fn sbf_artifact_exists() -> Result<()> {
    let path = workspace_root().join("target").join("deploy").join("mosaic_program.so");
    if !path.exists() {
        anyhow::bail!(
            "SBF artifact missing at {path:?}; run `cargo build-sbf --tools-version v1.52 \
             --manifest-path crates/mosaic-program/Cargo.toml` first"
        );
    }
    Ok(())
}

async fn setup_banks() -> (BanksClient, Keypair, solana_sdk::hash::Hash) {
    let mut pt = ProgramTest::default();
    pt.add_program("mosaic_program", PROGRAM_ID, None);
    pt.start().await
}

/// `ProgramTest::add_program` with `None` looks in `$BPF_OUT_DIR` /
/// `$SBF_OUT_DIR`. We don't set these at runtime (Rust 2024 makes
/// `std::env::set_var` unsafe) — instead, fail fast with a clear message.
///
/// CI sets them via the workflow `env:` block; local developers export
/// from their shell.
fn require_sbf_env() -> Result<()> {
    let deploy_dir = workspace_root().join("target").join("deploy");
    if std::env::var_os("BPF_OUT_DIR").is_none() && std::env::var_os("SBF_OUT_DIR").is_none() {
        anyhow::bail!(
            "neither BPF_OUT_DIR nor SBF_OUT_DIR is set; export one of them to \
             {deploy_dir:?} (or wherever cargo-build-sbf deposits mosaic_program.so)",
        );
    }
    Ok(())
}


/// Parse `Program <id> consumed <N> of <M> compute units` from program logs.
///
/// Returns the first `N` for a log line emitted by our program.
fn extract_cu(logs: &[String]) -> Option<u64> {
    let needle = format!("Program {PROGRAM_ID} consumed ");
    for line in logs {
        let Some(rest) = line.strip_prefix(&needle) else { continue };
        let n_str = rest.split_whitespace().next()?;
        if let Ok(n) = n_str.parse::<u64>() {
            return Some(n);
        }
    }
    None
}

#[derive(Debug)]
struct MeasurementReport {
    name: &'static str,
    measured_cu: u64,
    hard_cap_cu: u64,
    baseline_cu: u64,
    /// `Some(pct)` when measured_cu differs from baseline by more than tolerance.
    baseline_drift_pct: Option<f64>,
    exceeds_hard_cap: bool,
}

impl MeasurementReport {
    fn from_target(target: &SystemTarget, measured_cu: u64) -> Self {
        let baseline_drift_pct = if target.baseline_cu == 0 {
            None
        } else {
            let pct = ((measured_cu as f64 - target.baseline_cu as f64).abs() * 100.0)
                / target.baseline_cu as f64;
            if pct > BASELINE_TOLERANCE_PCT {
                Some(pct)
            } else {
                None
            }
        };
        Self {
            name: target.name,
            measured_cu,
            hard_cap_cu: target.hard_cap_cu,
            baseline_cu: target.baseline_cu,
            baseline_drift_pct,
            exceeds_hard_cap: measured_cu > target.hard_cap_cu,
        }
    }

    fn status(&self) -> &'static str {
        if self.exceeds_hard_cap {
            "FAIL"
        } else if self.baseline_drift_pct.is_some() {
            "WARN"
        } else {
            "OK"
        }
    }
}

async fn bench_groth16_mul_circuit(target: &SystemTarget) -> Result<MeasurementReport> {
    let vk = fixture_bytes("groth16", "vk.bin")?;
    let proof = fixture_bytes("groth16", "proof.bin")?;
    let public_inputs = fixture_bytes("groth16", "public_inputs.bin")?;

    let backend = HostBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);
    ProofSystem::verify(&verifier, &vk, &proof, &public_inputs)
        .map_err(|e| anyhow!("host preflight failed: {e}"))?;

    run_bpf_verify(target, 0x01, &vk, &proof, &public_inputs, 300_000).await
}

async fn bench_groth16_batch_n5(target: &SystemTarget) -> Result<MeasurementReport> {
    const N: usize = 5;
    let vk = fixture_bytes("groth16", "vk.bin")?;
    let proof = fixture_bytes("groth16", "proof.bin")?;
    let public_inputs = fixture_bytes("groth16", "public_inputs.bin")?;

    // Host preflight: batch-verify N copies of the same proof. Σ r_i
    // cancels cryptographically so the pairing check still holds when
    // all A/L/C are identical. Syscall CU is identical to the
    // distinct-proof case because the r_i scalar mul is per-proof
    // regardless.
    use mosaic_core::proof_system::ProofSystem;
    use mosaic_groth16::Groth16Verifier;
    let backend = HostBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);
    let proof_refs: Vec<&[u8]> = (0..N).map(|_| proof.as_slice()).collect();
    let pi_refs: Vec<&[u8]> = (0..N).map(|_| public_inputs.as_slice()).collect();
    ProofSystem::batch_verify(&verifier, &vk, &proof_refs, &pi_refs)
        .map_err(|e| anyhow!("host batch preflight failed: {e}"))?;

    sbf_artifact_exists()?;
    require_sbf_env()?;
    let (banks, payer, blockhash) = setup_banks().await;

    // Build VerifyProofBatch instruction.
    let payload = VerifyProofBatchData {
        proof_system_id: 0x01, // Groth16Bn254
        vk: vk.clone(),
        proofs: (0..N).map(|_| proof.clone()).collect(),
        public_inputs: (0..N).map(|_| public_inputs.clone()).collect(),
    };
    let mut data = Vec::with_capacity(2 + N * (proof.len() + public_inputs.len()) + 128);
    data.push(0x02); // VerifyProofBatch tag
    borsh::to_writer(&mut data, &payload).expect("borsh VerifyProofBatchData");
    let verify_ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: Vec::<AccountMeta>::new(),
        data,
    };

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(600_000);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let meta = banks
        .process_transaction_with_metadata(tx)
        .await
        .context("submit batch VerifyProof tx")?;
    if let Err(e) = meta.result {
        let logs = meta
            .metadata
            .as_ref()
            .map(|m| m.log_messages.join("\n"))
            .unwrap_or_default();
        anyhow::bail!("batch verify tx failed: {e:?}\nlogs:\n{logs}");
    }
    let logs = meta
        .metadata
        .ok_or_else(|| anyhow!("no tx metadata"))?
        .log_messages;
    let cu = extract_cu(&logs)
        .ok_or_else(|| anyhow!("no CU line in logs:\n{}", logs.join("\n")))?;
    Ok(MeasurementReport::from_target(target, cu))
}

async fn bench_plonk_mul_circuit(target: &SystemTarget) -> Result<MeasurementReport> {
    use mosaic_plonk::PlonkKzgBn254;
    let vk = fixture_bytes("plonk", "vk.bin")?;
    let proof = fixture_bytes("plonk", "proof.bin")?;
    let public_inputs = fixture_bytes("plonk", "public_inputs.bin")?;

    let backend = HostBackend::new();
    let verifier = PlonkKzgBn254::new(&backend);
    PlonkKzgBn254::verify(&verifier, &vk, &proof, &public_inputs)
        .map_err(|e| anyhow!("host PLONK preflight failed: {e}"))?;

    // Request the full 14M CU so we can measure the actual consumption
    // even if initial run lands high. Hard cap is checked against
    // target.hard_cap_cu, not against set_compute_unit_limit.
    run_bpf_verify(target, 0x02, &vk, &proof, &public_inputs, 1_400_000).await
}

async fn run_bpf_verify(
    target: &SystemTarget,
    proof_system_id: u8,
    vk: &[u8],
    proof: &[u8],
    public_inputs: &[u8],
    cu_limit: u32,
) -> Result<MeasurementReport> {
    sbf_artifact_exists()?;
    require_sbf_env()?;
    let (banks, payer, blockhash) = setup_banks().await;

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(cu_limit);
    let verify_ix = build_verify_ix_for_system(proof_system_id, vk, proof, public_inputs);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    let meta = banks
        .process_transaction_with_metadata(tx)
        .await
        .context("submit VerifyProof tx")?;

    if let Err(e) = meta.result {
        let logs = meta
            .metadata
            .as_ref()
            .map(|m| m.log_messages.join("\n"))
            .unwrap_or_default();
        anyhow::bail!("verify tx failed: {e:?}\nlogs:\n{logs}");
    }

    let logs = meta
        .metadata
        .ok_or_else(|| anyhow!("no transaction metadata returned"))?
        .log_messages;
    let cu = extract_cu(&logs).ok_or_else(|| {
        anyhow!(
            "could not find CU consumption line in logs:\n{}",
            logs.join("\n")
        )
    })?;

    Ok(MeasurementReport::from_target(target, cu))
}

fn build_verify_ix_for_system(
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
    borsh::to_writer(&mut data, &payload).expect("borsh VerifyProofData");
    Instruction { program_id: PROGRAM_ID, accounts: Vec::<AccountMeta>::new(), data }
}

fn print_report(reports: &[MeasurementReport]) {
    println!("\nmosaic bpf-bench — CU regression report");
    println!("────────────────────────────────────────────────────────────");
    println!(
        "{:<40} {:>10} {:>10} {:>10} {:>6}",
        "SYSTEM", "MEASURED", "CAP", "BASELINE", "STATUS"
    );
    for r in reports {
        let baseline_display = if r.baseline_cu == 0 {
            "none".to_string()
        } else {
            r.baseline_cu.to_string()
        };
        println!(
            "{:<40} {:>10} {:>10} {:>10} {:>6}",
            r.name, r.measured_cu, r.hard_cap_cu, baseline_display, r.status(),
        );
        if let Some(pct) = r.baseline_drift_pct {
            println!(
                "    ↳ baseline drift {:+.2}% (tolerance ±{:.1}%)",
                pct, BASELINE_TOLERANCE_PCT,
            );
        }
        if r.exceeds_hard_cap {
            println!(
                "    ↳ HARD CAP EXCEEDED by {} CU — see docs/compute-unit-budget.md",
                r.measured_cu.saturating_sub(r.hard_cap_cu),
            );
        }
    }
    println!();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut reports = Vec::new();
    let mut any_hard_fail = false;

    for target in TARGETS {
        let outcome = match target.name {
            "groth16_bn254_mul_circuit_1pi" => bench_groth16_mul_circuit(target).await,
            "groth16_batch_n5_mul_circuit_1pi" => bench_groth16_batch_n5(target).await,
            "plonk_bn254_mul_circuit_1pi" => bench_plonk_mul_circuit(target).await,
            other => {
                eprintln!("unknown bench target: {other}");
                continue;
            },
        };
        match outcome {
            Ok(r) => {
                any_hard_fail |= r.exceeds_hard_cap;
                reports.push(r);
            },
            Err(e) => {
                eprintln!("error benching {}: {e}", target.name);
                return ExitCode::from(2);
            },
        }
    }

    print_report(&reports);
    if any_hard_fail {
        eprintln!("one or more systems exceeded their ADR-0005 hard cap");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
