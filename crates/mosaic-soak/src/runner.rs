//! Soak runner — submit loop + RPC interaction.

use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use borsh::BorshSerialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::{
    commitment_config::{CommitmentConfig, CommitmentLevel},
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use solana_transaction_status_client_types::UiTransactionEncoding;

use crate::{
    config::SoakConfig,
    report::{pinned_baseline, DispatchOutcome, SoakReport},
};

/// Borsh layout — must match `mosaic_program::VerifyProofData`.
#[derive(BorshSerialize)]
struct VerifyProofData {
    proof_system_id: u8,
    vk: Vec<u8>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

/// Discovered fixture set on disk.
#[derive(Debug, Clone)]
struct Fixture {
    /// Slug used in the dispatch log line; pinned-baseline lookups
    /// key on this string.
    dispatch_slug: String,
    /// `ProofSystemId` byte (see `mosaic_core::proof_system`).
    proof_system_id: u8,
    vk: Vec<u8>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

/// Walk `fixtures_dir/<system>/<circuit>/canonical/{vk,proof,public_inputs}.bin`
/// and load every set that matches the layout.
fn discover_fixtures(dir: &Path) -> Result<Vec<Fixture>> {
    let mut out = Vec::new();
    let known: &[(&str, u8, &str)] = &[
        ("groth16", 0x01, "groth16_bn254"),
        ("plonk", 0x02, "plonk_kzg_bn254"),
    ];
    for (subdir, id, slug) in known {
        let root = dir.join(subdir);
        if !root.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&root)
            .with_context(|| format!("reading {root:?}"))?
        {
            let entry = entry?;
            let canonical = entry.path().join("canonical");
            let vk_path = canonical.join("vk.bin");
            let proof_path = canonical.join("proof.bin");
            let pi_path = canonical.join("public_inputs.bin");
            if !vk_path.exists() || !proof_path.exists() || !pi_path.exists() {
                continue;
            }
            out.push(Fixture {
                dispatch_slug: slug.to_string(),
                proof_system_id: *id,
                vk: fs::read(&vk_path)?,
                proof: fs::read(&proof_path)?,
                public_inputs: fs::read(&pi_path)?,
            });
        }
    }
    if out.is_empty() {
        anyhow::bail!(
            "no fixtures found under {dir:?}. Expected layout: \
             <system>/<circuit>/canonical/{{vk,proof,public_inputs}}.bin"
        );
    }
    Ok(out)
}

fn build_verify_proof_ix(
    program_id: &Pubkey,
    fixture: &Fixture,
    tampered: bool,
) -> Instruction {
    let mut proof = fixture.proof.clone();
    if tampered && !proof.is_empty() {
        proof[0] ^= 0x01;
    }
    let payload = VerifyProofData {
        proof_system_id: fixture.proof_system_id,
        vk: fixture.vk.clone(),
        proof,
        public_inputs: fixture.public_inputs.clone(),
    };
    let mut data = Vec::with_capacity(
        1 + 1 + fixture.vk.len() + fixture.proof.len() + fixture.public_inputs.len() + 16,
    );
    data.push(0x01); // InstructionTag::VerifyProof
    borsh::to_writer(&mut data, &payload).expect("borsh VerifyProofData");
    Instruction {
        program_id: *program_id,
        accounts: Vec::<AccountMeta>::new(),
        data,
    }
}

fn extract_cu(logs: &[String], program_id: &Pubkey) -> Option<u64> {
    let needle = format!("Program {program_id} consumed ");
    logs.iter()
        .filter_map(|l| l.strip_prefix(&needle))
        .filter_map(|r| r.split_whitespace().next())
        .filter_map(|n| n.parse::<u64>().ok())
        .next()
}

fn extract_dispatch_slug(logs: &[String]) -> Option<String> {
    for l in logs {
        if let Some(rest) = l.strip_prefix("Program log: mosaic: dispatch ") {
            // first token after "dispatch" is the slug
            return Some(rest.split_whitespace().next()?.to_string());
        }
        if let Some(rest) = l.strip_prefix("Program log: mosaic: dispatch_compressed ") {
            return Some(rest.split_whitespace().next()?.to_string());
        }
    }
    None
}

fn looks_like_documented_soundness_error(err_text: &str) -> bool {
    // OnChainError::PairingCheckFailed = 0x20 = Custom(32)
    // OnChainError::PointNotOnCurve = 0x06 = Custom(6)
    // OnChainError::AltBn128SyscallFailed = 0x40 = Custom(64)
    err_text.contains("Custom(32)")
        || err_text.contains("0x20")
        || err_text.contains("Custom(64)")
        || err_text.contains("0x40")
        || err_text.contains("Custom(6)")
        || err_text.contains("0x6")
}

/// Run a soak test against the configured RPC + program.
pub async fn run_soak(cfg: SoakConfig) -> Result<SoakReport> {
    let fixtures = discover_fixtures(&cfg.fixtures_dir)?;
    eprintln!("mosaic-soak: discovered {} fixture(s)", fixtures.len());
    for f in &fixtures {
        eprintln!(
            "  {} ({:#04x}) vk={} B proof={} B pi={} B",
            f.dispatch_slug,
            f.proof_system_id,
            f.vk.len(),
            f.proof.len(),
            f.public_inputs.len(),
        );
    }

    let payer = read_keypair_file(&cfg.payer_keypair).map_err(|e| {
        anyhow!(
            "failed to read payer keypair from {:?}: {e}",
            cfg.payer_keypair
        )
    })?;
    eprintln!("mosaic-soak: payer pubkey {}", payer.pubkey());

    let rpc = RpcClient::new_with_commitment(cfg.rpc_url.clone(), CommitmentConfig::confirmed());
    let balance = rpc
        .get_balance(&payer.pubkey())
        .await
        .context("get payer balance")?;
    eprintln!(
        "mosaic-soak: payer balance {} SOL (raw {} lamports)",
        balance as f64 / 1e9,
        balance,
    );
    if balance == 0 {
        anyhow::bail!(
            "payer balance is zero. Airdrop with `solana airdrop 5 {} --url {}`",
            payer.pubkey(),
            cfg.rpc_url
        );
    }

    let mut report = SoakReport::new(cfg.rpc_url.clone(), cfg.program_id.to_string());
    report.fixture_count = fixtures.len();

    let start = Instant::now();
    let mut tx_count = 0u64;
    let mut fixture_idx = 0usize;
    let mut last_status_print = Instant::now();

    while start.elapsed() < cfg.duration {
        let fixture = &fixtures[fixture_idx % fixtures.len()];
        fixture_idx += 1;
        tx_count += 1;

        // Decide tampered vs valid based on tx_count and ratio. We
        // use modulo arithmetic instead of a PRNG so a re-run with
        // the same fixture order produces the same valid/tampered
        // sequence — useful for debugging divergence.
        let tampered = (tx_count as f64 / (1.0 / cfg.tampered_ratio).max(1.0)).floor() as u64
            != ((tx_count - 1) as f64 / (1.0 / cfg.tampered_ratio).max(1.0)).floor() as u64;

        let cu_budget = match fixture.proof_system_id {
            0x01 => 200_000, // Groth16
            0x02 => 1_200_000, // PLONK
            _ => 400_000,
        };

        let blockhash = match rpc.get_latest_blockhash().await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("mosaic-soak: get_latest_blockhash failed: {e}");
                tokio::time::sleep(cfg.submit_interval).await;
                continue;
            }
        };

        let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(cu_budget);
        let verify_ix = build_verify_proof_ix(&cfg.program_id, fixture, tampered);
        let tx = Transaction::new_signed_with_payer(
            &[cu_ix, verify_ix],
            Some(&payer.pubkey()),
            &[&payer],
            blockhash,
        );

        match rpc.send_and_confirm_transaction(&tx).await {
            Ok(sig) => {
                // Confirmed tx — fetch logs via the configured
                // encoding helper. We use `Json` because the log
                // extraction below indexes into `meta.log_messages`.
                let detail = rpc
                    .get_transaction_with_config(
                        &sig,
                        RpcTransactionConfig {
                            encoding: Some(UiTransactionEncoding::Json),
                            commitment: Some(CommitmentConfig {
                                commitment: CommitmentLevel::Confirmed,
                            }),
                            max_supported_transaction_version: Some(0),
                        },
                    )
                    .await;
                let logs: Vec<String> = match detail {
                    Ok(t) => t
                        .transaction
                        .meta
                        .and_then(|m| Option::<Vec<String>>::from(m.log_messages))
                        .unwrap_or_default(),
                    Err(_) => Vec::new(),
                };
                let dispatch_slug = extract_dispatch_slug(&logs);
                let cu = extract_cu(&logs, &cfg.program_id);
                if tampered {
                    // We expected rejection. send_and_confirm OK = unexpected accept!
                    report.record_outcome(
                        DispatchOutcome::UnexpectedFailure,
                        dispatch_slug.as_deref(),
                        cu,
                    );
                    report.record_failure(
                        sig.to_string(),
                        "tampered tx unexpectedly accepted".to_string(),
                        logs.join("\n").chars().take(200).collect(),
                    );
                } else {
                    report.record_outcome(
                        DispatchOutcome::AcceptedValid,
                        dispatch_slug.as_deref(),
                        cu,
                    );
                    if let (Some(slug), Some(measured)) = (dispatch_slug.as_deref(), cu) {
                        if let Some(baseline) = pinned_baseline(slug) {
                            let drift_pct = ((measured as f64 - baseline as f64).abs() * 100.0)
                                / baseline as f64;
                            if drift_pct > cfg.cu_drift_tolerance * 100.0 {
                                report.record_drift_alert(slug.to_string(), measured, baseline);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                let err_text = format!("{e:?}");
                if tampered && looks_like_documented_soundness_error(&err_text) {
                    report.record_outcome(DispatchOutcome::RejectedTampered, None, None);
                } else {
                    report.record_outcome(DispatchOutcome::UnexpectedFailure, None, None);
                    report.record_failure(
                        "—".to_string(),
                        err_text,
                        "(rpc-side failure; no logs available)".to_string(),
                    );
                }
            }
        }

        if last_status_print.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "mosaic-soak: progress — {} txs · {} accepted · {} rejected · {} unexpected · {} elapsed",
                report.total_txs,
                report.accepted_valid,
                report.rejected_tampered,
                report.unexpected_failure,
                format_duration(start.elapsed()),
            );
            last_status_print = Instant::now();
        }

        tokio::time::sleep(cfg.submit_interval).await;
    }

    report.finish();
    Ok(report)
}

fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{}s", s / 60, s % 60)
    } else {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    }
}
