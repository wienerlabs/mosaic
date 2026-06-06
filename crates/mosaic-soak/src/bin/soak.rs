// mosaic-soak — devnet/testnet soak runner.
//
// Reads a config file and runs the soak loop. Writes a markdown
// report to the path declared in the config.
//
// Example config (commit alongside the report):
//
//   {
//     "rpc_url": "https://api.devnet.solana.com",
//     "program_id": "MosA1cVer1f1er11111111111111111111111111111",
//     "payer_keypair": "/Volumes/USB-VAULT/devnet-payer.json",
//     "fixtures_dir": "tests/fixtures",
//     "duration": 86400,
//     "submit_interval": 12,
//     "tampered_ratio": 0.10,
//     "report_path": "docs/devnet-soak/2026-05-13.md",
//     "cu_drift_tolerance": 0.10
//   }
//
// Run:
//
//   cargo run --release -p mosaic-soak --bin soak -- \
//     --config scripts/soak-config-devnet.json
//
// Closes part of issue #67.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::{env, fs, path::PathBuf, process::ExitCode};

use anyhow::{anyhow, Context, Result};
use mosaic_soak::{run_soak, SoakConfig};

fn print_usage() {
    eprintln!(
        "mosaic-soak — devnet/testnet soak runner

Usage:
  cargo run --release -p mosaic-soak --bin soak -- --config <path>

Options:
  --config <path>   JSON config (see docs/devnet-soak/README.md for schema)
  -h, --help        Print this message

Closes part of issue #67."
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let mut config_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                if i + 1 >= args.len() {
                    eprintln!("mosaic-soak: --config requires a path argument");
                    return ExitCode::from(1);
                }
                config_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-h" | "--help" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("mosaic-soak: unknown argument '{other}'");
                print_usage();
                return ExitCode::from(1);
            }
        }
    }
    let config_path = match config_path {
        Some(p) => p,
        None => {
            eprintln!("mosaic-soak: --config <path> required");
            print_usage();
            return ExitCode::from(1);
        }
    };

    match real_main(&config_path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mosaic-soak: {e:#}");
            ExitCode::from(2)
        }
    }
}

async fn real_main(config_path: &std::path::Path) -> Result<()> {
    let config = SoakConfig::load(config_path)
        .with_context(|| format!("loading config from {config_path:?}"))?;
    eprintln!(
        "mosaic-soak: starting — duration {} s, submit interval {} s, tampered ratio {:.2}",
        config.duration.as_secs(),
        config.submit_interval.as_secs(),
        config.tampered_ratio,
    );
    let report_path = config.report_path.clone();

    let report = run_soak(config).await?;
    let markdown = report.render_markdown();

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&report_path, markdown.as_bytes())
        .with_context(|| format!("writing report to {report_path:?}"))?;
    eprintln!("mosaic-soak: report written to {report_path:?}");

    if report.unexpected_failure > 0 {
        eprintln!(
            "mosaic-soak: ⚠ {} unexpected failure(s) — soak does NOT pass",
            report.unexpected_failure
        );
        return Err(anyhow!("soak failed: unexpected failures present"));
    }
    if !report.cu_drift_alerts.is_empty() {
        eprintln!(
            "mosaic-soak: ⚠ {} CU drift alert(s) — investigate but soak passes",
            report.cu_drift_alerts.len()
        );
    }
    eprintln!("mosaic-soak: ✓ soak run complete, no unexpected failures");
    Ok(())
}
