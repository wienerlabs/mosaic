//! # mosaic-soak
//!
//! Devnet / testnet soak-test harness for `mosaic-program`.
//!
//! Submits `VerifyProof` transactions to a deployed Mosaic program
//! at a controlled rate, captures per-tx outcome + compute-unit
//! consumption from RPC logs, and writes a markdown report.
//!
//! Tracks issue [#67](https://github.com/wienerlabs/labs/mosaic/issues/67).
//!
//! ## Design
//!
//! The harness is intentionally simple:
//!
//! - **Synchronous submit loop** — one transaction at a time, signed
//!   by the configured payer keypair. We do not pipeline because the
//!   soak's purpose is to surface divergence over wall-clock time, not
//!   maximise throughput.
//!
//! - **Mixed valid/tampered traffic** — every Nth transaction has its
//!   first proof byte's low bit flipped (`tampered_ratio`). Valid txs
//!   must succeed; tampered txs must fail with one of
//!   `PairingCheckFailed` / `PointNotOnCurve` / `AltBn128SyscallFailed`.
//!   Anything else is an unexpected-failure event and gets logged.
//!
//! - **CU regression alerts** — each verifier dispatch's CU is
//!   compared against a baseline (from `mosaic-bench::bpf_bench::TARGETS`)
//!   and a `±10 %` drift triggers a WARN line in the report.
//!
//! - **Markdown report** — written to a configurable path at the end
//!   of the run. The format mirrors what we'd commit to
//!   `docs/devnet-soak/YYYY-MM-DD-HHMM.md` as a record.
//!
//! ## What this crate is NOT
//!
//! - It is not a load tester. No throughput tuning, no concurrent
//!   client connections, no rate-limit handling beyond a sleep.
//! - It does not deploy the program. Use `scripts/deploy-devnet.sh`
//!   for that; this harness assumes the program is already deployed
//!   and accepts a `PROGRAM_ID` via config.
//! - It does not validate the deployed bytecode SHA. That guard
//!   lives in `scripts/deploy-mainnet.sh`. Soak runs against
//!   whatever is on chain at the configured `PROGRAM_ID`.

#![forbid(unsafe_code)]

pub mod config;
pub mod report;
pub mod runner;

pub use config::SoakConfig;
pub use report::{CuStats, DispatchOutcome, SoakReport};
pub use runner::run_soak;
