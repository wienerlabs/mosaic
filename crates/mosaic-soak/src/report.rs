//! Soak report — accumulator + markdown renderer.
//!
//! Keeps per-dispatch CU samples in memory; at end-of-run the runner
//! calls `render_markdown` which produces the report committed under
//! `docs/devnet-soak/`.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

/// The outcome of a single submitted transaction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Valid proof accepted (`Ok(())`).
    AcceptedValid,
    /// Tampered proof rejected with one of the documented soundness
    /// errors (`PairingCheckFailed`, `PointNotOnCurve`,
    /// `AltBn128SyscallFailed`).
    RejectedTampered,
    /// Anything else — must be investigated.
    UnexpectedFailure,
}

/// CU statistics computed at end-of-run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuStats {
    pub samples: u64,
    pub min: u64,
    pub max: u64,
    pub median: u64,
    pub p95: u64,
}

impl CuStats {
    pub fn from_samples(mut s: Vec<u64>) -> Self {
        let samples = s.len() as u64;
        if s.is_empty() {
            return Self {
                samples: 0,
                min: 0,
                max: 0,
                median: 0,
                p95: 0,
            };
        }
        s.sort_unstable();
        let min = *s.first().unwrap();
        let max = *s.last().unwrap();
        let median = s[s.len() / 2];
        let p95_idx = (s.len() as f64 * 0.95) as usize;
        let p95 = s[p95_idx.min(s.len() - 1)];
        Self {
            samples,
            min,
            max,
            median,
            p95,
        }
    }
}

/// Mosaic-bench pinned CU baselines, mirrored here so the soak
/// runner can compute drift without depending on the bench crate.
/// Update alongside any change to `mosaic-bench::TARGETS`.
pub fn pinned_baseline(dispatch_slug: &str) -> Option<u64> {
    match dispatch_slug {
        "groth16_bn254" => Some(83_574),
        "plonk_kzg_bn254" => Some(968_457),
        _ => None,
    }
}

/// In-memory soak report. The runner adds outcomes via `record_*`
/// methods; the binary calls `render_markdown` at end-of-run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakReport {
    pub started_at_unix: u64,
    pub ended_at_unix: u64,
    pub rpc_url: String,
    pub program_id: String,
    pub fixture_count: usize,
    pub total_txs: u64,
    pub accepted_valid: u64,
    pub rejected_tampered: u64,
    pub unexpected_failure: u64,
    /// Per-dispatch-slug CU samples (raw, capped at `MAX_SAMPLES` to
    /// keep memory bounded for very long runs).
    #[serde(skip)]
    pub cu_samples: BTreeMap<String, Vec<u64>>,
    /// Errors collected from failed transactions, capped to avoid
    /// unbounded growth.
    pub unexpected_failures: Vec<UnexpectedFailureRecord>,
    /// CU drift incidents (sample exceeded ±tolerance vs baseline).
    pub cu_drift_alerts: Vec<CuDriftAlert>,
}

pub const MAX_SAMPLES_PER_DISPATCH: usize = 50_000;
pub const MAX_UNEXPECTED_FAILURES: usize = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnexpectedFailureRecord {
    pub timestamp_unix: u64,
    pub tx_signature: String,
    pub error_text: String,
    /// First 200 chars of program logs, for triage in the report.
    pub logs_excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuDriftAlert {
    pub timestamp_unix: u64,
    pub dispatch_slug: String,
    pub measured_cu: u64,
    pub baseline_cu: u64,
    pub drift_pct: f64,
}

impl SoakReport {
    pub fn new(rpc_url: String, program_id: String) -> Self {
        Self {
            started_at_unix: now_unix(),
            ended_at_unix: 0,
            rpc_url,
            program_id,
            fixture_count: 0,
            total_txs: 0,
            accepted_valid: 0,
            rejected_tampered: 0,
            unexpected_failure: 0,
            cu_samples: BTreeMap::new(),
            unexpected_failures: Vec::new(),
            cu_drift_alerts: Vec::new(),
        }
    }

    pub fn record_outcome(
        &mut self,
        outcome: DispatchOutcome,
        dispatch_slug: Option<&str>,
        cu: Option<u64>,
    ) {
        self.total_txs += 1;
        match outcome {
            DispatchOutcome::AcceptedValid => self.accepted_valid += 1,
            DispatchOutcome::RejectedTampered => self.rejected_tampered += 1,
            DispatchOutcome::UnexpectedFailure => self.unexpected_failure += 1,
        }
        if let (Some(slug), Some(cu)) = (dispatch_slug, cu) {
            let bucket = self.cu_samples.entry(slug.to_string()).or_default();
            if bucket.len() < MAX_SAMPLES_PER_DISPATCH {
                bucket.push(cu);
            }
        }
    }

    pub fn record_failure(
        &mut self,
        signature: String,
        error_text: String,
        logs_excerpt: String,
    ) {
        if self.unexpected_failures.len() < MAX_UNEXPECTED_FAILURES {
            self.unexpected_failures.push(UnexpectedFailureRecord {
                timestamp_unix: now_unix(),
                tx_signature: signature,
                error_text,
                logs_excerpt,
            });
        }
    }

    pub fn record_drift_alert(
        &mut self,
        dispatch_slug: String,
        measured_cu: u64,
        baseline_cu: u64,
    ) {
        let drift_pct = ((measured_cu as f64 - baseline_cu as f64).abs() * 100.0)
            / baseline_cu as f64;
        self.cu_drift_alerts.push(CuDriftAlert {
            timestamp_unix: now_unix(),
            dispatch_slug,
            measured_cu,
            baseline_cu,
            drift_pct,
        });
    }

    pub fn finish(&mut self) {
        self.ended_at_unix = now_unix();
    }

    /// Render a markdown summary suitable for commit under
    /// `docs/devnet-soak/YYYY-MM-DD-HHMM.md`.
    pub fn render_markdown(&self) -> String {
        let duration_s = self.ended_at_unix.saturating_sub(self.started_at_unix);
        let mut out = String::new();
        out.push_str(&format!("# Mosaic devnet soak — {}\n\n", iso_date(self.started_at_unix)));
        out.push_str("Generated by `cargo run -p mosaic-soak --bin soak`.\n\n");

        out.push_str("## Run identity\n\n");
        out.push_str(&format!("| Field | Value |\n|---|---|\n"));
        out.push_str(&format!("| Started | {} |\n", iso_datetime(self.started_at_unix)));
        out.push_str(&format!("| Ended | {} |\n", iso_datetime(self.ended_at_unix)));
        out.push_str(&format!("| Duration | {} s ({:.2} h) |\n", duration_s, duration_s as f64 / 3600.0));
        out.push_str(&format!("| RPC URL | `{}` |\n", self.rpc_url));
        out.push_str(&format!("| Program ID | `{}` |\n", self.program_id));
        out.push_str(&format!("| Fixtures | {} |\n", self.fixture_count));
        out.push_str("\n");

        out.push_str("## Outcomes\n\n");
        out.push_str("| Outcome | Count | Share |\n|---|---:|---:|\n");
        let pct = |n: u64| {
            if self.total_txs == 0 {
                0.0
            } else {
                100.0 * n as f64 / self.total_txs as f64
            }
        };
        out.push_str(&format!("| Total transactions submitted | {} | 100.00% |\n", self.total_txs));
        out.push_str(&format!("| Valid proofs accepted | {} | {:.2}% |\n", self.accepted_valid, pct(self.accepted_valid)));
        out.push_str(&format!("| Tampered proofs rejected | {} | {:.2}% |\n", self.rejected_tampered, pct(self.rejected_tampered)));
        out.push_str(&format!("| Unexpected failures | {} | {:.2}% |\n", self.unexpected_failure, pct(self.unexpected_failure)));
        out.push_str("\n");

        if self.unexpected_failure == 0 {
            out.push_str("**No unexpected failures.** Soundness boundary intact across this run.\n\n");
        } else {
            out.push_str(&format!("**⚠ {} unexpected failures** — investigate before mainnet.\n\n", self.unexpected_failure));
        }

        out.push_str("## Compute-unit consumption per dispatch\n\n");
        out.push_str("| Dispatch | Samples | Min | Median | p95 | Max | Baseline | Drift |\n");
        out.push_str("|---|---:|---:|---:|---:|---:|---:|---:|\n");
        for (slug, samples) in &self.cu_samples {
            let stats = CuStats::from_samples(samples.clone());
            let baseline = pinned_baseline(slug);
            let drift_str = match baseline {
                Some(b) => {
                    let drift = ((stats.median as f64 - b as f64).abs() * 100.0) / b as f64;
                    format!("{:+.2}%", drift * (if (stats.median as i64) < b as i64 { -1.0 } else { 1.0 }))
                }
                None => "—".to_string(),
            };
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} | {} |\n",
                slug,
                stats.samples,
                stats.min,
                stats.median,
                stats.p95,
                stats.max,
                baseline.map(|b| b.to_string()).unwrap_or_else(|| "—".to_string()),
                drift_str,
            ));
        }
        out.push_str("\n");

        if !self.cu_drift_alerts.is_empty() {
            out.push_str("## CU drift alerts\n\n");
            out.push_str("Samples that exceeded the configured drift tolerance.\n\n");
            out.push_str("| Time (UTC) | Dispatch | Measured | Baseline | Drift |\n|---|---|---:|---:|---:|\n");
            for alert in &self.cu_drift_alerts {
                out.push_str(&format!(
                    "| {} | `{}` | {} | {} | {:+.2}% |\n",
                    iso_datetime(alert.timestamp_unix),
                    alert.dispatch_slug,
                    alert.measured_cu,
                    alert.baseline_cu,
                    alert.drift_pct,
                ));
            }
            out.push_str("\n");
        }

        if !self.unexpected_failures.is_empty() {
            out.push_str("## Unexpected failures\n\n");
            for (i, f) in self.unexpected_failures.iter().enumerate() {
                out.push_str(&format!(
                    "### Failure {} — {} UTC\n\n",
                    i + 1,
                    iso_datetime(f.timestamp_unix)
                ));
                out.push_str(&format!("- Signature: `{}`\n", f.tx_signature));
                out.push_str(&format!("- Error: `{}`\n\n", f.error_text));
                out.push_str("Logs excerpt:\n\n```\n");
                out.push_str(&f.logs_excerpt);
                out.push_str("\n```\n\n");
            }
        }

        out.push_str("---\n\n");
        out.push_str("Report schema v1. Generated by `mosaic-soak` per issue #67.\n");
        out
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn iso_date(unix: u64) -> String {
    let (y, m, d, _, _, _) = unix_to_ymdhms(unix as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

fn iso_datetime(unix: u64) -> String {
    let (y, mo, d, h, mi, s) = unix_to_ymdhms(unix as i64);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

// Same minimal UTC formatter as mosaic-demo-sudoku's generate-fixtures.
fn unix_to_ymdhms(mut secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let s = secs.rem_euclid(60) as u32;
    secs = secs.div_euclid(60);
    let mi = secs.rem_euclid(60) as u32;
    secs = secs.div_euclid(60);
    let h = secs.rem_euclid(24) as u32;
    let mut days = secs.div_euclid(24);
    let mut year = 1970i32;
    loop {
        let leap = is_leap(year);
        let yd = if leap { 366 } else { 365 };
        if days < yd {
            break;
        }
        days -= yd;
        year += 1;
    }
    let mdays = if is_leap(year) {
        [31u32, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut day_in_year = days as u32;
    for (i, dim) in mdays.iter().enumerate() {
        if day_in_year < *dim {
            return (year, (i + 1) as u32, day_in_year + 1, h, mi, s);
        }
        day_in_year -= dim;
    }
    (year, 12, day_in_year + 1, h, mi, s)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
