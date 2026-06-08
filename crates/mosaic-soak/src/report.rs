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
    // Mirrors `mosaic-bench::TARGETS` baselines. Re-measured 2026-06-06
    // on the borsh-1.5.7 / platform-tools v1.52 SBF build via
    // `cargo run -p mosaic-bench --bin bpf-bench`.
    match dispatch_slug {
        "groth16_bn254" => Some(84_027),
        "plonk_kzg_bn254" => Some(973_388),
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

    /// Render the soak result in Prometheus text exposition format for
    /// ingestion by Grafana / Datadog / any Prometheus-compatible
    /// scraper (issue #85). The runner writes this alongside the
    /// markdown report; an agent textfile-collector or push-gateway
    /// surfaces it on the observability stack.
    ///
    /// The load-bearing metric is `mosaic_soak_unexpected_failure_total`:
    /// alert when it is `> 0` (the soak's pass/fail gate). CU gauges per
    /// dispatch plus the pinned baseline let a dashboard plot measured
    /// vs baseline and fire on drift.
    pub fn render_prometheus(&self) -> String {
        let duration_s = self.ended_at_unix.saturating_sub(self.started_at_unix);
        let mut out = String::new();
        let mut metric = |name: &str, help: &str, kind: &str, value: u64| {
            out.push_str(&format!("# HELP {name} {help}\n"));
            out.push_str(&format!("# TYPE {name} {kind}\n"));
            out.push_str(&format!("{name} {value}\n"));
        };

        metric(
            "mosaic_soak_total_txs",
            "Total transactions submitted during the soak.",
            "counter",
            self.total_txs,
        );
        metric(
            "mosaic_soak_accepted_valid_total",
            "Valid proofs accepted on chain.",
            "counter",
            self.accepted_valid,
        );
        metric(
            "mosaic_soak_rejected_tampered_total",
            "Tampered proofs correctly rejected with a documented soundness error.",
            "counter",
            self.rejected_tampered,
        );
        metric(
            "mosaic_soak_unexpected_failure_total",
            "Outcomes that were neither a valid accept nor a documented tampered reject. ALERT WHEN > 0.",
            "counter",
            self.unexpected_failure,
        );
        metric(
            "mosaic_soak_duration_seconds",
            "Wall-clock duration of the soak run.",
            "gauge",
            duration_s,
        );
        metric(
            "mosaic_soak_cu_drift_alerts_total",
            "CU samples that exceeded the configured drift tolerance vs the pinned baseline.",
            "counter",
            self.cu_drift_alerts.len() as u64,
        );

        // Per-dispatch CU gauges + the pinned baseline, labelled by slug.
        out.push_str("# HELP mosaic_soak_cu Compute units per dispatch (min/median/p95/max + baseline).\n");
        out.push_str("# TYPE mosaic_soak_cu gauge\n");
        for (slug, samples) in &self.cu_samples {
            let stats = CuStats::from_samples(samples.clone());
            for (stat, v) in [
                ("min", stats.min),
                ("median", stats.median),
                ("p95", stats.p95),
                ("max", stats.max),
                ("samples", stats.samples),
            ] {
                out.push_str(&format!(
                    "mosaic_soak_cu{{dispatch=\"{slug}\",stat=\"{stat}\"}} {v}\n"
                ));
            }
            if let Some(baseline) = pinned_baseline(slug) {
                out.push_str(&format!(
                    "mosaic_soak_cu{{dispatch=\"{slug}\",stat=\"baseline\"}} {baseline}\n"
                ));
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cu_stats_empty_returns_zeroes() {
        let stats = CuStats::from_samples(vec![]);
        assert_eq!(stats.samples, 0);
        assert_eq!(stats.min, 0);
        assert_eq!(stats.max, 0);
        assert_eq!(stats.median, 0);
        assert_eq!(stats.p95, 0);
    }

    #[test]
    fn cu_stats_single_sample() {
        let stats = CuStats::from_samples(vec![83_574]);
        assert_eq!(stats.samples, 1);
        assert_eq!(stats.min, 83_574);
        assert_eq!(stats.max, 83_574);
        assert_eq!(stats.median, 83_574);
        assert_eq!(stats.p95, 83_574);
    }

    #[test]
    fn cu_stats_unsorted_input_is_handled() {
        let stats = CuStats::from_samples(vec![100, 50, 200, 75, 150]);
        assert_eq!(stats.samples, 5);
        assert_eq!(stats.min, 50);
        assert_eq!(stats.max, 200);
        // 5 samples sorted: [50, 75, 100, 150, 200]; median index 2 -> 100
        assert_eq!(stats.median, 100);
    }

    #[test]
    fn cu_stats_p95_clamps_to_last_index() {
        // With 20 samples 0..=19, p95 index = (20 * 0.95).floor() = 19,
        // which is the last index, so p95 = 19.
        let s: Vec<u64> = (0..20).collect();
        let stats = CuStats::from_samples(s);
        assert_eq!(stats.p95, 19);
    }

    #[test]
    fn pinned_baseline_known_systems() {
        assert_eq!(pinned_baseline("groth16_bn254"), Some(84_027));
        assert_eq!(pinned_baseline("plonk_kzg_bn254"), Some(973_388));
        assert_eq!(pinned_baseline("unknown_system"), None);
    }

    #[test]
    fn record_outcome_increments_correct_counter() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        report.record_outcome(DispatchOutcome::AcceptedValid, Some("groth16_bn254"), Some(80_000));
        report.record_outcome(DispatchOutcome::RejectedTampered, None, None);
        report.record_outcome(DispatchOutcome::UnexpectedFailure, None, None);
        assert_eq!(report.total_txs, 3);
        assert_eq!(report.accepted_valid, 1);
        assert_eq!(report.rejected_tampered, 1);
        assert_eq!(report.unexpected_failure, 1);
        assert_eq!(report.cu_samples.get("groth16_bn254").map(|s| s.len()), Some(1));
    }

    #[test]
    fn record_outcome_caps_cu_samples_at_max() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        // Push MAX + 5 samples; bucket should stop at MAX.
        for i in 0..(MAX_SAMPLES_PER_DISPATCH + 5) {
            report.record_outcome(
                DispatchOutcome::AcceptedValid,
                Some("groth16_bn254"),
                Some(i as u64),
            );
        }
        let bucket = report.cu_samples.get("groth16_bn254").unwrap();
        assert_eq!(bucket.len(), MAX_SAMPLES_PER_DISPATCH);
        // First sample preserved, last 5 dropped.
        assert_eq!(bucket[0], 0);
    }

    #[test]
    fn record_failure_caps_at_max_unexpected_failures() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        for i in 0..(MAX_UNEXPECTED_FAILURES + 10) {
            report.record_failure(
                format!("sig{i}"),
                format!("err{i}"),
                format!("logs{i}"),
            );
        }
        assert_eq!(report.unexpected_failures.len(), MAX_UNEXPECTED_FAILURES);
    }

    #[test]
    fn record_drift_alert_computes_correct_drift_pct() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        // baseline 100, measured 110 -> +10% drift
        report.record_drift_alert("test".into(), 110, 100);
        assert_eq!(report.cu_drift_alerts.len(), 1);
        let alert = &report.cu_drift_alerts[0];
        assert_eq!(alert.dispatch_slug, "test");
        assert_eq!(alert.measured_cu, 110);
        assert_eq!(alert.baseline_cu, 100);
        assert!((alert.drift_pct - 10.0).abs() < 1e-9);
    }

    #[test]
    fn record_drift_alert_absolute_value_for_negative_drift() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        // baseline 100, measured 90 -> drift magnitude 10%
        report.record_drift_alert("test".into(), 90, 100);
        let alert = &report.cu_drift_alerts[0];
        assert!((alert.drift_pct - 10.0).abs() < 1e-9);
    }

    #[test]
    fn render_markdown_contains_all_required_sections() {
        let mut report = SoakReport::new(
            "https://api.devnet.solana.com".into(),
            "MosA1cVer1f1er11111111111111111111111111111".into(),
        );
        report.fixture_count = 2;
        report.record_outcome(DispatchOutcome::AcceptedValid, Some("groth16_bn254"), Some(83_500));
        report.record_outcome(DispatchOutcome::RejectedTampered, None, None);
        report.finish();

        let md = report.render_markdown();
        // Header
        assert!(md.starts_with("# Mosaic devnet soak"));
        // Sections
        assert!(md.contains("## Run identity"));
        assert!(md.contains("## Outcomes"));
        assert!(md.contains("## Compute-unit consumption per dispatch"));
        // Run identity payload
        assert!(md.contains("https://api.devnet.solana.com"));
        assert!(md.contains("MosA1cVer1f1er11111111111111111111111111111"));
        // Outcome counts present
        assert!(md.contains("| Total transactions submitted | 2 |"));
        assert!(md.contains("| Valid proofs accepted | 1 |"));
        assert!(md.contains("| Tampered proofs rejected | 1 |"));
        // Compute table includes the groth16 row + baseline column
        assert!(md.contains("`groth16_bn254`"));
        assert!(md.contains("84027"));
        // Schema footer
        assert!(md.contains("Report schema v1"));
    }

    #[test]
    fn render_markdown_flags_unexpected_failures() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        report.record_outcome(DispatchOutcome::UnexpectedFailure, None, None);
        report.record_failure(
            "abc123".into(),
            "Custom(0xdeadbeef)".into(),
            "Program log: oops".into(),
        );
        report.finish();
        let md = report.render_markdown();
        assert!(md.contains("unexpected failures"));
        assert!(md.contains("abc123"));
        assert!(md.contains("Custom(0xdeadbeef)"));
    }

    #[test]
    fn render_markdown_clean_run_shows_soundness_intact() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        report.record_outcome(DispatchOutcome::AcceptedValid, None, None);
        report.finish();
        let md = report.render_markdown();
        assert!(md.contains("Soundness boundary intact"));
    }

    #[test]
    fn render_prometheus_emits_key_metrics() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        report.record_outcome(DispatchOutcome::AcceptedValid, Some("groth16_bn254"), Some(84_100));
        report.record_outcome(DispatchOutcome::RejectedTampered, None, None);
        report.record_outcome(DispatchOutcome::UnexpectedFailure, None, None);
        report.record_drift_alert("groth16_bn254".into(), 100_000, 84_027);
        report.finish();
        let p = report.render_prometheus();

        // Valid Prometheus exposition: every metric has HELP + TYPE.
        assert_eq!(
            p.matches("# HELP ").count(),
            p.matches("# TYPE ").count()
        );
        assert!(p.contains("mosaic_soak_total_txs 3"));
        assert!(p.contains("mosaic_soak_accepted_valid_total 1"));
        assert!(p.contains("mosaic_soak_rejected_tampered_total 1"));
        // The load-bearing alerting metric.
        assert!(p.contains("mosaic_soak_unexpected_failure_total 1"));
        assert!(p.contains("mosaic_soak_cu_drift_alerts_total 1"));
        // Per-dispatch CU gauge + baseline, labelled by slug.
        assert!(p.contains("mosaic_soak_cu{dispatch=\"groth16_bn254\",stat=\"median\"} 84100"));
        assert!(p.contains("mosaic_soak_cu{dispatch=\"groth16_bn254\",stat=\"baseline\"} 84027"));
    }

    #[test]
    fn render_markdown_includes_drift_section_when_alerts_present() {
        let mut report = SoakReport::new("rpc".into(), "prog".into());
        report.record_drift_alert("groth16_bn254".into(), 100_000, 83_574);
        report.finish();
        let md = report.render_markdown();
        assert!(md.contains("## CU drift alerts"));
        assert!(md.contains("groth16_bn254"));
        assert!(md.contains("100000"));
        assert!(md.contains("83574"));
    }

    #[test]
    fn unix_to_ymdhms_known_epoch() {
        // 2026-01-01 00:00:00 UTC = 1_767_225_600
        let (y, m, d, h, mi, s) = unix_to_ymdhms(1_767_225_600);
        assert_eq!((y, m, d, h, mi, s), (2026, 1, 1, 0, 0, 0));
    }

    #[test]
    fn unix_to_ymdhms_leap_year_handling() {
        // 2024-02-29 00:00:00 UTC = 1_709_164_800
        // (sanity-checked: 1704067200 + 59*86400 = 1709164800)
        let (y, m, d, h, mi, s) = unix_to_ymdhms(1_709_164_800);
        assert_eq!((y, m, d, h, mi, s), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn is_leap_year_rules() {
        assert!(is_leap(2024)); // divisible by 4
        assert!(!is_leap(2023));
        assert!(!is_leap(2100)); // divisible by 100 but not 400
        assert!(is_leap(2000)); // divisible by 400
    }
}
