//! Soak runner configuration.
//!
//! The config is JSON-loadable so an operator can commit a stable
//! `soak-config.json` alongside the soak report. The keypair is
//! always loaded from a file path (never inline JSON) so the same
//! config can be re-used across runs without leaking secrets into
//! version control.

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;

/// Top-level soak configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakConfig {
    /// JSON-RPC endpoint, e.g.
    /// `"https://api.devnet.solana.com"` or
    /// `"https://api.testnet.solana.com"`.
    pub rpc_url: String,

    /// Deployed Mosaic program ID on this cluster. Serialized as
    /// base-58 to match the `solana-keygen pubkey` output format.
    #[serde(with = "pubkey_base58")]
    pub program_id: Pubkey,

    /// Path to the payer keypair JSON. The payer funds tx fees and
    /// rent for the soak run. Must contain enough SOL for
    /// `duration / submit_interval` transactions at the cluster's
    /// fee schedule.
    pub payer_keypair: PathBuf,

    /// Where to read `vk.bin` / `proof.bin` / `public_inputs.bin`
    /// fixtures from. The runner sweeps every subdirectory of this
    /// path that contains all three artifacts.
    pub fixtures_dir: PathBuf,

    /// Wall-clock duration the soak runs for. Common values are
    /// 24 h (`86_400 s`) for the pre-mainnet gate or 1 h (`3_600 s`)
    /// for smoke tests.
    #[serde(with = "duration_seconds")]
    pub duration: Duration,

    /// Time between transaction submissions. Lower = higher RPC
    /// load; higher = lower divergence-detection resolution. 12 s
    /// is the Solana slot duration, a reasonable default.
    #[serde(with = "duration_seconds")]
    pub submit_interval: Duration,

    /// Fraction of submissions that should be tampered (low bit of
    /// proof byte 0 flipped). The runner must observe that **every**
    /// tampered tx rejects with one of the documented soundness
    /// errors. Anything else is logged as `unexpected_failure`.
    ///
    /// Recommended: `0.10` (10 %) for pre-audit soak runs.
    pub tampered_ratio: f64,

    /// Where to write the markdown soak report at end-of-run.
    pub report_path: PathBuf,

    /// CU drift tolerance against `mosaic-bench` pinned baselines.
    /// Default `0.10` (±10 %). A measured CU outside this window
    /// triggers a WARN line in the per-dispatch summary.
    pub cu_drift_tolerance: f64,
}

impl SoakConfig {
    /// Load from a JSON config file.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }
}

mod pubkey_base58 {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    pub fn serialize<S: Serializer>(p: &Pubkey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&p.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Pubkey, D::Error> {
        let s = String::deserialize(d)?;
        Pubkey::from_str(&s).map_err(D::Error::custom)
    }
}

mod duration_seconds {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JSON: &str = r#"{
        "rpc_url": "https://api.devnet.solana.com",
        "program_id": "MosA1cVer1f1er11111111111111111111111111111",
        "payer_keypair": "/tmp/payer.json",
        "fixtures_dir": "tests/fixtures",
        "duration": 86400,
        "submit_interval": 12,
        "tampered_ratio": 0.10,
        "report_path": "docs/devnet-soak/2026-06-06.md",
        "cu_drift_tolerance": 0.10
    }"#;

    #[test]
    fn parses_canonical_json_shape() {
        let cfg: SoakConfig = serde_json::from_str(SAMPLE_JSON).expect("parse");
        assert_eq!(cfg.rpc_url, "https://api.devnet.solana.com");
        assert_eq!(
            cfg.program_id.to_string(),
            "MosA1cVer1f1er11111111111111111111111111111"
        );
        assert_eq!(cfg.payer_keypair, PathBuf::from("/tmp/payer.json"));
        assert_eq!(cfg.fixtures_dir, PathBuf::from("tests/fixtures"));
        assert_eq!(cfg.duration, Duration::from_secs(86_400));
        assert_eq!(cfg.submit_interval, Duration::from_secs(12));
        assert!((cfg.tampered_ratio - 0.10).abs() < 1e-9);
        assert!((cfg.cu_drift_tolerance - 0.10).abs() < 1e-9);
    }

    #[test]
    fn roundtrips_through_serde() {
        let cfg: SoakConfig = serde_json::from_str(SAMPLE_JSON).unwrap();
        let serialized = serde_json::to_string(&cfg).unwrap();
        let cfg2: SoakConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(cfg.rpc_url, cfg2.rpc_url);
        assert_eq!(cfg.program_id, cfg2.program_id);
        assert_eq!(cfg.duration, cfg2.duration);
        assert_eq!(cfg.submit_interval, cfg2.submit_interval);
    }

    #[test]
    fn rejects_invalid_program_id() {
        let bad = SAMPLE_JSON.replace(
            "MosA1cVer1f1er11111111111111111111111111111",
            "not-a-base58-pubkey",
        );
        let result: Result<SoakConfig, _> = serde_json::from_str(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn load_reads_real_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("mosaic-soak-config-test-{}.json", std::process::id()));
        std::fs::write(&path, SAMPLE_JSON).unwrap();
        let cfg = SoakConfig::load(&path).expect("load from disk");
        assert_eq!(cfg.duration, Duration::from_secs(86_400));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ship_devnet_template_parses() {
        // The template ship at scripts/soak-config-devnet.json is the
        // canonical starting point for operators. Verify it stays
        // parseable after any future edits.
        //
        // We allow the `_comment` key in the file because operators
        // need a place to leave annotations. serde-json silently
        // ignores unknown keys by default, so this just works.
        let template = include_str!("../../../scripts/soak-config-devnet.json");
        let _cfg: SoakConfig = serde_json::from_str(template).expect("template parses");
    }
}
