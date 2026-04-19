//! `bpf-bench` — drive the on-chain reference program through
//! `solana-program-test` and report the CU consumption.
//!
//! TODO(mosaic-014): wire the program loading + CU reporting once the
//! reference program lands its first real fixtures. Phase 1 ships the
//! skeleton so CI integration can be staged.

use anyhow::Result;

fn main() -> Result<()> {
    eprintln!("mosaic bpf-bench: phase 1 stub — see TODO(mosaic-014)");
    Ok(())
}
