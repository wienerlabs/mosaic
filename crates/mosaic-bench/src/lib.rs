//! # mosaic-bench
//!
//! Two complementary benchmark surfaces:
//!
//! - **Criterion micro-benchmarks** (`benches/groth16_host.rs`) measure the
//!   host-backend verifier in isolation, producing wall-clock numbers that
//!   should regress only when the verifier algorithm changes.
//! - **`bpf-bench` binary** (`src/bin/bpf_bench.rs`) drives the on-chain
//!   reference program via `solana-program-test` and reads back the CU
//!   consumption logged by the runtime.
//!
//! Both surfaces are wired into CI via `.github/workflows/bench.yml`.
//! See ADR-0005 for the CU regression policy.

#![forbid(unsafe_code)]

/// Convenience re-exports for benchmark binaries.
pub mod prelude {
    pub use mosaic_core::{
        proof_system::{ProofSystem, ProofSystemId},
        syscall::host::HostBackend,
    };
    pub use mosaic_groth16::Groth16Verifier;
}
