//! Criterion benchmark — host-backend Groth16 verification.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p mosaic-bench --bench groth16_host
//! ```
//!
//! Numbers regress only when the verifier algorithm or arkworks dependency
//! changes; this is the canary for CPU regressions before they hit on-chain.
#![allow(missing_docs)] // criterion_group! macro generates undocumented items.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mosaic_bench::prelude::*;
use mosaic_core::syscall::host::HostBackend;

fn build_dummy_inputs(num_pi: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use mosaic_groth16::{
        canonical::Groth16VerifyingKey,
        sizes::{FR_LEN, G1_LEN, G2_LEN, PROOF_LEN},
    };
    let vk = Groth16VerifyingKey {
        alpha_g1: [0; G1_LEN],
        beta_g2: [0; G2_LEN],
        gamma_g2: [0; G2_LEN],
        delta_g2: [0; G2_LEN],
        ic: vec![[0; G1_LEN]; num_pi + 1],
    };
    let proof = vec![0u8; PROOF_LEN];
    let pi = vec![0u8; FR_LEN * num_pi];
    (vk.to_bytes(), proof, pi)
}

fn bench_groth16_verify(c: &mut Criterion) {
    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);
    let mut group = c.benchmark_group("groth16_verify_host");
    for num_pi in [1_usize, 5, 10, 50] {
        let (vk, proof, pi) = build_dummy_inputs(num_pi);
        group.bench_with_input(
            BenchmarkId::from_parameter(num_pi),
            &num_pi,
            |b, _| {
                b.iter(|| {
                    // We expect this to error (zero points are off-curve);
                    // the benchmark measures the deserialization + bounds-check
                    // hot path that runs unconditionally.
                    let _ = v.verify(&vk, &proof, &pi);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_groth16_verify);
criterion_main!(benches);
