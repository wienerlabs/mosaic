//! Criterion benchmarks — host-backend Phase-3 audit-gate isolation
//! baselines.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p mosaic-bench --bench audit_gates_host
//! ```
//!
//! Sessions 86 → 91 extracted the primary soundness check of every
//! Phase-3 verifier into a named ADR-0006 audit gate (see
//! [`docs/adr/0006-verifier-audit-gate-pattern.md`]). The
//! `phase3_host` bench measures end-to-end `verify` wall-clock; this
//! complementary bench measures **each audit gate in isolation** so
//! regressions in the gate's algebraic content surface separately
//! from regressions in the parsing / transcript / Merkle pipelines.
//!
//! ## Why isolate gate benches
//!
//! - **Regression isolation.** A change to the verifier's parsing
//!   layer that adds 50 µs is acoustically masked by the millisecond-
//!   scale verifier `verify` bench. The gate-level bench surfaces
//!   the same change distinctly because the gate body alone runs in
//!   tens of microseconds.
//! - **CU budget allocation.** Each Phase-3 verifier has an
//!   ADR-0005 hard CU cap. Knowing how much of that budget the audit
//!   gate accounts for vs the rest of the pipeline is essential for
//!   targeted optimization (e.g. "Nova's verify_folding_consistency
//!   is 30K of the 900K total — leave it alone").
//! - **Audit story.** External auditors reviewing an audit gate get
//!   a wall-clock number alongside the soundness story.
//!
//! ## Phase-2 omission
//!
//! Groth16 and PLONK pairing-identity gates are not benchmarked here
//! because their wall-clock is dominated by the alt_bn128 pairing
//! syscall (which the existing `groth16_host` bench already
//! captures). The gate-level bench would just be "syscall cost +
//! 5 ns of byte-comparison" — no useful signal.

#![allow(missing_docs)] // criterion_group! macro generates undocumented items.
#![allow(clippy::unwrap_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use mosaic_core::syscall::host::HostBackend;

// ──────────────────────────────────────────────────────────────────────
// Nova — verify_folding_consistency
// ──────────────────────────────────────────────────────────────────────

fn bench_nova_consistency_gate(c: &mut Criterion) {
    use ark_bn254::Fr;
    use mosaic_nova::verify_folding_consistency;
    use mosaic_zk_primitives::g1_consts::g1_generator_bytes;

    // Honest baseline: G1 generator at base_e_1 + base_w_1, rest
    // zero. Reconstructed E = W = G1 generator; declared = same.
    let g1 = g1_generator_bytes();
    let zero = [0u8; 64];
    let r = Fr::from(42u64);
    let backend = HostBackend::new();

    c.bench_function("nova_consistency_gate_host_honest", |b| {
        b.iter(|| {
            let _ = verify_folding_consistency(
                &backend, &g1, &zero, &g1, &zero, &zero, &g1, &g1, &r,
            );
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// Halo2 — verify_multi_column_lookup_identity (arity 1 + arity 4)
// ──────────────────────────────────────────────────────────────────────

fn bench_halo2_lookup_gate(c: &mut Criterion) {
    use ark_bn254::Fr;
    use mosaic_halo2::{verify_multi_column_lookup_identity, MultiColumnLookupEvals};

    let theta = Fr::from(11u64);

    // Arity-1 satisfying tuple: matching column, m=1.
    let lookup_a1 = MultiColumnLookupEvals::try_new(
        alloc::vec![Fr::from(7u64)],
        alloc::vec![Fr::from(7u64)],
        Fr::from(1u64),
    )
    .unwrap();
    c.bench_function("halo2_lookup_gate_host_arity_1_honest", |b| {
        b.iter(|| {
            let _ = verify_multi_column_lookup_identity(&lookup_a1, &theta);
        });
    });

    // Arity-4 satisfying tuple — surfaces the cost growth from
    // additional θ-power computation + inner products.
    let cols: alloc::vec::Vec<Fr> =
        (0..4).map(|i| Fr::from(7u64 + i as u64)).collect();
    let lookup_a4 = MultiColumnLookupEvals::try_new(
        cols.clone(),
        cols,
        Fr::from(1u64),
    )
    .unwrap();
    c.bench_function("halo2_lookup_gate_host_arity_4_honest", |b| {
        b.iter(|| {
            let _ = verify_multi_column_lookup_identity(&lookup_a4, &theta);
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// STARK FRI — verify_fri_query (1-layer fold)
// ──────────────────────────────────────────────────────────────────────

fn bench_stark_fri_query_gate(c: &mut Criterion) {
    use mosaic_stark::{verify_fri_query, Goldilocks};

    // Honest 1-layer fold of p(t) = c_0 + c_1·t.
    let c_0 = Goldilocks::new(7);
    let c_1 = Goldilocks::new(3);
    let beta = Goldilocks::new(11);
    let x = Goldilocks::new(5);
    let f_x = c_0.add(c_1.mul(x));
    let f_neg_x = c_0.add(c_1.mul(x.neg()));

    // f_1(t) = c_0 + β·c_1 (constant after one fold).
    let f1_const = c_0.add(beta.mul(c_1));
    let final_poly_bytes: alloc::vec::Vec<u8> = f1_const.to_bytes_le().to_vec();

    let layer_evals = [(f_x, f_neg_x)];
    let betas = [beta];

    c.bench_function("stark_fri_query_gate_host_1_layer_honest", |b| {
        b.iter(|| {
            let _ = verify_fri_query(&layer_evals, &betas, x, &final_poly_bytes);
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// HyperPlonk — verify_sumcheck_claim_reduction
// ──────────────────────────────────────────────────────────────────────

fn bench_hyperplonk_claim_reduction_gate(c: &mut Criterion) {
    use ark_bn254::Fr;
    use mosaic_hyperplonk::{
        verify_sumcheck_claim_reduction, HyperPlonkVerifyingKey, PreSumcheckChallenges,
    };
    use mosaic_zk_primitives::g1_consts::g2_generator_bytes;

    const FR_LEN: usize = 32;
    const G1_LEN: usize = 64;
    const FINAL_EVALS: usize = 12;

    // Zero baseline: every eval = 0 ⇒ expected claim = 0.
    let evals: alloc::vec::Vec<u8> = alloc::vec![0u8; FINAL_EVALS * FR_LEN];
    let challenges = PreSumcheckChallenges {
        alpha: Fr::from(7u64),
        beta: Fr::from(11u64),
        gamma: Fr::from(13u64),
    };
    let vk = HyperPlonkVerifyingKey {
        n_public: 1,
        num_variables: 10,
        x2_g2: g2_generator_bytes(),
        q_m_g1: [0; G1_LEN],
        q_l_g1: [0; G1_LEN],
        q_r_g1: [0; G1_LEN],
        q_o_g1: [0; G1_LEN],
        q_c_g1: [0; G1_LEN],
        sigma_1_g1: [0; G1_LEN],
        sigma_2_g1: [0; G1_LEN],
        sigma_3_g1: [0; G1_LEN],
        k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
        k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
        k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
    };
    let final_claim = Fr::from(0u64);

    c.bench_function("hyperplonk_claim_reduction_gate_host_zero_baseline", |b| {
        b.iter(|| {
            let _ = verify_sumcheck_claim_reduction(&evals, &challenges, &vk, &final_claim);
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// Aggregator
// ──────────────────────────────────────────────────────────────────────

extern crate alloc;

criterion_group!(
    audit_gates,
    bench_nova_consistency_gate,
    bench_halo2_lookup_gate,
    bench_stark_fri_query_gate,
    bench_hyperplonk_claim_reduction_gate,
);
criterion_main!(audit_gates);
