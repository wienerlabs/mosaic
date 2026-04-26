//! Criterion benchmarks — host-backend Phase-3 verifier wall-clock
//! baselines.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p mosaic-bench --bench phase3_host
//! ```
//!
//! These wall-clock numbers are the canary for host-side CPU regressions
//! before they hit on-chain CU. The criterion harness gives us
//! statistical noise floors so a real algorithmic change surfaces
//! distinctly from a JIT/codegen drift on the runner.
//!
//! ## Fixture provenance
//!
//! Each system uses the same scaffold-acceptance fixture pattern as
//! `bpf-bench` (sessions 47, 49) — built inline by mirroring the
//! verifier's own `verifier::tests` dummy fixtures. This means the
//! `verify` call returns `Ok(())` and exercises the FULL pipeline:
//! parse → challenges → sumcheck/identity → KZG/FRI pairing/Merkle
//! verification. The wall-clock number reflects every code path that
//! a real-world prover output would touch (with the caveat that
//! cryptographic content is uniform-zero, so cache effects on real
//! data may differ slightly).
//!
//! Mirrors the bpf-bench's `build_*_scaffold_fixture` helpers; kept
//! inline here to avoid pulling the bin module into the bench crate's
//! lib graph.

#![allow(missing_docs)] // criterion_group! macro generates undocumented items.
#![allow(clippy::unwrap_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};

// ──────────────────────────────────────────────────────────────────────
// HyperPlonk
// ──────────────────────────────────────────────────────────────────────

fn build_hyperplonk_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use mosaic_hyperplonk::canonical::{
        sizes::{FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN, G1_LEN, SUMCHECK_POLY_LEN},
        HyperPlonkVerifyingKey,
    };
    use mosaic_zk_primitives::g1_consts::g2_generator_bytes;

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
    }
    .to_bytes();
    let polys_len = 10 * SUMCHECK_POLY_LEN;
    let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
    let mut proof = vec![0u8; total];
    proof[256..260].copy_from_slice(&10u32.to_le_bytes());
    let public_inputs = vec![0u8; FR_LEN];
    (vk, proof, public_inputs)
}

fn bench_hyperplonk(c: &mut Criterion) {
    use mosaic_hyperplonk::HyperPlonkKzgBn254;
    let (vk, proof, public_inputs) = build_hyperplonk_fixture();
    let backend = HostBackend::new();
    let v = HyperPlonkKzgBn254::new(&backend);
    c.bench_function("hyperplonk_verify_host_scaffold", |b| {
        b.iter(|| {
            let _ = ProofSystem::verify(&v, &vk, &proof, &public_inputs);
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// Halo2
// ──────────────────────────────────────────────────────────────────────

fn build_halo2_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use mosaic_halo2::canonical::{
        sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN},
        Halo2KzgVerifyingKey,
    };
    use mosaic_zk_primitives::field::fr_to_canonical_bytes;
    use mosaic_zk_primitives::g1_consts::g2_generator_bytes;

    let vk = Halo2KzgVerifyingKey {
        k: 10,
        n_instances: 1,
        n_advice: 5,
        n_fixed: 2,
        x2_g2: {
            let mut a = [0u8; G2_LEN];
            a.copy_from_slice(&g2_generator_bytes());
            a
        },
        omega_fr: [0u8; FR_LEN],
        fixed_commits: vec![0; 2 * G1_LEN],
        permutation_commits: vec![0; 5 * G1_LEN],
    }
    .to_bytes();

    let n_advice = 5u32;
    let n_lookups = 0u32;
    let n_quotient = 3u32;
    let n_evals = 19u32;
    let total = FIXED_HEADER_LEN
        + (n_advice as usize) * G1_LEN
        + (n_lookups as usize) * G1_LEN
        + G1_LEN
        + (n_quotient as usize) * G1_LEN
        + (n_evals as usize) * FR_LEN
        + 2 * G1_LEN;
    let mut proof = vec![0u8; total];
    proof[0..4].copy_from_slice(&n_advice.to_le_bytes());
    proof[4..8].copy_from_slice(&n_lookups.to_le_bytes());
    proof[8..12].copy_from_slice(&n_quotient.to_le_bytes());
    proof[12..16].copy_from_slice(&n_evals.to_le_bytes());
    let evals_off = FIXED_HEADER_LEN
        + (n_advice as usize) * G1_LEN
        + (n_lookups as usize) * G1_LEN
        + G1_LEN
        + (n_quotient as usize) * G1_LEN;
    let m_off = evals_off + 15 * FR_LEN;
    let one_bytes = fr_to_canonical_bytes(&ark_bn254::Fr::from(1u64));
    proof[m_off..m_off + FR_LEN].copy_from_slice(&one_bytes);
    let public_inputs = vec![0u8; FR_LEN];
    (vk, proof, public_inputs)
}

fn bench_halo2(c: &mut Criterion) {
    use mosaic_halo2::Halo2KzgBn254;
    let (vk, proof, public_inputs) = build_halo2_fixture();
    let backend = HostBackend::new();
    let v = Halo2KzgBn254::new(&backend);
    c.bench_function("halo2_verify_host_scaffold", |b| {
        b.iter(|| {
            let _ = ProofSystem::verify(&v, &vk, &proof, &public_inputs);
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// Nova
// ──────────────────────────────────────────────────────────────────────

fn build_nova_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use mosaic_nova::canonical::{
        sizes::{
            FIXED_COMMITS_LEN, FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN, HADAMARD_EVALS_LEN,
            OPENING_LEN, SCALAR_LEN, W_EVAL_LEN,
        },
        FoldingVariant, NovaFoldingVerifyingKey,
    };
    use mosaic_zk_primitives::g1_consts::g2_generator_bytes;

    let vk = NovaFoldingVerifyingKey {
        variant: FoldingVariant::Nova,
        n_public: 2,
        n_constraints: 1024,
        x2_g2: {
            let mut a = [0u8; G2_LEN];
            a.copy_from_slice(&g2_generator_bytes());
            a
        },
        a_comm: [0u8; G1_LEN],
        b_comm: [0u8; G1_LEN],
        c_comm: [0u8; G1_LEN],
        cs_digest: [0u8; 32],
    }
    .to_bytes();

    let pi_len = 2 * FR_LEN;
    let total = FIXED_HEADER_LEN
        + FIXED_COMMITS_LEN
        + SCALAR_LEN
        + 4 * G1_LEN
        + HADAMARD_EVALS_LEN
        + W_EVAL_LEN
        + pi_len
        + OPENING_LEN;
    let mut proof = vec![0u8; total];
    proof[0] = FoldingVariant::Nova as u8;
    proof[1] = 0;
    proof[2..4].copy_from_slice(&2u16.to_le_bytes());
    let public_inputs = vec![0u8; pi_len];
    (vk, proof, public_inputs)
}

fn bench_nova(c: &mut Criterion) {
    use mosaic_nova::NovaFolding;
    let (vk, proof, public_inputs) = build_nova_fixture();
    let backend = HostBackend::new();
    let v = NovaFolding::new(&backend);
    c.bench_function("nova_verify_host_scaffold", |b| {
        b.iter(|| {
            let _ = ProofSystem::verify(&v, &vk, &proof, &public_inputs);
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// FRI-STARK
// ──────────────────────────────────────────────────────────────────────

fn build_stark_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use mosaic_stark::canonical::{
        sizes::{DIGEST_LEN, FIXED_HEADER_LEN, POW_NONCE_LEN},
        FriStarkVerifyingKey, StarkFieldId, FRI_LAYER_OPENING_LEN,
    };

    let field_id = StarkFieldId::Goldilocks;
    let log_blowup: u8 = 1;
    let num_fri_layers: u8 = 4;
    let num_queries: u16 = 8;
    let trace_log_height: u16 = 10;
    let trace_width: u32 = 1;

    let vk = FriStarkVerifyingKey {
        field_id,
        trace_width,
        trace_log_height,
        log_blowup,
        air_hash: [0u8; 32],
        omega_g: [0u8; 8],
    }
    .to_bytes();

    let ood_bytes = 10 * field_id.field_elem_bytes();
    let final_bytes = 4 * field_id.field_elem_bytes();
    let depth = (trace_log_height as usize) + (log_blowup as usize);
    let per_query_bytes = 2 * (DIGEST_LEN + depth * DIGEST_LEN);
    let query_bytes = (num_queries as usize) * per_query_bytes;
    let fri_openings_bytes =
        (num_queries as usize) * (num_fri_layers as usize) * FRI_LAYER_OPENING_LEN;
    let auth_paths_bytes =
        (num_queries as usize) * (num_fri_layers as usize) * 2 * depth * DIGEST_LEN;

    let total = FIXED_HEADER_LEN
        + 2 * DIGEST_LEN
        + (num_fri_layers as usize) * DIGEST_LEN
        + 4
        + ood_bytes
        + 4
        + final_bytes
        + 4
        + query_bytes
        + 4
        + fri_openings_bytes
        + 4
        + auth_paths_bytes
        + POW_NONCE_LEN;

    let mut proof = vec![0u8; total];
    proof[0] = field_id as u8;
    proof[1] = log_blowup;
    proof[2] = num_fri_layers;
    proof[3] = 0;
    proof[4..6].copy_from_slice(&num_queries.to_le_bytes());
    proof[6..8].copy_from_slice(&trace_log_height.to_le_bytes());
    proof[8..12].copy_from_slice(&trace_width.to_le_bytes());

    let mut off = FIXED_HEADER_LEN + 2 * DIGEST_LEN + (num_fri_layers as usize) * DIGEST_LEN;
    proof[off..off + 4].copy_from_slice(&(ood_bytes as u32).to_le_bytes());
    off += 4 + ood_bytes;
    proof[off..off + 4].copy_from_slice(&(final_bytes as u32).to_le_bytes());
    off += 4 + final_bytes;
    proof[off..off + 4].copy_from_slice(&(query_bytes as u32).to_le_bytes());
    off += 4 + query_bytes;
    proof[off..off + 4].copy_from_slice(&(fri_openings_bytes as u32).to_le_bytes());
    off += 4 + fri_openings_bytes;
    proof[off..off + 4].copy_from_slice(&(auth_paths_bytes as u32).to_le_bytes());

    let public_inputs = Vec::new();
    (vk, proof, public_inputs)
}

fn bench_stark(c: &mut Criterion) {
    use mosaic_stark::FriStark;
    let (vk, proof, public_inputs) = build_stark_fixture();
    let backend = HostBackend::new();
    let v = FriStark::new(&backend);
    c.bench_function("fri_stark_verify_host_scaffold", |b| {
        b.iter(|| {
            let _ = ProofSystem::verify(&v, &vk, &proof, &public_inputs);
        });
    });
}

criterion_group!(
    benches,
    bench_hyperplonk,
    bench_halo2,
    bench_nova,
    bench_stark
);
criterion_main!(benches);
