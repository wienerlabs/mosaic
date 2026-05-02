//! Criterion benchmarks — alt_bn128 compression host cost
//! characteristics.
//!
//! Run with:
//!
//! ```text
//! cargo bench -p mosaic-bench --bench compression_host
//! ```
//!
//! Sessions 103-104 wired the alt_bn128_compression syscall on both
//! backends + added typed helpers in
//! `mosaic-zk-primitives::compression`. Sessions 106-110 wired six
//! verifier-side consumers (Halo2 / Groth16 / PLONK proof + VK).
//! This bench measures the **host-side** cost of those consumers
//! using the arkworks-based `solana-bn254` fallback (host target
//! routes through arkworks `serialize_compressed` / `deserialize_with_mode`).
//!
//! ## Why host bench (not SBF CU)
//!
//! Real on-chain CU consumption goes through the
//! `sol_alt_bn128_compression` syscall which has its own per-op cost
//! schedule. To measure that we'd need an SBF program instruction
//! that decompresses in-program (out of scope for this session).
//!
//! The host bench still establishes useful baselines:
//! - **Regression detection**: host arkworks compression is the
//!   reference implementation; if its cost changes, downstream
//!   syscall correctness assumptions could shift.
//! - **Cost-ratio characterization**: G1 vs G2 vs proof-shape
//!   ratios should remain constant across releases. A drift in any
//!   ratio surfaces here before the syscall side.
//! - **Trade-off validation**: the CHANGELOG entries for
//!   v0.9.5/.7/.8/.9 cite ~10 K CU per G1 decompress and ~12 K CU
//!   per G2 decompress. The host bench measures the corresponding
//!   wall-clock so we can compute the host-vs-SBF cost ratio when
//!   syscall measurements land.

#![allow(missing_docs)] // criterion_group! macro
#![allow(clippy::unwrap_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use mosaic_core::syscall::host::HostBackend;

// ──────────────────────────────────────────────────────────────────────
// Single-point primitive baselines (G1 / G2 compress + decompress).
// ──────────────────────────────────────────────────────────────────────

fn bench_compress_g1(c: &mut Criterion) {
    use mosaic_zk_primitives::compression::compress_g1;
    let backend = HostBackend::new();
    let g1 = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    c.bench_function("compress_g1_generator_host", |b| {
        b.iter(|| {
            let _ = compress_g1(&backend, &g1).unwrap();
        });
    });
}

fn bench_decompress_g1(c: &mut Criterion) {
    use mosaic_zk_primitives::compression::{compress_g1, decompress_g1};
    let backend = HostBackend::new();
    let g1 = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    let compressed = compress_g1(&backend, &g1).unwrap();
    c.bench_function("decompress_g1_generator_host", |b| {
        b.iter(|| {
            let _ = decompress_g1(&backend, &compressed).unwrap();
        });
    });
}

fn bench_compress_g2(c: &mut Criterion) {
    use mosaic_zk_primitives::compression::compress_g2;
    let backend = HostBackend::new();
    let g2 = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
    c.bench_function("compress_g2_generator_host", |b| {
        b.iter(|| {
            let _ = compress_g2(&backend, &g2).unwrap();
        });
    });
}

fn bench_decompress_g2(c: &mut Criterion) {
    use mosaic_zk_primitives::compression::{compress_g2, decompress_g2};
    let backend = HostBackend::new();
    let g2 = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
    let compressed = compress_g2(&backend, &g2).unwrap();
    c.bench_function("decompress_g2_generator_host", |b| {
        b.iter(|| {
            let _ = decompress_g2(&backend, &compressed).unwrap();
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// End-to-end verifier round-trips (proof + VK compress → decompress).
// ──────────────────────────────────────────────────────────────────────

fn bench_groth16_proof_round_trip(c: &mut Criterion) {
    use mosaic_groth16::Groth16Proof;

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
    let mut canonical = Vec::with_capacity(256);
    canonical.extend_from_slice(&g1_gen);
    canonical.extend_from_slice(&g2_gen);
    canonical.extend_from_slice(&g1_gen);

    c.bench_function("groth16_proof_compress_host", |b| {
        b.iter(|| {
            let _ = Groth16Proof::compress_from_canonical_bytes(&backend, &canonical)
                .unwrap();
        });
    });

    let compressed =
        Groth16Proof::compress_from_canonical_bytes(&backend, &canonical).unwrap();
    c.bench_function("groth16_proof_decompress_host", |b| {
        b.iter(|| {
            let _ = Groth16Proof::decompress_to_canonical_bytes(&backend, &compressed)
                .unwrap();
        });
    });
}

fn bench_groth16_vk_round_trip(c: &mut Criterion) {
    use mosaic_groth16::Groth16VerifyingKey;

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
    let vk = Groth16VerifyingKey {
        alpha_g1: g1_gen,
        beta_g2: g2_gen,
        gamma_g2: g2_gen,
        delta_g2: g2_gen,
        ic: vec![g1_gen, g1_gen, g1_gen],
    };

    c.bench_function("groth16_vk_compress_host_ic_3", |b| {
        b.iter(|| {
            let _ = vk.to_compressed_bytes(&backend).unwrap();
        });
    });

    let compressed = vk.to_compressed_bytes(&backend).unwrap();
    c.bench_function("groth16_vk_decompress_host_ic_3", |b| {
        b.iter(|| {
            let _ = Groth16VerifyingKey::from_compressed_bytes(&backend, &compressed)
                .unwrap();
        });
    });
}

fn bench_plonk_proof_round_trip(c: &mut Criterion) {
    use mosaic_plonk::canonical::PlonkProof;
    use mosaic_plonk::canonical::sizes;

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    let mut canonical = Vec::with_capacity(sizes::PROOF_LEN);
    for _ in 0..9 {
        canonical.extend_from_slice(&g1_gen);
    }
    canonical.extend_from_slice(&[0u8; 6 * sizes::FR_LEN]);

    c.bench_function("plonk_proof_compress_host", |b| {
        b.iter(|| {
            let _ = PlonkProof::compress_from_canonical_bytes(&backend, &canonical)
                .unwrap();
        });
    });

    let compressed =
        PlonkProof::compress_from_canonical_bytes(&backend, &canonical).unwrap();
    c.bench_function("plonk_proof_decompress_host", |b| {
        b.iter(|| {
            let _ = PlonkProof::decompress_to_canonical_bytes(&backend, &compressed)
                .unwrap();
        });
    });
}

fn bench_plonk_vk_round_trip(c: &mut Criterion) {
    use mosaic_plonk::canonical::sizes;
    use mosaic_plonk::canonical::PlonkVerifyingKey;

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
    let vk = PlonkVerifyingKey {
        qm_g1: g1_gen,
        ql_g1: g1_gen,
        qr_g1: g1_gen,
        qo_g1: g1_gen,
        qc_g1: g1_gen,
        s1_g1: g1_gen,
        s2_g1: g1_gen,
        s3_g1: g1_gen,
        x2_g2: g2_gen,
        power: 10,
        k1: [0u8; sizes::FR_LEN],
        k2: [0u8; sizes::FR_LEN],
        omega: [0u8; sizes::FR_LEN],
        n_public: 3,
    };

    c.bench_function("plonk_vk_compress_host", |b| {
        b.iter(|| {
            let _ = vk.to_compressed_bytes(&backend).unwrap();
        });
    });

    let compressed = vk.to_compressed_bytes(&backend).unwrap();
    c.bench_function("plonk_vk_decompress_host", |b| {
        b.iter(|| {
            let _ =
                PlonkVerifyingKey::from_compressed_bytes(&backend, &compressed)
                    .unwrap();
        });
    });
}

fn bench_halo2_vk_round_trip(c: &mut Criterion) {
    use mosaic_halo2::canonical::sizes;
    use mosaic_halo2::canonical::Halo2KzgVerifyingKey;

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();
    let vk = Halo2KzgVerifyingKey {
        k: 10,
        n_instances: 1,
        n_advice: 5,
        n_fixed: 2,
        x2_g2: g2_gen,
        omega_fr: [0u8; sizes::FR_LEN],
        // 2 fixed + 5 perm — typical Halo2 circuit shape.
        fixed_commits: {
            let mut v = Vec::with_capacity(2 * sizes::G1_LEN);
            v.extend_from_slice(&g1_gen);
            v.extend_from_slice(&g1_gen);
            v
        },
        permutation_commits: {
            let mut v = Vec::with_capacity(5 * sizes::G1_LEN);
            for _ in 0..5 {
                v.extend_from_slice(&g1_gen);
            }
            v
        },
    };

    c.bench_function("halo2_vk_compress_host_2_fixed_5_perm", |b| {
        b.iter(|| {
            let _ = vk.to_compressed_bytes(&backend).unwrap();
        });
    });

    let compressed = vk.to_compressed_bytes(&backend).unwrap();
    c.bench_function("halo2_vk_decompress_host_2_fixed_5_perm", |b| {
        b.iter(|| {
            let _ = Halo2KzgVerifyingKey::from_compressed_bytes(&backend, &compressed)
                .unwrap();
        });
    });
}

fn bench_halo2_proof_round_trip(c: &mut Criterion) {
    use mosaic_halo2::canonical::sizes;
    use mosaic_halo2::canonical::Halo2KzgProof;

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();

    // Realistic Halo2 proof: 5 advice + 0 lookups + 3 quotient + 19 evals,
    // arity = 1.
    let n_advice: u32 = 5;
    let n_lookups: u32 = 0;
    let n_quotient: u32 = 3;
    let n_evals: u32 = 19;
    let arity: u32 = 1;
    let total = sizes::FIXED_HEADER_LEN
        + (n_advice as usize) * sizes::G1_LEN
        + (n_lookups as usize) * sizes::G1_LEN
        + sizes::G1_LEN
        + (n_quotient as usize) * sizes::G1_LEN
        + (n_evals as usize) * sizes::FR_LEN
        + 2 * sizes::G1_LEN;
    let mut canonical = vec![0u8; total];
    canonical[0..4].copy_from_slice(&n_advice.to_le_bytes());
    canonical[4..8].copy_from_slice(&n_lookups.to_le_bytes());
    canonical[8..12].copy_from_slice(&n_quotient.to_le_bytes());
    canonical[12..16].copy_from_slice(&n_evals.to_le_bytes());
    canonical[16..20].copy_from_slice(&arity.to_le_bytes());
    let mut o = sizes::FIXED_HEADER_LEN;
    for _ in 0..n_advice {
        canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);
        o += sizes::G1_LEN;
    }
    canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);
    o += sizes::G1_LEN;
    for _ in 0..n_quotient {
        canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);
        o += sizes::G1_LEN;
    }
    o += (n_evals as usize) * sizes::FR_LEN; // skip Fr evals
    canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);
    o += sizes::G1_LEN;
    canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);

    c.bench_function("halo2_proof_compress_host_5_advice_3_quot", |b| {
        b.iter(|| {
            let _ = Halo2KzgProof::compress_from_canonical_bytes(&backend, &canonical)
                .unwrap();
        });
    });

    let compressed =
        Halo2KzgProof::compress_from_canonical_bytes(&backend, &canonical).unwrap();
    c.bench_function("halo2_proof_decompress_host_5_advice_3_quot", |b| {
        b.iter(|| {
            let _ =
                Halo2KzgProof::decompress_to_canonical_bytes(&backend, &compressed)
                    .unwrap();
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// Session 114 — Phase-3 round-trip benches.
//
// Mirrors the Phase-2 layout above for HyperPlonk and Nova. STARK has
// no BN254 curve points so alt_bn128 compression is not applicable.
// ──────────────────────────────────────────────────────────────────────

fn bench_hyperplonk_proof_round_trip(c: &mut Criterion) {
    use mosaic_hyperplonk::canonical::sizes;
    use mosaic_hyperplonk::canonical::HyperPlonkProof;

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();

    // Realistic HyperPlonk proof at sumcheck_rounds = 10 (= 2^10 circuit).
    let rounds: u32 = 10;
    let polys_len = (rounds as usize) * sizes::SUMCHECK_POLY_LEN;
    let total = 4 * sizes::G1_LEN
        + 4
        + polys_len
        + sizes::FINAL_EVALS * sizes::FR_LEN
        + sizes::G1_LEN;
    let mut canonical = vec![0u8; total];
    let mut o = 0;
    for _ in 0..4 {
        canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);
        o += sizes::G1_LEN;
    }
    canonical[o..o + 4].copy_from_slice(&rounds.to_le_bytes());
    o += 4 + polys_len + sizes::FINAL_EVALS * sizes::FR_LEN;
    canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);

    c.bench_function("hyperplonk_proof_compress_host_r10", |b| {
        b.iter(|| {
            let _ =
                HyperPlonkProof::compress_from_canonical_bytes(&backend, &canonical)
                    .unwrap();
        });
    });

    let compressed =
        HyperPlonkProof::compress_from_canonical_bytes(&backend, &canonical).unwrap();
    c.bench_function("hyperplonk_proof_decompress_host_r10", |b| {
        b.iter(|| {
            let _ =
                HyperPlonkProof::decompress_to_canonical_bytes(&backend, &compressed)
                    .unwrap();
        });
    });
}

fn bench_hyperplonk_vk_round_trip(c: &mut Criterion) {
    use mosaic_hyperplonk::canonical::HyperPlonkVerifyingKey;

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();

    let canonical = HyperPlonkVerifyingKey {
        n_public: 3,
        num_variables: 10,
        x2_g2: g2_gen,
        q_m_g1: g1_gen,
        q_l_g1: g1_gen,
        q_r_g1: g1_gen,
        q_o_g1: g1_gen,
        q_c_g1: g1_gen,
        sigma_1_g1: g1_gen,
        sigma_2_g1: g1_gen,
        sigma_3_g1: g1_gen,
        k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
        k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
        k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
    }
    .to_bytes();

    c.bench_function("hyperplonk_vk_compress_host", |b| {
        b.iter(|| {
            let _ =
                HyperPlonkVerifyingKey::to_compressed_bytes(&backend, &canonical)
                    .unwrap();
        });
    });

    let compressed =
        HyperPlonkVerifyingKey::to_compressed_bytes(&backend, &canonical).unwrap();
    c.bench_function("hyperplonk_vk_decompress_host", |b| {
        b.iter(|| {
            let _ = HyperPlonkVerifyingKey::from_compressed_bytes(&backend, &compressed)
                .unwrap();
        });
    });
}

fn bench_nova_proof_round_trip(c: &mut Criterion) {
    use mosaic_nova::canonical::{sizes, FoldingVariant, NovaFoldingProof};

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();

    // Realistic Nova proof: variant=Nova, num_aux=0, n_public=4.
    let variant = FoldingVariant::Nova;
    let num_aux: u8 = 0;
    let n_public: u16 = 4;
    let aux_len = (num_aux as usize) * sizes::G1_LEN;
    let pi_len = (n_public as usize) * sizes::FR_LEN;
    let total = sizes::FIXED_HEADER_LEN
        + 3 * sizes::G1_LEN
        + sizes::SCALAR_LEN
        + 4 * sizes::G1_LEN
        + sizes::HADAMARD_EVALS_LEN
        + sizes::W_EVAL_LEN
        + aux_len
        + pi_len
        + 2 * sizes::G1_LEN;
    let mut canonical = vec![0u8; total];
    canonical[0] = variant as u8;
    canonical[1] = num_aux;
    canonical[2..4].copy_from_slice(&n_public.to_le_bytes());

    let mut o = sizes::FIXED_HEADER_LEN;
    for _ in 0..3 {
        canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);
        o += sizes::G1_LEN;
    }
    o += sizes::SCALAR_LEN;
    for _ in 0..4 {
        canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);
        o += sizes::G1_LEN;
    }
    o += sizes::HADAMARD_EVALS_LEN + sizes::W_EVAL_LEN + pi_len;
    for _ in 0..2 {
        canonical[o..o + sizes::G1_LEN].copy_from_slice(&g1_gen);
        o += sizes::G1_LEN;
    }

    c.bench_function("nova_proof_compress_host_default_shape", |b| {
        b.iter(|| {
            let _ =
                NovaFoldingProof::compress_from_canonical_bytes(&backend, &canonical)
                    .unwrap();
        });
    });

    let compressed =
        NovaFoldingProof::compress_from_canonical_bytes(&backend, &canonical).unwrap();
    c.bench_function("nova_proof_decompress_host_default_shape", |b| {
        b.iter(|| {
            let _ =
                NovaFoldingProof::decompress_to_canonical_bytes(&backend, &compressed)
                    .unwrap();
        });
    });
}

fn bench_nova_vk_round_trip(c: &mut Criterion) {
    use mosaic_nova::canonical::{FoldingVariant, NovaFoldingVerifyingKey};

    let backend = HostBackend::new();
    let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
    let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();

    let canonical = NovaFoldingVerifyingKey {
        variant: FoldingVariant::Nova,
        n_public: 4,
        n_constraints: 1024,
        x2_g2: g2_gen,
        a_comm: g1_gen,
        b_comm: g1_gen,
        c_comm: g1_gen,
        cs_digest: [0u8; 32],
    }
    .to_bytes();

    c.bench_function("nova_vk_compress_host", |b| {
        b.iter(|| {
            let _ =
                NovaFoldingVerifyingKey::to_compressed_bytes(&backend, &canonical)
                    .unwrap();
        });
    });

    let compressed =
        NovaFoldingVerifyingKey::to_compressed_bytes(&backend, &canonical).unwrap();
    c.bench_function("nova_vk_decompress_host", |b| {
        b.iter(|| {
            let _ =
                NovaFoldingVerifyingKey::from_compressed_bytes(&backend, &compressed)
                    .unwrap();
        });
    });
}

// ──────────────────────────────────────────────────────────────────────
// Aggregator
// ──────────────────────────────────────────────────────────────────────

criterion_group!(
    compression,
    bench_compress_g1,
    bench_decompress_g1,
    bench_compress_g2,
    bench_decompress_g2,
    bench_groth16_proof_round_trip,
    bench_groth16_vk_round_trip,
    bench_plonk_proof_round_trip,
    bench_plonk_vk_round_trip,
    bench_halo2_proof_round_trip,
    bench_halo2_vk_round_trip,
    bench_hyperplonk_proof_round_trip,
    bench_hyperplonk_vk_round_trip,
    bench_nova_proof_round_trip,
    bench_nova_vk_round_trip,
);
criterion_main!(compression);
