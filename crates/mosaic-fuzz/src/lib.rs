//! # mosaic-fuzz
//!
//! cargo-fuzz harnesses for the Mosaic verifier suite.
//!
//! ## Original three Groth16 harnesses (sessions ≤ 54)
//!
//! - `fuzz_groth16_proof_bytes` — feed arbitrary bytes as proof; expect
//!   `Err(_)` or panic-free success.
//! - `fuzz_vk_bytes` — feed arbitrary bytes as Groth16 VK; same expectation.
//! - `fuzz_public_inputs` — fix VK + proof, vary public inputs.
//!
//! ## Session 54-59 expansion (Phase-2 + Phase-3 verifier outer surfaces)
//!
//! For each of the 5 systems below, four harnesses fuzz the verifier's
//! outer entry-point byte slots: `proof_bytes`, `vk_bytes`,
//! `public_inputs`, and a `combined` cross-slot fuzzer that varies
//! all three independently. 5 systems × 4 surfaces = 20 harnesses.
//!
//! - `fuzz_plonk_*` — KZG-PLONK BN254
//! - `fuzz_hyperplonk_*` — HyperPlonk-KZG BN254
//! - `fuzz_halo2_*` — Halo2-KZG BN254
//! - `fuzz_nova_*` — Nova folding BN254
//! - `fuzz_stark_*` — FRI-STARK Goldilocks
//!
//! ## Session 95 expansion (audit-gate algebraic surfaces)
//!
//! Following ADR-0006 (audit-gate extraction pattern), each Phase-3
//! verifier exposes its primary soundness check as a named `verify_*`
//! audit gate. These four harnesses fuzz the gate's algebraic input
//! surface directly — NOT the verifier's outer parsing surface:
//!
//! - `fuzz_nova_consistency_gate` — Nova `verify_folding_consistency`
//!   (7 × 64 G1 + 1 × 32 Fr = 480 B input)
//! - `fuzz_halo2_lookup_gate` — Halo2
//!   `verify_multi_column_lookup_identity` (variable-arity columns)
//! - `fuzz_stark_fri_query_gate` — STARK `verify_fri_query`
//!   (variable-layer fold chain + final-poly bytes)
//! - `fuzz_hyperplonk_claim_reduction_gate` — HyperPlonk
//!   `verify_sumcheck_claim_reduction` (12-slot final_evals + α/β/γ
//!   + VK cosets + alleged sumcheck claim)
//!
//! The Phase-2 pairing-identity gates (Groth16 / PLONK
//! `verify_*_pairing_identity`) are NOT fuzzed at the gate level —
//! their algebraic surface reduces to the syscall verdict byte, which
//! has zero useful fuzz-discoverable space.
//!
//! ## Session 111 expansion (compressed wire format surfaces)
//!
//! Sessions 106-110 added compressed proof + VK forms via the
//! alt_bn128 compression syscall (sessions 103-104). These six
//! harnesses fuzz the decompression entry points to catch panics
//! on hostile compressed-byte inputs:
//!
//! - `fuzz_groth16_compressed_proof` — `Groth16Proof::decompress_to_canonical_bytes`
//! - `fuzz_groth16_compressed_vk`    — `Groth16VerifyingKey::from_compressed_bytes`
//! - `fuzz_plonk_compressed_proof`   — `PlonkProof::decompress_to_canonical_bytes`
//! - `fuzz_plonk_compressed_vk`      — `PlonkVerifyingKey::from_compressed_bytes`
//! - `fuzz_halo2_compressed_proof`   — `Halo2KzgProof::decompress_to_canonical_bytes`
//! - `fuzz_halo2_compressed_vk`      — `Halo2KzgVerifyingKey::from_compressed_bytes`
//!
//! Catches: off-curve compressed points, wrong-length payloads,
//! header counter mismatches, sign-bit edge cases, and usize
//! arithmetic overflow in compression-driven slice computations.
//!
//! ## Total inventory at session 111
//!
//! 23 outer-surface harnesses + 4 audit-gate harnesses + 6 compression
//! harnesses = **33 harnesses**.
//!
//! ## Panic-free invariant
//!
//! Every harness asserts the same panic-free invariant: hostile bytes
//! must surface as `Err(OnChainError::*)` or — in the rare case the
//! input happens to satisfy the verifier's scaffold-acceptance rules
//! — `Ok(())`. Any panic is a fuzzer-found bug.
//!
//! The harnesses share the [`SharedFixtures`] family of helpers to
//! avoid recomputing valid fixture material on every iteration.

#![forbid(unsafe_code)]

use mosaic_groth16::{
    canonical::Groth16VerifyingKey,
    sizes::{FR_LEN, G1_LEN, G2_LEN, PROOF_LEN},
};

/// Shared Groth16 fixtures for the original three fuzz harnesses.
pub struct SharedFixtures {
    /// Canonical-format VK bytes (zero points — invalid but well-formed).
    pub vk: Vec<u8>,
    /// 256-byte zero-filled proof skeleton.
    pub proof: Vec<u8>,
    /// One zero-valued public input.
    pub public_inputs: Vec<u8>,
}

impl Default for SharedFixtures {
    fn default() -> Self {
        let vk = Groth16VerifyingKey {
            alpha_g1: [0; G1_LEN],
            beta_g2: [0; G2_LEN],
            gamma_g2: [0; G2_LEN],
            delta_g2: [0; G2_LEN],
            ic: vec![[0; G1_LEN], [0; G1_LEN]],
        }
        .to_bytes();
        Self {
            vk,
            proof: vec![0u8; PROOF_LEN],
            public_inputs: vec![0u8; FR_LEN],
        }
    }
}

/// Split a libfuzzer input buffer into three length-prefixed slots
/// `(vk_bytes, proof_bytes, public_inputs_bytes)`. Returns `None` if
/// any length prefix runs off the end of the buffer.
///
/// Layout: `[vk_len: u16 LE] [vk_bytes] [proof_len: u16 LE]
/// [proof_bytes] [public_inputs ...]`
///
/// Used by `fuzz_*_combined.rs` (sessions 56, 59) to explore a
/// coordinate in `(vk, proof, pi)` space rather than the 1-D slice
/// the per-slot harnesses cover. See the rationale comment in
/// `fuzz_halo2_combined.rs` for why combined fuzzers complement
/// the single-slot variants.
pub fn split_three_slots(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let cursor = data;

    // vk_len (u16 LE).
    if cursor.len() < 2 {
        return None;
    }
    let (lp, rest) = cursor.split_at(2);
    let vk_len = u16::from_le_bytes([lp[0], lp[1]]) as usize;
    if rest.len() < vk_len {
        return None;
    }
    let (vk, rest) = rest.split_at(vk_len);

    // proof_len (u16 LE).
    if rest.len() < 2 {
        return None;
    }
    let (lp, rest) = rest.split_at(2);
    let proof_len = u16::from_le_bytes([lp[0], lp[1]]) as usize;
    if rest.len() < proof_len {
        return None;
    }
    let (proof, public_inputs) = rest.split_at(proof_len);

    // Whatever remains is the public-inputs slot.
    Some((vk, proof, public_inputs))
}

// ─────────────────────────────────────────────────────────────────────
// Session 54 — Phase-2 + Phase-3 fixture builders.
//
// Each `fixtures_*` function returns a `(vk, proof, public_inputs)`
// triple where the VK and public-inputs are valid scaffold bytes (so
// the harness exercises the full verifier pipeline) and the proof
// buffer is the per-system canonical layout's smallest sane shape.
// The fuzz target replaces the proof buffer with the libfuzzer input
// on each iteration.
//
// Mirrors the inline scaffold builders in `bpf-bench` (sessions
// 47, 49) and `phase3_host` criterion benches (session 51); kept
// in lib.rs here so multiple fuzz target binaries can share them.
// ─────────────────────────────────────────────────────────────────────

/// PLONK fixture: 768-byte zero-filled proof, 744-byte VK with real
/// G2 generator and (k1, k2) = (1, 2) coset constants. The
/// host-backend pairing syscall rejects (0, 0, 0, 0) G2, so the
/// generator placeholder keeps the fuzz path inside cryptographic
/// territory rather than short-circuiting at the syscall layer.
pub struct PlonkFixtures {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl Default for PlonkFixtures {
    fn default() -> Self {
        use mosaic_plonk::canonical::{
            sizes::{FR_LEN as PFR, G1_LEN as PG1, G2_LEN as PG2, PROOF_LEN as PPROOF},
            PlonkVerifyingKey,
        };
        use mosaic_zk_primitives::g1_consts::g2_generator_bytes;
        let mut x2_g2 = [0u8; PG2];
        x2_g2.copy_from_slice(&g2_generator_bytes());
        let vk = PlonkVerifyingKey {
            qm_g1: [0; PG1],
            ql_g1: [0; PG1],
            qr_g1: [0; PG1],
            qo_g1: [0; PG1],
            qc_g1: [0; PG1],
            s1_g1: [0; PG1],
            s2_g1: [0; PG1],
            s3_g1: [0; PG1],
            x2_g2,
            power: 10,
            k1: {
                let mut k = [0u8; PFR];
                k[PFR - 1] = 1;
                k
            },
            k2: {
                let mut k = [0u8; PFR];
                k[PFR - 1] = 2;
                k
            },
            omega: [0u8; PFR],
            n_public: 1,
        }
        .to_bytes();
        Self {
            vk,
            proof: vec![0u8; PPROOF],
            public_inputs: vec![0u8; PFR],
        }
    }
}

/// HyperPlonk fixture mirroring `bpf_bench::build_hyperplonk_scaffold_fixture`.
pub struct HyperPlonkFixtures {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl Default for HyperPlonkFixtures {
    fn default() -> Self {
        use mosaic_hyperplonk::canonical::{
            sizes::{
                FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN as HFR, G1_LEN as HG1, SUMCHECK_POLY_LEN,
            },
            HyperPlonkVerifyingKey,
        };
        use mosaic_zk_primitives::g1_consts::g2_generator_bytes;
        let vk = HyperPlonkVerifyingKey {
            n_public: 1,
            num_variables: 10,
            x2_g2: g2_generator_bytes(),
            q_m_g1: [0; HG1],
            q_l_g1: [0; HG1],
            q_r_g1: [0; HG1],
            q_o_g1: [0; HG1],
            q_c_g1: [0; HG1],
            sigma_1_g1: [0; HG1],
            sigma_2_g1: [0; HG1],
            sigma_3_g1: [0; HG1],
            k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
            k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
            k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
        }
        .to_bytes();
        let polys_len = 10 * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * HFR + HG1;
        let mut proof = vec![0u8; total];
        proof[256..260].copy_from_slice(&10u32.to_le_bytes());
        Self {
            vk,
            proof,
            public_inputs: vec![0u8; HFR],
        }
    }
}

/// Halo2 fixture mirroring `bpf_bench::build_halo2_scaffold_fixture`.
pub struct Halo2Fixtures {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl Default for Halo2Fixtures {
    fn default() -> Self {
        use mosaic_halo2::canonical::{
            sizes::{FIXED_HEADER_LEN, FR_LEN as HFR, G1_LEN as HG1, G2_LEN as HG2},
            Halo2KzgVerifyingKey,
        };
        use mosaic_zk_primitives::field::fr_to_canonical_bytes;
        use mosaic_zk_primitives::g1_consts::g2_generator_bytes;

        let mut x2_g2 = [0u8; HG2];
        x2_g2.copy_from_slice(&g2_generator_bytes());
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2,
            omega_fr: [0u8; HFR],
            fixed_commits: vec![0; 2 * HG1],
            permutation_commits: vec![0; 5 * HG1],
        }
        .to_bytes();
        let n_advice = 5u32;
        let n_lookups = 0u32;
        let n_quotient = 3u32;
        let n_evals = 19u32;
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * HG1
            + (n_lookups as usize) * HG1
            + HG1
            + (n_quotient as usize) * HG1
            + (n_evals as usize) * HFR
            + 2 * HG1;
        let mut proof = vec![0u8; total];
        proof[0..4].copy_from_slice(&n_advice.to_le_bytes());
        proof[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        proof[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        proof[12..16].copy_from_slice(&n_evals.to_le_bytes());
        let evals_off = FIXED_HEADER_LEN
            + (n_advice as usize) * HG1
            + (n_lookups as usize) * HG1
            + HG1
            + (n_quotient as usize) * HG1;
        let m_off = evals_off + 15 * HFR;
        let one_bytes = fr_to_canonical_bytes(&ark_bn254::Fr::from(1u64));
        proof[m_off..m_off + HFR].copy_from_slice(&one_bytes);
        Self {
            vk,
            proof,
            public_inputs: vec![0u8; HFR],
        }
    }
}

/// Nova folding fixture mirroring `bpf_bench::build_nova_scaffold_fixture`.
pub struct NovaFixtures {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl Default for NovaFixtures {
    fn default() -> Self {
        use mosaic_nova::canonical::{
            sizes::{
                FIXED_COMMITS_LEN, FIXED_HEADER_LEN, FR_LEN as NFR, G1_LEN as NG1, G2_LEN as NG2,
                HADAMARD_EVALS_LEN, OPENING_LEN, SCALAR_LEN, W_EVAL_LEN,
            },
            FoldingVariant, NovaFoldingVerifyingKey,
        };
        use mosaic_zk_primitives::g1_consts::g2_generator_bytes;
        let mut x2_g2 = [0u8; NG2];
        x2_g2.copy_from_slice(&g2_generator_bytes());
        let vk = NovaFoldingVerifyingKey {
            variant: FoldingVariant::Nova,
            n_public: 2,
            n_constraints: 1024,
            x2_g2,
            a_comm: [0u8; NG1],
            b_comm: [0u8; NG1],
            c_comm: [0u8; NG1],
            cs_digest: [0u8; 32],
        }
        .to_bytes();
        let pi_len = 2 * NFR;
        let total = FIXED_HEADER_LEN
            + FIXED_COMMITS_LEN
            + SCALAR_LEN
            + 4 * NG1
            + HADAMARD_EVALS_LEN
            + W_EVAL_LEN
            + pi_len
            + OPENING_LEN;
        let mut proof = vec![0u8; total];
        proof[0] = FoldingVariant::Nova as u8;
        proof[1] = 0;
        proof[2..4].copy_from_slice(&2u16.to_le_bytes());
        Self {
            vk,
            proof,
            public_inputs: vec![0u8; pi_len],
        }
    }
}

/// FRI-STARK Goldilocks fixture mirroring
/// `bpf_bench::build_stark_scaffold_fixture`.
pub struct StarkFixtures {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl Default for StarkFixtures {
    fn default() -> Self {
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
        Self {
            vk,
            proof,
            public_inputs: Vec::new(),
        }
    }
}
