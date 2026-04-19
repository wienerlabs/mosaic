//! # mosaic-fuzz
//!
//! cargo-fuzz harnesses for the Mosaic verifier suite.
//!
//! Three harnesses are wired in `fuzz_targets/`:
//!
//! - `fuzz_groth16_proof_bytes` — feed arbitrary bytes as proof; expect
//!   `Err(_)` or panic-free success.
//! - `fuzz_vk_bytes` — feed arbitrary bytes as VK; same expectation.
//! - `fuzz_public_inputs` — fix VK + proof, vary public inputs.
//!
//! The harnesses share the [`SharedFixtures`] helper to avoid recomputing
//! valid fixture material on every iteration.

#![forbid(unsafe_code)]

use mosaic_groth16::{
    canonical::Groth16VerifyingKey,
    sizes::{FR_LEN, G1_LEN, G2_LEN, PROOF_LEN},
};

/// Shared test fixtures for the fuzz harnesses.
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
        Self { vk, proof: vec![0u8; PROOF_LEN], public_inputs: vec![0u8; FR_LEN] }
    }
}
