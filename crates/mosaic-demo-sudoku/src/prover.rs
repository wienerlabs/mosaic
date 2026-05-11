//! arkworks Groth16 prover + Mosaic verifier glue.
//!
//! The setup seed is fixed to make every fixture reproducible: same
//! commit + same `cargo run -p mosaic-demo-sudoku --bin generate-fixtures`
//! produces byte-identical artifacts.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof as ArkProof, ProvingKey, VerifyingKey as ArkVk};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use crate::{circuit::SudokuCircuit, puzzles::Grid};

/// Fixed seed for the Groth16 setup ceremony. Deterministic → every
/// re-run of the generator produces the same VK bytes.
pub const SETUP_SEED: u64 = 0xC0FF_EEDE_AD42_BEEFu64;

/// Fixed seed for proof randomness. Deterministic → every re-run of
/// the generator produces the same proof bytes (modulo arkworks
/// upgrades, which we'd note in the CHANGELOG).
pub const PROVE_SEED: u64 = 0xB16B_00B5_DEAD_C0DEu64;

/// Run Groth16 setup against the SudokuCircuit. Uses
/// `circuit_specific_setup` (the variant that takes a circuit shape
/// rather than a pre-computed `ProverKey`), so the toxic waste is
/// generated and immediately discarded inside the call. Deterministic
/// given `SETUP_SEED` + circuit shape.
pub fn setup(clues: Grid) -> (ProvingKey<Bn254>, ArkVk<Bn254>) {
    let mut rng = StdRng::seed_from_u64(SETUP_SEED);
    let circuit = SudokuCircuit { clues, solution: None };
    Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
        .expect("Groth16 setup must succeed for a well-formed circuit")
}

/// Generate a Groth16 proof of knowledge of `solution` for the given
/// puzzle. The public input vector is the 81 clue values in
/// row-major order, each lifted to Fr.
pub fn prove(
    pk: &ProvingKey<Bn254>,
    clues: Grid,
    solution: Grid,
) -> ArkProof<Bn254> {
    let mut rng = StdRng::seed_from_u64(PROVE_SEED);
    let circuit = SudokuCircuit { clues, solution: Some(solution) };
    Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .expect("Groth16 prove must succeed when the witness satisfies")
}

/// Compute the 81-element public-input vector that the verifier sees.
#[must_use]
pub fn public_inputs(clues: Grid) -> Vec<Fr> {
    clues.iter().map(|&c| Fr::from(u64::from(c))).collect()
}

/// Verify with arkworks' reference verifier. Returns `true` iff the
/// proof is accepted.
#[must_use]
pub fn verify_arkworks(
    vk: &ArkVk<Bn254>,
    proof: &ArkProof<Bn254>,
    public: &[Fr],
) -> bool {
    Groth16::<Bn254>::verify(vk, public, proof).unwrap_or(false)
}

/// Verify with Mosaic's [`Groth16Verifier`] over canonical bytes.
/// Returns `Ok(())` on accept, an [`OnChainError`] on reject. The
/// byte format is identical to what `mosaic-program` accepts on
/// chain — verifying with this function tests exactly the same code
/// path the SBF runtime would.
pub fn verify_mosaic(
    canonical_vk: &[u8],
    canonical_proof: &[u8],
    canonical_public_inputs: &[u8],
) -> Result<(), mosaic_core::OnChainError> {
    use mosaic_core::{proof_system::ProofSystem, syscall::host::HostBackend};
    use mosaic_groth16::Groth16Verifier;
    let backend = HostBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);
    ProofSystem::verify(&verifier, canonical_vk, canonical_proof, canonical_public_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::puzzles::{PUZZLE_INKALA_2010, SOLUTION_INKALA_2010};
    use mosaic_serde::arkworks::ArkworksCodec;

    #[test]
    fn end_to_end_setup_prove_verify_via_mosaic() {
        // 1. Setup against the public puzzle shape.
        let (pk, vk) = setup(PUZZLE_INKALA_2010);

        // 2. Prover proves knowledge of the solution.
        let proof = prove(&pk, PUZZLE_INKALA_2010, SOLUTION_INKALA_2010);

        // 3. Both verifiers accept.
        let public = public_inputs(PUZZLE_INKALA_2010);
        assert!(verify_arkworks(&vk, &proof, &public));

        let canonical_vk = ArkworksCodec::encode_vk(&vk);
        let canonical_proof = ArkworksCodec::encode_proof(&proof);
        let canonical_pi = ArkworksCodec::encode_public_inputs(&public);
        verify_mosaic(&canonical_vk, &canonical_proof, &canonical_pi)
            .expect("Mosaic must accept the same proof arkworks accepts");
    }

    #[test]
    fn tampered_proof_rejects_via_mosaic() {
        let (pk, vk) = setup(PUZZLE_INKALA_2010);
        let proof = prove(&pk, PUZZLE_INKALA_2010, SOLUTION_INKALA_2010);
        let public = public_inputs(PUZZLE_INKALA_2010);

        let canonical_vk = ArkworksCodec::encode_vk(&vk);
        let mut canonical_proof = ArkworksCodec::encode_proof(&proof);
        let canonical_pi = ArkworksCodec::encode_public_inputs(&public);

        // Flip a bit in proof.a's first byte. Mosaic should reject —
        // either via PairingCheckFailed (the canonical case) or via
        // PointNotOnCurve / AltBn128SyscallFailed depending on
        // where the flipped point lands.
        canonical_proof[0] ^= 0x01;
        let result = verify_mosaic(&canonical_vk, &canonical_proof, &canonical_pi);
        assert!(
            result.is_err(),
            "tampered proof must NOT verify; got {result:?}",
        );
    }
}
