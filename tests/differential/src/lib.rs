//! Differential testing helpers.
//!
//! The strategy: generate a small but non-trivial R1CS circuit, produce a
//! valid Groth16 proof via arkworks, then verify the same proof with both:
//!
//! 1. The arkworks reference verifier (must succeed).
//! 2. Mosaic's [`Groth16Verifier`] over the [`HostBackend`] (must also
//!    succeed and produce identical "ok" / "error" classification).
//!
//! Any divergence is a test failure.
//!
//! # Why a custom circuit?
//!
//! We use a hand-rolled `R1CSConstraintSynthesizer` that proves knowledge
//! of two field elements `a, b` whose product equals a public input `c`.
//! Tiny, deterministic, and avoids pulling Circom into the test harness.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey as ArkVk};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use mosaic_core::{
    proof_system::ProofSystem,
    syscall::host::HostBackend,
};
use mosaic_groth16::Groth16Verifier;
use mosaic_serde::arkworks::ArkworksCodec;

/// Multiplication circuit: prove that `a * b == c` for a public `c`.
#[derive(Clone, Copy)]
pub struct MulCircuit {
    /// Witness factor `a`. `None` during setup.
    pub a: Option<Fr>,
    /// Witness factor `b`. `None` during setup.
    pub b: Option<Fr>,
    /// Public product `c = a * b`. `None` during setup.
    pub c: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MulCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

/// Generate proving + verifying keys for the multiplication circuit.
pub fn setup(seed: u64) -> (ProvingKey<Bn254>, ArkVk<Bn254>) {
    let mut rng = StdRng::seed_from_u64(seed);
    Groth16::<Bn254>::circuit_specific_setup(
        MulCircuit { a: None, b: None, c: None },
        &mut rng,
    )
    .expect("Groth16 setup")
}

/// Produce a valid proof for `a * b == c`.
pub fn prove(pk: &ProvingKey<Bn254>, a: u64, b: u64, seed: u64) -> ark_groth16::Proof<Bn254> {
    let mut rng = StdRng::seed_from_u64(seed);
    let a_fr = Fr::from(a);
    let b_fr = Fr::from(b);
    let c_fr = a_fr * b_fr;
    Groth16::<Bn254>::prove(
        pk,
        MulCircuit { a: Some(a_fr), b: Some(b_fr), c: Some(c_fr) },
        &mut rng,
    )
    .expect("Groth16 prove")
}

/// Verify with both backends. Returns `(ark_ok, mosaic_ok)`.
///
/// The two booleans must always agree; the caller asserts equality.
pub fn cross_verify(
    vk: &ArkVk<Bn254>,
    proof: &ark_groth16::Proof<Bn254>,
    public_inputs: &[Fr],
) -> (bool, bool) {
    let ark_ok = Groth16::<Bn254>::verify(vk, public_inputs, proof).unwrap_or(false);

    let canonical_vk = ArkworksCodec::encode_vk(vk);
    let canonical_proof = ArkworksCodec::encode_proof(proof);
    let canonical_pi = ArkworksCodec::encode_public_inputs(public_inputs);

    let backend = HostBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);
    let mosaic_ok = ProofSystem::verify(&verifier, &canonical_vk, &canonical_proof, &canonical_pi)
        .is_ok();

    (ark_ok, mosaic_ok)
}
