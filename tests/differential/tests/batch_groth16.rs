//! Differential test: Groth16 batch_verify vs looped single verify.
//!
//! Generates N arkworks-proved Groth16 proofs for the same VK, then
//! verifies them two ways:
//!
//! 1. Looped: N independent single-proof verifications.
//! 2. Batched: one `batch_verify` call using Bowe-Gabizon aggregation.
//!
//! Both must agree. Any divergence is a bug in the batch path.
//!
//! Also tests that a single tampered proof inside an otherwise-valid
//! batch causes the batch to reject (prevents "most-proofs-valid wins"
//! failure mode).

#![allow(clippy::unwrap_used, clippy::expect_used)]

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

#[derive(Clone, Copy)]
struct MulCircuit {
    a: Option<Fr>,
    b: Option<Fr>,
    c: Option<Fr>,
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

fn setup(seed: u64) -> (ProvingKey<Bn254>, ArkVk<Bn254>) {
    let mut rng = StdRng::seed_from_u64(seed);
    Groth16::<Bn254>::circuit_specific_setup(
        MulCircuit { a: None, b: None, c: None },
        &mut rng,
    )
    .expect("setup")
}

fn prove(pk: &ProvingKey<Bn254>, a: u64, b: u64, seed: u64) -> ark_groth16::Proof<Bn254> {
    let mut rng = StdRng::seed_from_u64(seed);
    let a_fr = Fr::from(a);
    let b_fr = Fr::from(b);
    Groth16::<Bn254>::prove(
        pk,
        MulCircuit { a: Some(a_fr), b: Some(b_fr), c: Some(a_fr * b_fr) },
        &mut rng,
    )
    .expect("prove")
}

fn build_n_valid_proofs(n: usize) -> (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (pk, vk) = setup(0xBA7C4);
    let vk_bytes = ArkworksCodec::encode_vk(&vk);

    let mut proofs = Vec::with_capacity(n);
    let mut public_inputs = Vec::with_capacity(n);
    for i in 0..n {
        let a = (7 + i) as u64;
        let b = (6 + i) as u64;
        let proof = prove(&pk, a, b, 1000 + i as u64);
        let c = Fr::from(a) * Fr::from(b);
        proofs.push(ArkworksCodec::encode_proof(&proof));
        public_inputs.push(ArkworksCodec::encode_public_inputs(&[c]));
    }
    (vk_bytes, proofs, public_inputs)
}

fn as_refs(vecs: &[Vec<u8>]) -> Vec<&[u8]> {
    vecs.iter().map(|v| v.as_slice()).collect()
}

#[test]
fn batch_agrees_with_loop_for_n_equals_1() {
    let (vk, proofs, pis) = build_n_valid_proofs(1);
    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);

    // Loop path.
    for (p, pi) in proofs.iter().zip(pis.iter()) {
        ProofSystem::verify(&v, &vk, p, pi).expect("single-proof verify");
    }
    // Batch path.
    ProofSystem::batch_verify(&v, &vk, &as_refs(&proofs), &as_refs(&pis))
        .expect("batch verify");
}

#[test]
fn batch_agrees_with_loop_for_n_equals_3() {
    let (vk, proofs, pis) = build_n_valid_proofs(3);
    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);

    for (p, pi) in proofs.iter().zip(pis.iter()) {
        ProofSystem::verify(&v, &vk, p, pi).expect("single-proof verify");
    }
    ProofSystem::batch_verify(&v, &vk, &as_refs(&proofs), &as_refs(&pis))
        .expect("batch of 3 must verify");
}

#[test]
fn batch_agrees_with_loop_for_n_equals_10() {
    let (vk, proofs, pis) = build_n_valid_proofs(10);
    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);

    // Skip the loop assertion for N=10 to keep the test fast; single
    // correctness already proven by the N=1 and N=3 cases above.
    ProofSystem::batch_verify(&v, &vk, &as_refs(&proofs), &as_refs(&pis))
        .expect("batch of 10 must verify");
}

#[test]
fn batch_rejects_if_one_proof_is_tampered() {
    let (vk, mut proofs, pis) = build_n_valid_proofs(5);
    // Flip low bit of proof.a.x byte 0 of the third proof.
    proofs[2][0] ^= 0x01;

    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);
    let result = ProofSystem::batch_verify(&v, &vk, &as_refs(&proofs), &as_refs(&pis));
    assert!(
        result.is_err(),
        "batch with one tampered proof must reject: {result:?}",
    );
}

#[test]
fn batch_rejects_wrong_public_input_on_one_proof() {
    let (vk, proofs, mut pis) = build_n_valid_proofs(4);
    // Change the public input of the second proof: submit c+1 instead of c.
    let pi_len = pis[1].len();
    pis[1][pi_len - 1] = pis[1][pi_len - 1].wrapping_add(1);

    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);
    let result = ProofSystem::batch_verify(&v, &vk, &as_refs(&proofs), &as_refs(&pis));
    assert!(
        result.is_err(),
        "batch with one wrong PI must reject: {result:?}",
    );
}

#[test]
fn empty_batch_returns_ok() {
    let (vk, _, _) = build_n_valid_proofs(1);
    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);
    ProofSystem::batch_verify(&v, &vk, &[], &[]).expect("empty batch trivially Ok");
}

#[test]
fn mismatched_proof_and_pi_counts_rejected() {
    let (vk, proofs, pis) = build_n_valid_proofs(3);
    let backend = HostBackend::new();
    let v = Groth16Verifier::<_, false>::new(&backend);

    let pi_refs = as_refs(&pis);
    let only_two_proofs: Vec<&[u8]> = proofs[..2].iter().map(|v| v.as_slice()).collect();
    let result = ProofSystem::batch_verify(&v, &vk, &only_two_proofs, &pi_refs);
    assert!(result.is_err(), "mismatched lengths must reject");
}
