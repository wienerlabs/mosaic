//! Differential property tests over the `MulCircuit` fixture.

use ark_bn254::Fr;
use ark_ff::Field;
use mosaic_differential_tests::{cross_verify, prove, setup};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn valid_proof_classifications_match(a in 1u64..1_000, b in 1u64..1_000, seed in 0u64..16) {
        let (pk, vk) = setup(seed);
        let proof = prove(&pk, a, b, seed.wrapping_add(1));
        let c = Fr::from(a) * Fr::from(b);
        let (ark_ok, mosaic_ok) = cross_verify(&vk, &proof, &[c]);
        prop_assert_eq!(
            ark_ok, mosaic_ok,
            "arkworks vs Mosaic divergence on valid proof"
        );
    }

    #[test]
    fn wrong_public_input_classifications_match(a in 1u64..1_000, b in 1u64..1_000, seed in 0u64..16) {
        let (pk, vk) = setup(seed);
        let proof = prove(&pk, a, b, seed.wrapping_add(1));
        // Submit `c+1` instead of `a*b`. Both verifiers must reject.
        let wrong_c = Fr::from(a) * Fr::from(b) + Fr::ONE;
        let (ark_ok, mosaic_ok) = cross_verify(&vk, &proof, &[wrong_c]);
        prop_assert_eq!(ark_ok, mosaic_ok, "ark/mosaic divergence on wrong PI");
        prop_assert!(!ark_ok, "arkworks accepted a wrong-PI proof — fixture broken");
    }
}
