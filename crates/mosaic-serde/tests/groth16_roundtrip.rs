//! Round-trip integration tests for the Groth16 format adapters.
//!
//! Generates a real Groth16 proof with arkworks, then verifies that both
//! format adapters (`ArkworksCodec`, `SnarkjsCodec`) decode to byte-equal
//! canonical Mosaic bytes, and those bytes verify successfully via the
//! `mosaic-groth16` host backend.
//!
//! Run with:
//!
//! ```text
//! cargo test -p mosaic-serde --features host-backend --test groth16_roundtrip
//! ```
//!
//! To regenerate the static fixture corpus on disk:
//!
//! ```text
//! MOSAIC_REGEN_FIXTURES=1 cargo test -p mosaic-serde \
//!     --features host-backend --test groth16_roundtrip
//! ```

#![cfg(feature = "host-backend")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof as ArkProof, VerifyingKey as ArkVk};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use mosaic_core::{codec::ProofCodec, proof_system::ProofSystem, syscall::host::HostBackend};
use mosaic_groth16::Groth16Verifier;
use mosaic_serde::{arkworks::ArkworksCodec, snarkjs::SnarkjsCodec};
use num_bigint::BigUint;
use std::{fs, path::PathBuf};

/// Proves `a * b == c`. Same circuit the differential harness uses.
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

/// Full fixture bundle in all formats. Generated deterministically from a seed.
struct FixtureBundle {
    vk: ArkVk<Bn254>,
    proof: ArkProof<Bn254>,
    public_inputs: Vec<Fr>,
    a: u64,
    b: u64,
}

fn generate() -> FixtureBundle {
    // Deterministic seeds — identical output across platforms.
    let mut setup_rng = StdRng::seed_from_u64(2026_04_20);
    let mut prove_rng = StdRng::seed_from_u64(2026_04_21);
    let (a, b) = (7_u64, 6_u64);

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        MulCircuit {
            a: None,
            b: None,
            c: None,
        },
        &mut setup_rng,
    )
    .expect("setup");

    let a_fr = Fr::from(a);
    let b_fr = Fr::from(b);
    let c_fr = a_fr * b_fr;

    let proof = Groth16::<Bn254>::prove(
        &pk,
        MulCircuit {
            a: Some(a_fr),
            b: Some(b_fr),
            c: Some(c_fr),
        },
        &mut prove_rng,
    )
    .expect("prove");

    FixtureBundle {
        vk,
        proof,
        public_inputs: vec![c_fr],
        a,
        b,
    }
}

// ---------- snarkjs JSON encoding helpers ----------
//
// snarkjs 1.x emits field elements as decimal strings and G2 points as
// `[[x.c0, x.c1], [y.c0, y.c1], [z.c0, z.c1]]`.

fn fr_to_decimal(fr: &Fr) -> String {
    BigUint::from_bytes_be(&{
        let mut b = fr.into_bigint().to_bytes_be();
        b.resize(32, 0);
        b
    })
    .to_string()
}

fn fq_to_decimal(fq: &ark_bn254::Fq) -> String {
    BigUint::from_bytes_be(&{
        let mut b = fq.into_bigint().to_bytes_be();
        b.resize(32, 0);
        b
    })
    .to_string()
}

fn g1_to_snarkjs_json(point: &G1Affine) -> serde_json::Value {
    let (x, y) = point
        .xy()
        .unwrap_or((ark_bn254::Fq::default(), ark_bn254::Fq::default()));
    serde_json::json!([fq_to_decimal(&x), fq_to_decimal(&y), "1"])
}

fn g2_to_snarkjs_json(point: &G2Affine) -> serde_json::Value {
    let (x, y) = point
        .xy()
        .unwrap_or((ark_bn254::Fq2::default(), ark_bn254::Fq2::default()));
    serde_json::json!([
        [fq_to_decimal(&x.c0), fq_to_decimal(&x.c1)],
        [fq_to_decimal(&y.c0), fq_to_decimal(&y.c1)],
        ["1", "0"],
    ])
}

fn proof_to_snarkjs_json(proof: &ArkProof<Bn254>) -> serde_json::Value {
    serde_json::json!({
        "pi_a":     g1_to_snarkjs_json(&proof.a),
        "pi_b":     g2_to_snarkjs_json(&proof.b),
        "pi_c":     g1_to_snarkjs_json(&proof.c),
        "protocol": "groth16",
        "curve":    "bn128",
    })
}

fn vk_to_snarkjs_json(vk: &ArkVk<Bn254>) -> serde_json::Value {
    let ic: Vec<serde_json::Value> = vk.gamma_abc_g1.iter().map(g1_to_snarkjs_json).collect();
    serde_json::json!({
        "protocol":    "groth16",
        "curve":       "bn128",
        "nPublic":     vk.gamma_abc_g1.len() - 1,
        "vk_alpha_1":  g1_to_snarkjs_json(&vk.alpha_g1),
        "vk_beta_2":   g2_to_snarkjs_json(&vk.beta_g2),
        "vk_gamma_2":  g2_to_snarkjs_json(&vk.gamma_g2),
        "vk_delta_2":  g2_to_snarkjs_json(&vk.delta_g2),
        "IC":          ic,
    })
}

fn public_inputs_to_snarkjs_json(pi: &[Fr]) -> serde_json::Value {
    serde_json::Value::Array(
        pi.iter()
            .map(|fr| serde_json::Value::String(fr_to_decimal(fr)))
            .collect(),
    )
}

// ---------- arkworks canonical-serialize helpers ----------

fn ark_serialize_uncompressed<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(value.uncompressed_size());
    value
        .serialize_uncompressed(&mut buf)
        .expect("ark serialize");
    buf
}

// ---------- fixture on-disk layout ----------

fn fixtures_root() -> PathBuf {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    workspace_root
        .join("tests")
        .join("fixtures")
        .join("groth16")
        .join("mul-circuit")
}

fn write_if_regen(path: PathBuf, bytes: &[u8]) {
    if std::env::var("MOSAIC_REGEN_FIXTURES").ok().as_deref() == Some("1") {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        eprintln!("regenerated {}", path.display());
    }
}

// ---------- tests ----------

/// Happy path: all three paths (direct encode, arkworks adapter, snarkjs
/// adapter) produce byte-equal canonical bytes, and those bytes verify via
/// `mosaic-groth16` host backend.
#[test]
fn roundtrip_arkworks_and_snarkjs_produce_equal_canonical_bytes() {
    let FixtureBundle {
        vk,
        proof,
        public_inputs,
        ..
    } = generate();

    // --- path 1: direct encode from in-memory arkworks types ---
    let canonical_vk_direct = ArkworksCodec::encode_vk(&vk);
    let canonical_proof_direct = ArkworksCodec::encode_proof(&proof);
    let canonical_pi_direct = ArkworksCodec::encode_public_inputs(&public_inputs);

    // --- path 2: via arkworks canonical-serialize bytes → ArkworksCodec ---
    let ark_vk_bytes = ark_serialize_uncompressed(&vk);
    let ark_proof_bytes = ark_serialize_uncompressed(&proof);
    let ark_pi_bytes = ark_serialize_uncompressed(&public_inputs);
    let codec = ArkworksCodec::new();
    let canonical_vk_via_ark = codec.decode_vk(&ark_vk_bytes).unwrap();
    let canonical_proof_via_ark = codec.decode_proof(&ark_proof_bytes).unwrap();
    let canonical_pi_via_ark = codec.decode_public_inputs(&ark_pi_bytes).unwrap();

    // --- path 3: via snarkjs JSON → SnarkjsCodec ---
    let snarkjs_proof_json = proof_to_snarkjs_json(&proof).to_string();
    let snarkjs_vk_json = vk_to_snarkjs_json(&vk).to_string();
    let snarkjs_pi_json = public_inputs_to_snarkjs_json(&public_inputs).to_string();
    let sn_codec = SnarkjsCodec::new();
    let canonical_vk_via_snark = sn_codec.decode_vk(snarkjs_vk_json.as_bytes()).unwrap();
    let canonical_proof_via_snark = sn_codec
        .decode_proof(snarkjs_proof_json.as_bytes())
        .unwrap();
    let canonical_pi_via_snark = sn_codec
        .decode_public_inputs(snarkjs_pi_json.as_bytes())
        .unwrap();

    // --- byte equality across all three paths ---
    assert_eq!(
        canonical_vk_direct, canonical_vk_via_ark,
        "arkworks direct vs arkworks-bytes VK mismatch",
    );
    assert_eq!(
        canonical_vk_direct, canonical_vk_via_snark,
        "arkworks direct vs snarkjs VK mismatch — likely G2 c0/c1 layout bug",
    );
    assert_eq!(canonical_proof_direct, canonical_proof_via_ark);
    assert_eq!(canonical_proof_direct, canonical_proof_via_snark);
    assert_eq!(canonical_pi_direct, canonical_pi_via_ark);
    assert_eq!(canonical_pi_direct, canonical_pi_via_snark);

    // --- Mosaic host-backend verify succeeds on the canonical bytes ---
    let backend = HostBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);
    ProofSystem::verify(
        &verifier,
        &canonical_vk_direct,
        &canonical_proof_direct,
        &canonical_pi_direct,
    )
    .expect("valid proof should verify against canonical bytes");

    // --- regenerate static fixtures if requested ---
    let root = fixtures_root();
    write_if_regen(
        root.join("snarkjs/proof.json"),
        snarkjs_proof_json.as_bytes(),
    );
    write_if_regen(
        root.join("snarkjs/verification_key.json"),
        snarkjs_vk_json.as_bytes(),
    );
    write_if_regen(root.join("snarkjs/public.json"), snarkjs_pi_json.as_bytes());
    write_if_regen(root.join("arkworks/proof.bin"), &ark_proof_bytes);
    write_if_regen(root.join("arkworks/vk.bin"), &ark_vk_bytes);
    write_if_regen(root.join("arkworks/public_inputs.bin"), &ark_pi_bytes);
    write_if_regen(root.join("canonical/proof.bin"), &canonical_proof_direct);
    write_if_regen(root.join("canonical/vk.bin"), &canonical_vk_direct);
    write_if_regen(
        root.join("canonical/public_inputs.bin"),
        &canonical_pi_direct,
    );
}

/// Static fixtures on disk (if committed) must match the freshly-generated
/// bytes. Ensures we don't silently drift from the committed fixture.
#[test]
fn committed_fixtures_match_regenerated_bytes() {
    let root = fixtures_root();
    if !root.join("canonical/proof.bin").exists() {
        eprintln!("no committed fixtures at {}, skipping", root.display());
        return;
    }

    let FixtureBundle {
        vk,
        proof,
        public_inputs,
        ..
    } = generate();
    let direct_proof = ArkworksCodec::encode_proof(&proof);
    let direct_vk = ArkworksCodec::encode_vk(&vk);
    let direct_pi = ArkworksCodec::encode_public_inputs(&public_inputs);

    let committed_proof = fs::read(root.join("canonical/proof.bin")).unwrap();
    let committed_vk = fs::read(root.join("canonical/vk.bin")).unwrap();
    let committed_pi = fs::read(root.join("canonical/public_inputs.bin")).unwrap();

    assert_eq!(
        direct_proof, committed_proof,
        "committed canonical proof drifted — rerun MOSAIC_REGEN_FIXTURES=1 test",
    );
    assert_eq!(direct_vk, committed_vk);
    assert_eq!(direct_pi, committed_pi);
}

/// Negative test: flipping one byte in the proof causes the verifier to
/// reject. Ensures canonical-bytes verification is end-to-end sensitive.
#[test]
fn tampered_proof_byte_is_rejected() {
    let FixtureBundle {
        vk,
        proof,
        public_inputs,
        ..
    } = generate();
    let canonical_vk = ArkworksCodec::encode_vk(&vk);
    let mut canonical_proof = ArkworksCodec::encode_proof(&proof);
    // Flip the low bit of proof.A.x byte 0.
    canonical_proof[0] ^= 0x01;
    let canonical_pi = ArkworksCodec::encode_public_inputs(&public_inputs);

    let backend = HostBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);
    let result = ProofSystem::verify(&verifier, &canonical_vk, &canonical_proof, &canonical_pi);
    assert!(result.is_err(), "tampered proof must be rejected");
}

/// Negative test: wrong public input → reject. Binds the `a,b` values we
/// proved: asking the verifier about `a*b + 1` must fail.
#[test]
fn wrong_public_input_is_rejected() {
    let FixtureBundle {
        vk, proof, a, b, ..
    } = generate();
    let canonical_vk = ArkworksCodec::encode_vk(&vk);
    let canonical_proof = ArkworksCodec::encode_proof(&proof);
    let wrong_c = Fr::from(a) * Fr::from(b) + Fr::from(1_u64);
    let canonical_pi = ArkworksCodec::encode_public_inputs(&[wrong_c]);

    let backend = HostBackend::new();
    let verifier = Groth16Verifier::<_, false>::new(&backend);
    let result = ProofSystem::verify(&verifier, &canonical_vk, &canonical_proof, &canonical_pi);
    assert!(result.is_err(), "wrong public input must be rejected");
}
