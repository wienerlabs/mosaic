//! Round-trip integration test for the snarkjs PLONK decoder against
//! real snarkjs 0.7.6 output.
//!
//! Reads `tests/fixtures/plonk/mul-circuit/snarkjs/` and verifies the
//! decoder produces canonical bytes that parse cleanly via
//! `mosaic_plonk::canonical` types. Does not yet exercise full
//! verification — that lands in PLONK session 2d alongside the
//! linearization + pairing implementation.

#![cfg(feature = "host-backend")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use mosaic_serde::snarkjs::SnarkjsPlonkCodec;
use std::{fs, path::PathBuf};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/plonk/mul-circuit/snarkjs")
}

fn read(name: &str) -> Vec<u8> {
    fs::read(fixture_path().join(name))
        .unwrap_or_else(|_| panic!("fixture {name} not found"))
}

#[test]
fn snarkjs_plonk_proof_decodes_to_canonical_768_bytes() {
    let proof_json = read("proof.json");
    let canonical = SnarkjsPlonkCodec::decode_proof(&proof_json).unwrap();
    assert_eq!(canonical.len(), 768, "canonical proof length");
}

#[test]
fn snarkjs_plonk_vk_decodes_to_canonical_744_bytes() {
    let vk_json = read("verification_key.json");
    let canonical = SnarkjsPlonkCodec::decode_vk(&vk_json).unwrap();
    assert_eq!(canonical.len(), 744, "canonical VK header length");
}

#[test]
fn snarkjs_plonk_public_inputs_decode_single_fr() {
    let pi_json = read("public.json");
    let canonical = SnarkjsPlonkCodec::decode_public_inputs(&pi_json).unwrap();
    assert_eq!(canonical.len(), 32, "single public input = 32 B");
    // c = 42, big-endian 32-byte representation ends with 0x2A.
    assert_eq!(canonical[31], 42);
    // Leading 31 bytes should be zero for a small value.
    for b in &canonical[..31] {
        assert_eq!(*b, 0);
    }
}

#[test]
fn decoded_vk_parses_via_canonical_plonk_vk() {
    use mosaic_plonk::canonical::PlonkVerifyingKey;
    let vk_json = read("verification_key.json");
    let canonical = SnarkjsPlonkCodec::decode_vk(&vk_json).unwrap();
    let vk = PlonkVerifyingKey::from_bytes(&canonical).unwrap();
    assert_eq!(vk.n_public, 1);
    assert_eq!(vk.power, 3);
    // k1 = "2" → 32-byte BE ending with 0x02.
    assert_eq!(vk.k1[31], 2);
    // k2 = "3" → 32-byte BE ending with 0x03.
    assert_eq!(vk.k2[31], 3);
}

#[test]
fn decoded_proof_parses_via_canonical_plonk_proof() {
    use mosaic_plonk::canonical::PlonkProof;
    let proof_json = read("proof.json");
    let canonical = SnarkjsPlonkCodec::decode_proof(&proof_json).unwrap();
    let p = PlonkProof::from_bytes(&canonical).unwrap();
    // G1 slices are all 64 bytes by construction.
    for g1 in [p.a, p.b, p.c, p.z, p.t1, p.t2, p.t3, p.w_xi, p.w_xiw] {
        assert_eq!(g1.len(), 64);
    }
    // Fr slices are all 32 bytes.
    for fr in [p.eval_a, p.eval_b, p.eval_c, p.eval_s1, p.eval_s2, p.eval_zw] {
        assert_eq!(fr.len(), 32);
    }
}

#[test]
fn proof_rejects_wrong_protocol() {
    let wrong = br#"{
        "A":["1","1","1"],"B":["1","1","1"],"C":["1","1","1"],
        "Z":["1","1","1"],"T1":["1","1","1"],"T2":["1","1","1"],"T3":["1","1","1"],
        "Wxi":["1","1","1"],"Wxiw":["1","1","1"],
        "eval_a":"1","eval_b":"1","eval_c":"1",
        "eval_s1":"1","eval_s2":"1","eval_zw":"1",
        "protocol":"groth16","curve":"bn128"
    }"#;
    assert!(SnarkjsPlonkCodec::decode_proof(wrong).is_err());
}
