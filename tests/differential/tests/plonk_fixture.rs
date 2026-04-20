//! End-to-end PLONK verifier differential test against the committed
//! snarkjs 0.7.6 fixture.
//!
//! Reads `tests/fixtures/plonk/mul-circuit/snarkjs/` via the
//! `SnarkjsPlonkCodec` adapter, produces canonical bytes, and feeds them
//! to the `PlonkKzgBn254` verifier running on the arkworks host backend.
//!
//! This is the **correctness gate** for PLONK session 2: when this test
//! passes, the full verifier — transcript, Fr arithmetic, linearization
//! MSM, KZG pairing — is byte-for-byte compatible with snarkjs and
//! ready to wire into `mosaic-program`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use mosaic_core::syscall::host::HostBackend;
use mosaic_plonk::PlonkKzgBn254;
use mosaic_serde::snarkjs::SnarkjsPlonkCodec;
use std::{fs, path::PathBuf};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/plonk/mul-circuit/snarkjs")
}

fn read(name: &str) -> Vec<u8> {
    fs::read(fixture_root().join(name))
        .unwrap_or_else(|_| panic!("missing fixture {name}"))
}

#[test]
fn snarkjs_plonk_fixture_verifies_on_host_backend() {
    let vk_canon = SnarkjsPlonkCodec::decode_vk(&read("verification_key.json")).unwrap();
    let proof_canon = SnarkjsPlonkCodec::decode_proof(&read("proof.json")).unwrap();
    let pi_canon = SnarkjsPlonkCodec::decode_public_inputs(&read("public.json")).unwrap();

    let backend = HostBackend::new();
    let verifier = PlonkKzgBn254::new(&backend);

    verifier
        .verify(&vk_canon, &proof_canon, &pi_canon)
        .expect("committed snarkjs PLONK fixture must verify");

    // Regenerate canonical bytes on disk for bpf-bench + SBF integration
    // tests (gated by env var so `cargo test` doesn't mutate committed
    // files unprompted).
    if std::env::var("MOSAIC_REGEN_FIXTURES").ok().as_deref() == Some("1") {
        let canonical_dir = fixture_root()
            .parent()
            .unwrap()
            .join("canonical");
        fs::create_dir_all(&canonical_dir).unwrap();
        fs::write(canonical_dir.join("vk.bin"), &vk_canon).unwrap();
        fs::write(canonical_dir.join("proof.bin"), &proof_canon).unwrap();
        fs::write(canonical_dir.join("public_inputs.bin"), &pi_canon).unwrap();
        eprintln!("wrote canonical PLONK fixtures to {canonical_dir:?}");
    }
}

#[test]
fn snarkjs_plonk_fixture_rejects_tampered_proof_a() {
    let vk_canon = SnarkjsPlonkCodec::decode_vk(&read("verification_key.json")).unwrap();
    let mut proof_canon = SnarkjsPlonkCodec::decode_proof(&read("proof.json")).unwrap();
    let pi_canon = SnarkjsPlonkCodec::decode_public_inputs(&read("public.json")).unwrap();

    // Flip low bit of proof.A.x byte 0.
    proof_canon[0] ^= 0x01;

    let backend = HostBackend::new();
    let verifier = PlonkKzgBn254::new(&backend);

    let result = verifier.verify(&vk_canon, &proof_canon, &pi_canon);
    assert!(
        result.is_err(),
        "tampered proof must not verify: {result:?}",
    );
}

#[test]
fn snarkjs_plonk_fixture_rejects_wrong_public_input() {
    let vk_canon = SnarkjsPlonkCodec::decode_vk(&read("verification_key.json")).unwrap();
    let proof_canon = SnarkjsPlonkCodec::decode_proof(&read("proof.json")).unwrap();

    // Submit c = 43 instead of c = 42.
    let mut pi_bad = [0u8; 32];
    pi_bad[31] = 43;

    let backend = HostBackend::new();
    let verifier = PlonkKzgBn254::new(&backend);

    let result = verifier.verify(&vk_canon, &proof_canon, &pi_bad);
    assert!(result.is_err(), "wrong PI must not verify: {result:?}");
}
