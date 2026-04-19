//! arkworks `CanonicalSerialize` adapter for Groth16 over BN254.
//!
//! arkworks emits proofs in **little-endian** uncompressed canonical form.
//! We swap to big-endian to match Mosaic canonical (which mirrors the current
//! Solana syscall convention).

#![cfg(feature = "host-backend")]

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof as ArkProof, VerifyingKey as ArkVk};
use ark_serialize::CanonicalDeserialize;
use mosaic_core::{
    codec::{DecodedArtifacts, FormatTag, ProofCodec},
    OnChainError,
};
use std::vec::Vec;

/// arkworks-format codec.
#[derive(Copy, Clone, Debug, Default)]
pub struct ArkworksCodec;

impl ArkworksCodec {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convert an in-memory arkworks Groth16 proof to canonical bytes.
    pub fn encode_proof(proof: &ArkProof<Bn254>) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&g1_to_be64(&proof.a));
        out.extend_from_slice(&g2_to_be128(&proof.b));
        out.extend_from_slice(&g1_to_be64(&proof.c));
        out
    }

    /// Convert an in-memory arkworks VK to canonical bytes.
    pub fn encode_vk(vk: &ArkVk<Bn254>) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 128 * 3 + 64 * vk.gamma_abc_g1.len());
        out.extend_from_slice(&g1_to_be64(&vk.alpha_g1));
        out.extend_from_slice(&g2_to_be128(&vk.beta_g2));
        out.extend_from_slice(&g2_to_be128(&vk.gamma_g2));
        out.extend_from_slice(&g2_to_be128(&vk.delta_g2));
        for ic in &vk.gamma_abc_g1 {
            out.extend_from_slice(&g1_to_be64(ic));
        }
        out
    }

    /// Convert an arkworks public-input vector to canonical bytes.
    pub fn encode_public_inputs(inputs: &[Fr]) -> Vec<u8> {
        let mut out = Vec::with_capacity(inputs.len() * 32);
        for fr in inputs {
            let mut buf = fr.into_bigint().to_bytes_le();
            buf.resize(32, 0);
            buf.reverse();
            out.extend_from_slice(&buf);
        }
        out
    }

    /// Bundle decoder from CanonicalSerialize byte streams.
    pub fn decode_bundle(
        proof_bytes: &[u8],
        vk_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<DecodedArtifacts, OnChainError> {
        let codec = Self::new();
        Ok(DecodedArtifacts {
            vk: codec.decode_vk(vk_bytes)?,
            proof: codec.decode_proof(proof_bytes)?,
            public_inputs: codec.decode_public_inputs(public_inputs_bytes)?,
        })
    }
}

impl ProofCodec for ArkworksCodec {
    fn format(&self) -> FormatTag {
        FormatTag::Arkworks
    }

    fn decode_proof(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        let proof = ArkProof::<Bn254>::deserialize_compressed(source)
            .or_else(|_| ArkProof::<Bn254>::deserialize_uncompressed(source))
            .map_err(|_| OnChainError::InvalidPointEncoding)?;
        Ok(Self::encode_proof(&proof))
    }

    fn decode_vk(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        let vk = ArkVk::<Bn254>::deserialize_compressed(source)
            .or_else(|_| ArkVk::<Bn254>::deserialize_uncompressed(source))
            .map_err(|_| OnChainError::InvalidPointEncoding)?;
        Ok(Self::encode_vk(&vk))
    }

    fn decode_public_inputs(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        let inputs = Vec::<Fr>::deserialize_uncompressed(source)
            .map_err(|_| OnChainError::InvalidFieldEncoding)?;
        Ok(Self::encode_public_inputs(&inputs))
    }
}

fn g1_to_be64(point: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    let (x, y) = point.xy().unwrap_or((ark_bn254::Fq::default(), ark_bn254::Fq::default()));
    let mut x_bytes = x.into_bigint().to_bytes_le();
    let mut y_bytes = y.into_bigint().to_bytes_le();
    x_bytes.resize(32, 0);
    y_bytes.resize(32, 0);
    x_bytes.reverse();
    y_bytes.reverse();
    out[..32].copy_from_slice(&x_bytes);
    out[32..].copy_from_slice(&y_bytes);
    out
}

fn g2_to_be128(point: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    let (x, y) = point.xy().unwrap_or((ark_bn254::Fq2::default(), ark_bn254::Fq2::default()));
    let mut x_c0 = x.c0.into_bigint().to_bytes_le();
    let mut x_c1 = x.c1.into_bigint().to_bytes_le();
    let mut y_c0 = y.c0.into_bigint().to_bytes_le();
    let mut y_c1 = y.c1.into_bigint().to_bytes_le();
    for v in [&mut x_c0, &mut x_c1, &mut y_c0, &mut y_c1] {
        v.resize(32, 0);
        v.reverse();
    }
    // Solana alt_bn128 G2 layout: x.c1 || x.c0 || y.c1 || y.c0.
    out[..32].copy_from_slice(&x_c1);
    out[32..64].copy_from_slice(&x_c0);
    out[64..96].copy_from_slice(&y_c1);
    out[96..128].copy_from_slice(&y_c0);
    out
}
