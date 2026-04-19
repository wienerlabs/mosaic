//! `snarkjs` JSON adapter for Groth16 over BN254.
//!
//! Decodes the JSON layout that `snarkjs groth16 export` emits and produces
//! Mosaic canonical bytes (see [`mosaic_core::codec`]).
//!
//! ## Format reference
//!
//! `snarkjs` represents field elements as **decimal strings**, big-endian
//! integers. G1 points are `[x, y, z]` (Jacobian, but z is always "1" for
//! affine output); G2 points are `[[x.c0, x.c1], [y.c0, y.c1], [z.c0, z.c1]]`.
//! The `c0 || c1` ordering matters — different snarkjs versions have flipped
//! it; we follow the post-1.0.0 layout (c0 first).

use mosaic_core::{
    codec::{DecodedArtifacts, FormatTag, ProofCodec},
    OnChainError,
};
use num_bigint::BigUint;
use serde::Deserialize;
use std::vec::Vec;

/// snarkjs Groth16 proof JSON.
#[derive(Debug, Deserialize)]
pub struct SnarkjsProof {
    /// G1 point `(x, y, z)` as decimal-string components.
    pub pi_a: [String; 3],
    /// G2 point: `((x.c0, x.c1), (y.c0, y.c1), (z.c0, z.c1))`.
    pub pi_b: [[String; 2]; 3],
    /// G1 point `(x, y, z)`.
    pub pi_c: [String; 3],
    /// Protocol tag — must equal `"groth16"`.
    pub protocol: String,
    /// Curve tag — must equal `"bn128"`.
    pub curve: String,
}

/// snarkjs Groth16 verifying-key JSON.
#[derive(Debug, Deserialize)]
pub struct SnarkjsVk {
    /// Protocol tag — must equal `"groth16"`.
    pub protocol: String,
    /// Curve tag — must equal `"bn128"`.
    pub curve: String,
    /// Number of public inputs.
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    /// G1 element α.
    pub vk_alpha_1: [String; 3],
    /// G2 element β.
    pub vk_beta_2: [[String; 2]; 3],
    /// G2 element γ.
    pub vk_gamma_2: [[String; 2]; 3],
    /// G2 element δ.
    pub vk_delta_2: [[String; 2]; 3],
    /// IC vector (length `nPublic + 1`).
    #[serde(rename = "IC")]
    pub ic: Vec<[String; 3]>,
}

/// snarkjs JSON-format codec.
#[derive(Copy, Clone, Debug, Default)]
pub struct SnarkjsCodec;

impl SnarkjsCodec {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convert a snarkjs proof+vk+public-inputs bundle to canonical bytes.
    pub fn decode_bundle(
        proof_json: &[u8],
        vk_json: &[u8],
        public_inputs_json: &[u8],
    ) -> Result<DecodedArtifacts, OnChainError> {
        let codec = Self::new();
        Ok(DecodedArtifacts {
            vk: codec.decode_vk(vk_json)?,
            proof: codec.decode_proof(proof_json)?,
            public_inputs: codec.decode_public_inputs(public_inputs_json)?,
        })
    }
}

impl ProofCodec for SnarkjsCodec {
    fn format(&self) -> FormatTag {
        FormatTag::SnarkjsJson
    }

    fn decode_proof(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        let p: SnarkjsProof =
            serde_json::from_slice(source).map_err(|_| OnChainError::InvalidPointEncoding)?;
        if p.protocol != "groth16" || p.curve != "bn128" {
            return Err(OnChainError::UnsupportedOperation);
        }
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&encode_g1_dec(&p.pi_a)?);
        out.extend_from_slice(&encode_g2_dec(&p.pi_b)?);
        out.extend_from_slice(&encode_g1_dec(&p.pi_c)?);
        Ok(out)
    }

    fn decode_vk(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        let v: SnarkjsVk =
            serde_json::from_slice(source).map_err(|_| OnChainError::InvalidPointEncoding)?;
        if v.protocol != "groth16" || v.curve != "bn128" {
            return Err(OnChainError::UnsupportedOperation);
        }
        if v.ic.len() != v.n_public + 1 {
            return Err(OnChainError::PublicInputCountMismatch);
        }
        let mut out = Vec::with_capacity(64 + 128 * 3 + 64 * v.ic.len());
        out.extend_from_slice(&encode_g1_dec(&v.vk_alpha_1)?);
        out.extend_from_slice(&encode_g2_dec(&v.vk_beta_2)?);
        out.extend_from_slice(&encode_g2_dec(&v.vk_gamma_2)?);
        out.extend_from_slice(&encode_g2_dec(&v.vk_delta_2)?);
        for ic in &v.ic {
            out.extend_from_slice(&encode_g1_dec(ic)?);
        }
        Ok(out)
    }

    fn decode_public_inputs(&self, source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        // snarkjs writes public inputs as a JSON array of decimal strings.
        let inputs: Vec<String> =
            serde_json::from_slice(source).map_err(|_| OnChainError::InvalidFieldEncoding)?;
        let mut out = Vec::with_capacity(inputs.len() * 32);
        for s in &inputs {
            out.extend_from_slice(&decimal_to_be_32(s)?);
        }
        Ok(out)
    }
}

/// Decode a snarkjs G1 point `[x, y, z]` (z must be "1") to a 64-byte BE encoding.
fn encode_g1_dec(point: &[String; 3]) -> Result<[u8; 64], OnChainError> {
    if point[2] != "1" {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let x = decimal_to_be_32(&point[0])?;
    let y = decimal_to_be_32(&point[1])?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&x);
    out[32..].copy_from_slice(&y);
    Ok(out)
}

/// Decode a snarkjs G2 point `[[x.c0, x.c1], [y.c0, y.c1], [z.c0, z.c1]]`
/// (z must be `["1","0"]`) to a 128-byte BE encoding.
///
/// Solana syscall convention places `c1` before `c0` in the byte stream;
/// we apply that ordering here.
fn encode_g2_dec(point: &[[String; 2]; 3]) -> Result<[u8; 128], OnChainError> {
    if point[2][0] != "1" || point[2][1] != "0" {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let x_c0 = decimal_to_be_32(&point[0][0])?;
    let x_c1 = decimal_to_be_32(&point[0][1])?;
    let y_c0 = decimal_to_be_32(&point[1][0])?;
    let y_c1 = decimal_to_be_32(&point[1][1])?;
    let mut out = [0u8; 128];
    // Solana alt_bn128 G2 layout: x.c1 || x.c0 || y.c1 || y.c0
    out[..32].copy_from_slice(&x_c1);
    out[32..64].copy_from_slice(&x_c0);
    out[64..96].copy_from_slice(&y_c1);
    out[96..128].copy_from_slice(&y_c0);
    Ok(out)
}

fn decimal_to_be_32(s: &str) -> Result<[u8; 32], OnChainError> {
    let n: BigUint = s.parse().map_err(|_| OnChainError::InvalidFieldEncoding)?;
    let bytes = n.to_bytes_be();
    if bytes.len() > 32 {
        return Err(OnChainError::PublicInputOutOfRange);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_zero() {
        assert_eq!(decimal_to_be_32("0").unwrap(), [0u8; 32]);
    }

    #[test]
    fn decimal_one() {
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(decimal_to_be_32("1").unwrap(), expected);
    }

    #[test]
    fn decimal_overflow_rejected() {
        let too_big = "115792089237316195423570985008687907853269984665640564039457584007913129639937";
        assert!(matches!(
            decimal_to_be_32(too_big),
            Err(OnChainError::PublicInputOutOfRange),
        ));
    }
}
