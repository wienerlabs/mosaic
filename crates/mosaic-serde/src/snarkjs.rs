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

/// Decode a snarkjs G1 point `[x, y, z]` to a 64-byte BE encoding.
///
/// snarkjs uses projective coordinates: `z = "1"` for normal affine points,
/// `z = "0"` for the identity / point-at-infinity. We map the identity to
/// 64 zero bytes, matching Solana's `alt_bn128` identity convention.
fn encode_g1_dec(point: &[String; 3]) -> Result<[u8; 64], OnChainError> {
    // Identity: projective z = 0. snarkjs emits these for zero-polynomial
    // commitments (e.g. selectors that are identically zero in the circuit).
    if point[2] == "0" {
        return Ok([0u8; 64]);
    }
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

// ============================================================================
// PLONK decoder — snarkjs 0.7.x JSON format
// ============================================================================

/// snarkjs PLONK proof JSON (`snarkjs plonk prove` output).
///
/// 9 G1 commitments + 6 Fr evaluations, matching the canonical PLONK
/// wire format in `mosaic_plonk::canonical`.
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct SnarkjsPlonkProof {
    /// Witness polynomial commitment A (G1).
    #[serde(rename = "A")]
    pub a: [String; 3],
    /// Witness polynomial commitment B (G1).
    #[serde(rename = "B")]
    pub b: [String; 3],
    /// Witness polynomial commitment C (G1).
    #[serde(rename = "C")]
    pub c: [String; 3],
    /// Grand-product commitment Z (G1).
    #[serde(rename = "Z")]
    pub z: [String; 3],
    /// Quotient part 1 (G1).
    #[serde(rename = "T1")]
    pub t1: [String; 3],
    /// Quotient part 2 (G1).
    #[serde(rename = "T2")]
    pub t2: [String; 3],
    /// Quotient part 3 (G1).
    #[serde(rename = "T3")]
    pub t3: [String; 3],
    /// Opening proof at `xi` (G1).
    #[serde(rename = "Wxi")]
    pub w_xi: [String; 3],
    /// Opening proof at `xi · omega` (G1).
    #[serde(rename = "Wxiw")]
    pub w_xiw: [String; 3],
    /// Fr evaluation of A at `xi`.
    pub eval_a: String,
    /// Fr evaluation of B at `xi`.
    pub eval_b: String,
    /// Fr evaluation of C at `xi`.
    pub eval_c: String,
    /// Fr evaluation of sigma_1 at `xi`.
    pub eval_s1: String,
    /// Fr evaluation of sigma_2 at `xi`.
    pub eval_s2: String,
    /// Fr evaluation of Z at `xi · omega`.
    pub eval_zw: String,
    /// Protocol tag (must equal `"plonk"`).
    pub protocol: String,
    /// Curve tag (must equal `"bn128"`).
    pub curve: String,
}

/// snarkjs PLONK verifying-key JSON (`snarkjs zkey export verificationkey` output).
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
pub struct SnarkjsPlonkVk {
    /// Protocol tag (must equal `"plonk"`).
    pub protocol: String,
    /// Curve tag (must equal `"bn128"`).
    pub curve: String,
    /// Number of public inputs.
    #[serde(rename = "nPublic")]
    pub n_public: u32,
    /// Domain power: circuit size = 2^power.
    pub power: u32,
    /// Non-residue 1 (Fr decimal string).
    pub k1: String,
    /// Non-residue 2 (Fr decimal string).
    pub k2: String,
    /// Multiplication-selector commitment (G1).
    #[serde(rename = "Qm")]
    pub qm: [String; 3],
    /// Left-operand selector (G1).
    #[serde(rename = "Ql")]
    pub ql: [String; 3],
    /// Right-operand selector (G1).
    #[serde(rename = "Qr")]
    pub qr: [String; 3],
    /// Output selector (G1).
    #[serde(rename = "Qo")]
    pub qo: [String; 3],
    /// Constant selector (G1).
    #[serde(rename = "Qc")]
    pub qc: [String; 3],
    /// Permutation sigma_1 (G1).
    #[serde(rename = "S1")]
    pub s1: [String; 3],
    /// Permutation sigma_2 (G1).
    #[serde(rename = "S2")]
    pub s2: [String; 3],
    /// Permutation sigma_3 (G1).
    #[serde(rename = "S3")]
    pub s3: [String; 3],
    /// SRS element for pairing check (G2).
    #[serde(rename = "X_2")]
    pub x_2: [[String; 2]; 3],
    /// Primitive domain generator (Fr decimal string).
    pub w: String,
}

/// snarkjs-PLONK format codec, producing canonical Mosaic-PLONK bytes.
#[derive(Copy, Clone, Debug, Default)]
pub struct SnarkjsPlonkCodec;

impl SnarkjsPlonkCodec {
    /// Construct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Decode proof JSON to canonical 768-byte PLONK proof bytes.
    pub fn decode_proof(source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        let p: SnarkjsPlonkProof =
            serde_json::from_slice(source).map_err(|_| OnChainError::InvalidPointEncoding)?;
        if p.protocol != "plonk" || p.curve != "bn128" {
            return Err(OnChainError::UnsupportedOperation);
        }
        let mut out = Vec::with_capacity(768);
        // 9 G1 commitments in the canonical order.
        for g1 in [
            &p.a, &p.b, &p.c, &p.z, &p.t1, &p.t2, &p.t3, &p.w_xi, &p.w_xiw,
        ] {
            out.extend_from_slice(&encode_g1_dec(g1)?);
        }
        // 6 Fr evaluations.
        for fr in [
            &p.eval_a, &p.eval_b, &p.eval_c, &p.eval_s1, &p.eval_s2, &p.eval_zw,
        ] {
            out.extend_from_slice(&decimal_to_be_32(fr)?);
        }
        debug_assert_eq!(out.len(), 768);
        Ok(out)
    }

    /// Decode VK JSON to canonical 744-byte PLONK VK bytes.
    ///
    /// Layout matches `mosaic_plonk::canonical::PlonkVerifyingKey`:
    /// 8 × G1 selectors ‖ 1 × G2 SRS ‖ u32 power ‖ 3 × Fr (k1, k2, omega)
    /// ‖ u32 n_public.
    pub fn decode_vk(source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        let v: SnarkjsPlonkVk =
            serde_json::from_slice(source).map_err(|_| OnChainError::InvalidPointEncoding)?;
        if v.protocol != "plonk" || v.curve != "bn128" {
            return Err(OnChainError::UnsupportedOperation);
        }
        let mut out = Vec::with_capacity(744);
        // 8 G1 selectors.
        for g1 in [&v.qm, &v.ql, &v.qr, &v.qo, &v.qc, &v.s1, &v.s2, &v.s3] {
            out.extend_from_slice(&encode_g1_dec(g1)?);
        }
        // 1 G2 SRS element (x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0 byte order per ADR-0003).
        out.extend_from_slice(&encode_g2_dec(&v.x_2)?);
        // power (u32 LE).
        out.extend_from_slice(&v.power.to_le_bytes());
        // k1, k2, omega (32 B BE each).
        out.extend_from_slice(&decimal_to_be_32(&v.k1)?);
        out.extend_from_slice(&decimal_to_be_32(&v.k2)?);
        out.extend_from_slice(&decimal_to_be_32(&v.w)?);
        // n_public (u32 LE).
        out.extend_from_slice(&v.n_public.to_le_bytes());
        debug_assert_eq!(out.len(), 744);
        Ok(out)
    }

    /// Decode public-inputs JSON to canonical big-endian 32-byte Fr array.
    ///
    /// Same format as Groth16 public.json — a JSON array of decimal strings.
    pub fn decode_public_inputs(source: &[u8]) -> Result<Vec<u8>, OnChainError> {
        let inputs: Vec<String> =
            serde_json::from_slice(source).map_err(|_| OnChainError::InvalidFieldEncoding)?;
        let mut out = Vec::with_capacity(inputs.len() * 32);
        for s in &inputs {
            out.extend_from_slice(&decimal_to_be_32(s)?);
        }
        Ok(out)
    }
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
        let too_big =
            "115792089237316195423570985008687907853269984665640564039457584007913129639937";
        assert!(matches!(
            decimal_to_be_32(too_big),
            Err(OnChainError::PublicInputOutOfRange),
        ));
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 40 — proptest coverage for the snarkjs adapter primitives.
    //
    // The adapter has three soundness-critical building blocks:
    //
    //   - `decimal_to_be_32` — parses a snarkjs decimal string into a
    //     32-byte BE buffer; rejects values ≥ 2^256.
    //   - `encode_g1_dec`   — packs `[x, y, z]` into 64 BE bytes,
    //     mapping `z = "0"` to the identity (64 zero bytes).
    //   - `encode_g2_dec`   — packs `[[x.c0, x.c1], …]` into 128 BE
    //     bytes with the **Solana c1 ‖ c0** ordering (different from
    //     snarkjs's native c0 ‖ c1).
    //
    // Soundness narrative: a single bug in any of these silently
    // misroutes proof bytes through the alt_bn128 syscall — pairings
    // would either reject all valid proofs (best case) or accept
    // arbitrary forged ones if the misroute happens to hit a
    // self-consistent encoding. The properties below pin all three
    // primitives against round-trip identity, padding invariants, and
    // adversarial input rejection.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    /// Format a `BigUint` ≥ 0 as the decimal-string form snarkjs uses.
    fn big_to_decimal(n: &BigUint) -> String {
        n.to_str_radix(10)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Round-trip: any 32-byte BE buffer formatted as a decimal
        /// string parses back to itself. Pins both directions of the
        /// `BigUint ↔ snarkjs string ↔ canonical BE` chain.
        #[test]
        fn proptest_decimal_round_trip(
            bytes in proptest::collection::vec(any::<u8>(), 32..=32),
        ) {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes);
            let n = BigUint::from_bytes_be(&buf);
            let s = big_to_decimal(&n);
            let parsed = decimal_to_be_32(&s).expect("32-B value parses");
            prop_assert_eq!(parsed, buf);
        }

        /// Padding: any value ≤ u128::MAX is parsed and padded to 32
        /// bytes with leading zeros. Catches a regression that would
        /// emit a short buffer for small values (buffer overflow when
        /// the verifier reads past the end of the encoded slice).
        #[test]
        fn proptest_decimal_pads_small_values(x in any::<u128>()) {
            let s = x.to_string();
            let parsed = decimal_to_be_32(&s).expect("u128 fits in 32 B");
            prop_assert_eq!(parsed.len(), 32);
            // Trailing 16 bytes match `x.to_be_bytes()`; leading 16 are
            // zero-padded.
            prop_assert_eq!(&parsed[0..16], &[0u8; 16]);
            let expected_tail = x.to_be_bytes();
            prop_assert_eq!(&parsed[16..], &expected_tail[..]);
        }

        /// Any decimal value `≥ 2^256` is rejected with
        /// `PublicInputOutOfRange`. Generates the value as `2^256 +
        /// extra` to guarantee overflow.
        #[test]
        fn proptest_decimal_rejects_overflow(extra in 1u128..=u128::MAX) {
            let two_256 = BigUint::from(1u8) << 256;
            let big = two_256 + BigUint::from(extra);
            let s = big_to_decimal(&big);
            prop_assert!(matches!(
                decimal_to_be_32(&s),
                Err(OnChainError::PublicInputOutOfRange),
            ));
        }

        /// Any decimal string that fails to parse as a non-negative
        /// integer is rejected with `InvalidFieldEncoding`. The
        /// generator builds strings with a non-digit prefix so they
        /// never accidentally parse.
        #[test]
        fn proptest_decimal_rejects_garbage(
            prefix in "[a-zA-Z][a-zA-Z0-9]{0,8}",
            digits in proptest::collection::vec(any::<u8>(), 0..=8),
        ) {
            let mut s = prefix;
            for d in digits {
                s.push(char::from(b'0' + (d % 10)));
            }
            prop_assert!(matches!(
                decimal_to_be_32(&s),
                Err(OnChainError::InvalidFieldEncoding),
            ));
        }

        /// G1 identity: any point with `z = "0"` maps to 64 zero bytes
        /// regardless of the (formally meaningless) x and y values.
        /// Pins the snarkjs identity convention against future
        /// "validate x, y are also zero" tightening that would break
        /// real snarkjs output (which leaves x, y unspecified at the
        /// identity).
        #[test]
        fn proptest_g1_identity_z_zero_yields_zero_bytes(
            x in any::<u128>(),
            y in any::<u128>(),
        ) {
            let pt = [
                x.to_string(),
                y.to_string(),
                "0".to_string(),
            ];
            let bytes = encode_g1_dec(&pt).expect("identity encodes");
            prop_assert_eq!(bytes, [0u8; 64]);
        }

        /// G1 affine layout: any non-identity point with `z = "1"`
        /// packs as `x_BE ‖ y_BE` exactly. Catches a coordinate-swap
        /// bug between x and y in the encoder.
        #[test]
        fn proptest_g1_affine_layout(
            x_seed in any::<u128>(),
            y_seed in any::<u128>(),
        ) {
            let pt = [
                x_seed.to_string(),
                y_seed.to_string(),
                "1".to_string(),
            ];
            let bytes = encode_g1_dec(&pt).expect("affine encodes");
            // First 32 bytes = x_BE (zero-padded), last 32 = y_BE.
            let mut expected_x = [0u8; 32];
            expected_x[16..].copy_from_slice(&x_seed.to_be_bytes());
            let mut expected_y = [0u8; 32];
            expected_y[16..].copy_from_slice(&y_seed.to_be_bytes());
            prop_assert_eq!(&bytes[0..32], &expected_x);
            prop_assert_eq!(&bytes[32..64], &expected_y);
        }

        /// G1: any `z` other than "0" or "1" is rejected. snarkjs only
        /// emits z ∈ {"0", "1"}; anything else means the JSON was
        /// hand-crafted by an attacker (or by a buggy prover that
        /// emitted Jacobian coordinates without normalizing).
        #[test]
        fn proptest_g1_rejects_invalid_z(
            x in any::<u128>(),
            y in any::<u128>(),
            bad_z_seed in 2u8..=u8::MAX,
        ) {
            let pt = [
                x.to_string(),
                y.to_string(),
                bad_z_seed.to_string(),
            ];
            prop_assert!(matches!(
                encode_g1_dec(&pt),
                Err(OnChainError::InvalidPointEncoding),
            ));
        }

        /// G2 layout: pins the **Solana c1 ‖ c0** byte ordering on
        /// both x and y. snarkjs's native order is c0 ‖ c1; the
        /// adapter swaps them. A regression that drops the swap
        /// silently breaks the alt_bn128 pairing syscall.
        #[test]
        fn proptest_g2_layout_c1_then_c0(
            xc0 in any::<u128>(),
            xc1 in any::<u128>(),
            yc0 in any::<u128>(),
            yc1 in any::<u128>(),
        ) {
            let pt = [
                [xc0.to_string(), xc1.to_string()],
                [yc0.to_string(), yc1.to_string()],
                ["1".to_string(), "0".to_string()],
            ];
            let bytes = encode_g2_dec(&pt).expect("affine G2 encodes");
            let pad = |v: u128| -> [u8; 32] {
                let mut out = [0u8; 32];
                out[16..].copy_from_slice(&v.to_be_bytes());
                out
            };
            prop_assert_eq!(&bytes[0..32], &pad(xc1)); // x.c1 first
            prop_assert_eq!(&bytes[32..64], &pad(xc0)); // x.c0 second
            prop_assert_eq!(&bytes[64..96], &pad(yc1)); // y.c1 first
            prop_assert_eq!(&bytes[96..128], &pad(yc0)); // y.c0 second
        }

        /// G2: any z component other than the canonical (c0=1, c1=0)
        /// pair is rejected. snarkjs only emits the affine
        /// representation; anything else means a malformed input.
        #[test]
        fn proptest_g2_rejects_non_canonical_z(
            xc0 in any::<u128>(),
            xc1 in any::<u128>(),
            yc0 in any::<u128>(),
            yc1 in any::<u128>(),
            zc0 in 2u8..=u8::MAX,
            zc1_byte in 1u8..=u8::MAX,
        ) {
            let pt = [
                [xc0.to_string(), xc1.to_string()],
                [yc0.to_string(), yc1.to_string()],
                [zc0.to_string(), zc1_byte.to_string()],
            ];
            prop_assert!(matches!(
                encode_g2_dec(&pt),
                Err(OnChainError::InvalidPointEncoding),
            ));
        }
    }
}
