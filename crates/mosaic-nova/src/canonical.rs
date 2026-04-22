//! Nova / HyperNova / ProtoStar canonical byte layout — **placeholder
//! shape** derived from `sonobe` folding-compiler output.
//!
//! ## Reference shape (Nova)
//!
//! A Nova folded instance consists of:
//!
//! ```text
//! U = (E_comm, u, W_comm, x[])
//! ```
//!
//! where:
//! - `E_comm` (G1): commitment to the folded error vector
//! - `u` (Fr): folding scalar (=1 for a fresh instance)
//! - `W_comm` (G1): commitment to the folded witness
//! - `x[]` (Fr × n_public): public inputs
//!
//! The accompanying proof typically includes:
//!
//! - `T_comm` (G1): cross-term commitment from the last fold step
//! - KZG opening witness(es) if the verifier is Spartan-wrapped
//!
//! HyperNova and ProtoStar add higher-degree terms but keep the same
//! high-level `(commitments, scalar, openings)` shape. Phase-3 ADR
//! amendment pins the exact layout per variant.
//!
//! ## Our placeholder layout
//!
//! Fixed header + variable public-input tail + fixed opening suffix.
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0 | 1 | `variant` (u8) — 0=Nova, 1=HyperNova, 2=ProtoStar |
//! | 1 | 1 | `num_aux_commits` (u8) — variant-specific extra commits |
//! | 2 | 2 | `n_public` (u16 LE) — public input count |
//! | 4 | 4 | reserved (variant-specific flags) |
//! | 8 | 8 | reserved (future: step_count / folding_height) |
//! | 16 | 64 | `e_comm` (G1) |
//! | 80 | 64 | `w_comm` (G1) |
//! | 144 | 64 | `t_comm` (G1) |
//! | 208 | 32 | `u` (Fr, folding scalar) |
//! | 240 | 64 × `num_aux_commits` | variant extras |
//! | … | 32 × `n_public` | public inputs (Fr) |
//! | … | 64 | KZG opening `W_xi` (G1) |
//! | … | 64 | KZG opening `W_xiw` (G1) |
//!
//! For a typical Nova proof with no HyperNova extras and 4 public
//! inputs: 16 + 3·64 + 32 + 4·32 + 2·64 = **496 B** — comfortably
//! fits in a single Solana transaction.

use alloc::vec::Vec;
use ark_bn254::Fr;
use mosaic_core::OnChainError;
use mosaic_zk_primitives::field::fr_from_canonical_bytes;

/// Size + cap constants for the Nova canonical layout.
pub mod sizes {
    /// G1 affine length.
    pub const G1_LEN: usize = 64;
    /// Fr length.
    pub const FR_LEN: usize = 32;
    /// G2 length (for VK SRS element).
    pub const G2_LEN: usize = 128;
    /// Fixed header length.
    pub const FIXED_HEADER_LEN: usize = 16;
    /// Three fixed commitments (E, W, T).
    pub const FIXED_COMMITS_LEN: usize = 3 * G1_LEN;
    /// Folded scalar `u`.
    pub const SCALAR_LEN: usize = FR_LEN;
    /// Hadamard-relation evaluations at the Spartan point ξ:
    /// `a_eval ‖ b_eval ‖ c_eval ‖ e_eval` (4 × 32 B). Used by the
    /// verifier's residual check `A(ξ)·B(ξ) - u·C(ξ) - E(ξ) == 0`.
    pub const HADAMARD_EVALS_LEN: usize = 4 * FR_LEN;
    /// Two opening commitments (W_xi, W_xiw).
    pub const OPENING_LEN: usize = 2 * G1_LEN;
    /// Max variant-specific aux commitments. HyperNova uses ~4 for
    /// higher-degree terms; cap liberally.
    pub const MAX_AUX_COMMITS: u8 = 16;
    /// Max public inputs.
    pub const MAX_PUBLIC_INPUTS: u16 = 256;
}

/// Folding scheme variant tag.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FoldingVariant {
    /// Nova — relaxed R1CS folding, BN254 (PSE port).
    Nova = 0,
    /// HyperNova — customizable constraint system with higher-degree
    /// gates. Supports non-uniform computation.
    HyperNova = 1,
    /// ProtoStar — multi-folding via special-sound protocols, broader
    /// protocol family than Nova.
    ProtoStar = 2,
}

impl FoldingVariant {
    /// Decode from raw tag byte. Unknown tags rejected.
    pub fn from_byte(b: u8) -> Result<Self, OnChainError> {
        match b {
            0 => Ok(Self::Nova),
            1 => Ok(Self::HyperNova),
            2 => Ok(Self::ProtoStar),
            _ => Err(OnChainError::UnknownProofSystem),
        }
    }
}

/// Zero-copy view into a folded-instance proof buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NovaFoldingProof<'a> {
    /// Folding scheme variant.
    pub variant: FoldingVariant,
    /// Number of variant-specific auxiliary commitments.
    pub num_aux_commits: u8,
    /// Public input count (as declared in proof header).
    pub n_public: u16,
    /// Error-vector commitment `E`.
    pub e_comm: &'a [u8],
    /// Witness commitment `W`.
    pub w_comm: &'a [u8],
    /// Cross-term commitment `T` from the last fold step.
    pub t_comm: &'a [u8],
    /// Folding scalar `u` (Fr, big-endian canonical).
    pub u: &'a [u8],
    /// Hadamard-relation evaluations at ξ:
    /// `a_eval ‖ b_eval ‖ c_eval ‖ e_eval` (4 × 32 B). Used by the
    /// verifier's residual check.
    pub hadamard_evals: &'a [u8],
    /// Variant-specific extras (e.g. HyperNova higher-degree commits).
    pub aux_commits: &'a [u8],
    /// Public inputs concatenated (length = `n_public × 32`).
    pub public_inputs: &'a [u8],
    /// KZG opening at evaluation point ξ (G1).
    pub w_xi: &'a [u8],
    /// KZG opening at `ξω` (G1).
    pub w_xiw: &'a [u8],
}

impl<'a> NovaFoldingProof<'a> {
    /// Parse a canonical folding-instance proof.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, OnChainError> {
        use sizes::{
            FIXED_COMMITS_LEN, FIXED_HEADER_LEN, FR_LEN, G1_LEN, HADAMARD_EVALS_LEN,
            MAX_AUX_COMMITS, MAX_PUBLIC_INPUTS, OPENING_LEN, SCALAR_LEN,
        };

        let minimum = FIXED_HEADER_LEN
            + FIXED_COMMITS_LEN
            + SCALAR_LEN
            + HADAMARD_EVALS_LEN
            + OPENING_LEN;
        if bytes.len() < minimum {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let variant = FoldingVariant::from_byte(bytes[0])?;
        let num_aux_commits = bytes[1];
        let n_public = u16::from_le_bytes([bytes[2], bytes[3]]);

        if num_aux_commits > MAX_AUX_COMMITS || n_public > MAX_PUBLIC_INPUTS {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let aux_len = (num_aux_commits as usize)
            .checked_mul(G1_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let pi_len = (n_public as usize)
            .checked_mul(FR_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;

        let expected_len = FIXED_HEADER_LEN
            + FIXED_COMMITS_LEN
            + SCALAR_LEN
            + HADAMARD_EVALS_LEN
            + aux_len
            + pi_len
            + OPENING_LEN;

        if bytes.len() != expected_len {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let mut off = FIXED_HEADER_LEN;
        let e_comm = &bytes[off..off + G1_LEN];
        off += G1_LEN;
        let w_comm = &bytes[off..off + G1_LEN];
        off += G1_LEN;
        let t_comm = &bytes[off..off + G1_LEN];
        off += G1_LEN;
        let u = &bytes[off..off + FR_LEN];
        off += FR_LEN;
        let hadamard_evals = &bytes[off..off + HADAMARD_EVALS_LEN];
        off += HADAMARD_EVALS_LEN;
        let aux_commits = &bytes[off..off + aux_len];
        off += aux_len;
        let public_inputs = &bytes[off..off + pi_len];
        off += pi_len;
        let w_xi = &bytes[off..off + G1_LEN];
        off += G1_LEN;
        let w_xiw = &bytes[off..off + G1_LEN];

        Ok(Self {
            variant,
            num_aux_commits,
            n_public,
            e_comm,
            w_comm,
            t_comm,
            u,
            hadamard_evals,
            aux_commits,
            public_inputs,
            w_xi,
            w_xiw,
        })
    }

    /// Parse the Hadamard-relation evaluations `(a, b, c, e)` at ξ
    /// from the proof's `hadamard_evals` bundle.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::PublicInputOutOfRange`] if any Fr is out of
    ///   range.
    pub fn parse_hadamard_evals(&self) -> Result<(Fr, Fr, Fr, Fr), OnChainError> {
        let a = fr_from_canonical_bytes(&self.hadamard_evals[0..sizes::FR_LEN])?;
        let b = fr_from_canonical_bytes(&self.hadamard_evals[sizes::FR_LEN..2 * sizes::FR_LEN])?;
        let c = fr_from_canonical_bytes(
            &self.hadamard_evals[2 * sizes::FR_LEN..3 * sizes::FR_LEN],
        )?;
        let e = fr_from_canonical_bytes(
            &self.hadamard_evals[3 * sizes::FR_LEN..4 * sizes::FR_LEN],
        )?;
        Ok((a, b, c, e))
    }

    /// Iterate auxiliary commitments as 64-byte G1 slices.
    pub fn aux_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.aux_commits.chunks_exact(sizes::G1_LEN)
    }

    /// Iterate public inputs as 32-byte Fr slices.
    pub fn public_inputs_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.public_inputs.chunks_exact(sizes::FR_LEN)
    }
}

/// Nova / HyperNova / ProtoStar verifying key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NovaFoldingVerifyingKey {
    /// Folding scheme variant.
    pub variant: FoldingVariant,
    /// Declared number of public inputs for this constraint system.
    pub n_public: u16,
    /// Number of R1CS constraints (or CCS rows for HyperNova).
    pub n_constraints: u32,
    /// G2 SRS element for KZG pairing check.
    pub x2_g2: [u8; sizes::G2_LEN],
    /// A-matrix commitment (G1).
    pub a_comm: [u8; sizes::G1_LEN],
    /// B-matrix commitment (G1).
    pub b_comm: [u8; sizes::G1_LEN],
    /// C-matrix commitment (G1).
    pub c_comm: [u8; sizes::G1_LEN],
    /// Constraint system digest — uniquely identifies the R1CS / CCS
    /// this VK is for. Used to cross-check against proof claims.
    pub cs_digest: [u8; 32],
}

impl NovaFoldingVerifyingKey {
    /// Canonical serialized length.
    pub const SERIALIZED_LEN: usize = 1 // variant
        + 2 // n_public
        + 4 // n_constraints
        + sizes::G2_LEN
        + 3 * sizes::G1_LEN
        + 32; // cs_digest

    /// Decode from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let variant = FoldingVariant::from_byte(bytes[0])?;
        let n_public = u16::from_le_bytes([bytes[1], bytes[2]]);
        let n_constraints = u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
        let mut off = 7;
        let mut x2_g2 = [0u8; sizes::G2_LEN];
        x2_g2.copy_from_slice(&bytes[off..off + sizes::G2_LEN]);
        off += sizes::G2_LEN;
        let mut a_comm = [0u8; sizes::G1_LEN];
        a_comm.copy_from_slice(&bytes[off..off + sizes::G1_LEN]);
        off += sizes::G1_LEN;
        let mut b_comm = [0u8; sizes::G1_LEN];
        b_comm.copy_from_slice(&bytes[off..off + sizes::G1_LEN]);
        off += sizes::G1_LEN;
        let mut c_comm = [0u8; sizes::G1_LEN];
        c_comm.copy_from_slice(&bytes[off..off + sizes::G1_LEN]);
        off += sizes::G1_LEN;
        let mut cs_digest = [0u8; 32];
        cs_digest.copy_from_slice(&bytes[off..off + 32]);
        Ok(Self {
            variant,
            n_public,
            n_constraints,
            x2_g2,
            a_comm,
            b_comm,
            c_comm,
            cs_digest,
        })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SERIALIZED_LEN);
        out.push(self.variant as u8);
        out.extend_from_slice(&self.n_public.to_le_bytes());
        out.extend_from_slice(&self.n_constraints.to_le_bytes());
        out.extend_from_slice(&self.x2_g2);
        out.extend_from_slice(&self.a_comm);
        out.extend_from_slice(&self.b_comm);
        out.extend_from_slice(&self.c_comm);
        out.extend_from_slice(&self.cs_digest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sizes::{
        FIXED_COMMITS_LEN, FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN, HADAMARD_EVALS_LEN,
        OPENING_LEN, SCALAR_LEN,
    };

    fn proof_bytes(variant: FoldingVariant, num_aux: u8, n_public: u16) -> Vec<u8> {
        let aux_len = (num_aux as usize) * G1_LEN;
        let pi_len = (n_public as usize) * FR_LEN;
        let total = FIXED_HEADER_LEN
            + FIXED_COMMITS_LEN
            + SCALAR_LEN
            + HADAMARD_EVALS_LEN
            + aux_len
            + pi_len
            + OPENING_LEN;
        let mut buf = vec![0u8; total];
        buf[0] = variant as u8;
        buf[1] = num_aux;
        buf[2..4].copy_from_slice(&n_public.to_le_bytes());
        buf
    }

    #[test]
    fn proof_parses_nova_shape() {
        let buf = proof_bytes(FoldingVariant::Nova, 0, 4);
        let p = NovaFoldingProof::from_bytes(&buf).unwrap();
        assert_eq!(p.variant, FoldingVariant::Nova);
        assert_eq!(p.n_public, 4);
        assert_eq!(p.num_aux_commits, 0);
        assert_eq!(p.aux_iter().count(), 0);
        assert_eq!(p.public_inputs_iter().count(), 4);
    }

    #[test]
    fn proof_parses_hypernova_with_aux_commits() {
        let buf = proof_bytes(FoldingVariant::HyperNova, 4, 2);
        let p = NovaFoldingProof::from_bytes(&buf).unwrap();
        assert_eq!(p.variant, FoldingVariant::HyperNova);
        assert_eq!(p.num_aux_commits, 4);
        assert_eq!(p.aux_iter().count(), 4);
    }

    #[test]
    fn proof_parses_protostar() {
        let buf = proof_bytes(FoldingVariant::ProtoStar, 2, 1);
        let p = NovaFoldingProof::from_bytes(&buf).unwrap();
        assert_eq!(p.variant, FoldingVariant::ProtoStar);
    }

    #[test]
    fn proof_rejects_unknown_variant() {
        let mut buf = proof_bytes(FoldingVariant::Nova, 0, 1);
        buf[0] = 0xFF;
        assert!(matches!(
            NovaFoldingProof::from_bytes(&buf),
            Err(OnChainError::UnknownProofSystem),
        ));
    }

    #[test]
    fn proof_rejects_aux_over_max() {
        let buf = proof_bytes(FoldingVariant::HyperNova, sizes::MAX_AUX_COMMITS + 1, 1);
        assert!(matches!(
            NovaFoldingProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_pi_over_max() {
        let buf = proof_bytes(FoldingVariant::Nova, 0, sizes::MAX_PUBLIC_INPUTS + 1);
        assert!(matches!(
            NovaFoldingProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_trailing_garbage() {
        let mut buf = proof_bytes(FoldingVariant::Nova, 0, 2);
        buf.push(0xEF);
        assert!(matches!(
            NovaFoldingProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_short_buffer() {
        let short = vec![0u8; FIXED_HEADER_LEN];
        assert!(matches!(
            NovaFoldingProof::from_bytes(&short),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn vk_roundtrip() {
        let vk = NovaFoldingVerifyingKey {
            variant: FoldingVariant::Nova,
            n_public: 4,
            n_constraints: 1024,
            x2_g2: [0xAA; G2_LEN],
            a_comm: [0x11; G1_LEN],
            b_comm: [0x22; G1_LEN],
            c_comm: [0x33; G1_LEN],
            cs_digest: [0xCD; 32],
        };
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), NovaFoldingVerifyingKey::SERIALIZED_LEN);
        let decoded = NovaFoldingVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
    }

    #[test]
    fn vk_rejects_wrong_length() {
        let short = vec![0u8; NovaFoldingVerifyingKey::SERIALIZED_LEN - 1];
        assert!(matches!(
            NovaFoldingVerifyingKey::from_bytes(&short),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }

    #[test]
    fn vk_rejects_unknown_variant_tag() {
        let mut vk_bytes = NovaFoldingVerifyingKey {
            variant: FoldingVariant::Nova,
            n_public: 1,
            n_constraints: 100,
            x2_g2: [0; G2_LEN],
            a_comm: [0; G1_LEN],
            b_comm: [0; G1_LEN],
            c_comm: [0; G1_LEN],
            cs_digest: [0; 32],
        }
        .to_bytes();
        vk_bytes[0] = 0x99;
        assert!(matches!(
            NovaFoldingVerifyingKey::from_bytes(&vk_bytes),
            Err(OnChainError::UnknownProofSystem),
        ));
    }
}
