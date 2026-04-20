//! `Groth16Verifier` — the actual verification routine.
//!
//! The verifier is generic over a [`SyscallBackend`] so that the exact same
//! code runs both:
//!
//! - On-chain (via [`mosaic_core::syscall::solana::SolanaSyscallBackend`]).
//! - In host tests (via [`mosaic_core::syscall::host::HostBackend`]).
//!
//! Differential testing relies on this — see [`tests/differential/`] in the
//! workspace root.

use crate::{
    canonical::{lt_be, Groth16Proof, Groth16VerifyingKey, BN254_FR_MODULUS_BE},
    sizes::{FR_LEN, G1_LEN, G2_LEN},
};
use alloc::vec::Vec;
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::{AltBn128Op, InputEndianness, SyscallBackend},
    OnChainError,
};

/// Verifier handle. Holds a backend reference; no other state.
///
/// `LE_INPUTS = false` (default) means inputs are big-endian, matching the
/// current Solana syscall convention. Set to `true` after SIMD-0204 activates
/// to consume little-endian witness data.
pub struct Groth16Verifier<'a, B: SyscallBackend, const LE_INPUTS: bool = false> {
    backend: &'a B,
}

impl<'a, B: SyscallBackend, const LE: bool> Groth16Verifier<'a, B, LE> {
    /// Construct against an existing backend.
    #[must_use]
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    fn endianness() -> InputEndianness {
        if LE {
            InputEndianness::LittleEndian
        } else {
            InputEndianness::BigEndian
        }
    }

    /// Verify a Groth16 proof against a verifying key and public inputs.
    ///
    /// `vk_bytes` follows [`crate::canonical`] layout. `proof_bytes` is exactly
    /// 256 B (`A || B || C`). `public_inputs_bytes` is `n × 32 B` field
    /// elements concatenated, where `n == vk.num_public_inputs()`.
    pub fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        let vk = Groth16VerifyingKey::from_bytes(vk_bytes)?;
        let proof = Groth16Proof::from_bytes(proof_bytes)?;

        if public_inputs_bytes.len() != vk.num_public_inputs() * FR_LEN {
            return Err(OnChainError::PublicInputCountMismatch);
        }

        // Bounds-check every public input against the BN254 scalar field
        // order `r`. Failing this check leaks no timing info because we
        // exit before any group op.
        for chunk in public_inputs_bytes.chunks_exact(FR_LEN) {
            let mut be_input = [0u8; FR_LEN];
            be_input.copy_from_slice(chunk);
            if LE {
                be_input.reverse();
            }
            if !lt_be(&be_input, &BN254_FR_MODULUS_BE) {
                return Err(OnChainError::PublicInputOutOfRange);
            }
        }

        // ---------- L = IC[0] + Σ pi[i] · IC[i+1] ----------
        let mut l = vk.ic[0]; // start with IC[0]
        for (i, chunk) in public_inputs_bytes.chunks_exact(FR_LEN).enumerate() {
            let ic_i_plus_1 = vk.ic.get(i + 1).ok_or(OnChainError::InternalInvariantViolation)?;
            // scalar mul: IC[i+1] · pi[i]
            let mut mul_input = Vec::with_capacity(G1_LEN + FR_LEN);
            mul_input.extend_from_slice(ic_i_plus_1);
            mul_input.extend_from_slice(chunk);
            let prod = self.backend.alt_bn128_group_op(
                AltBn128Op::G1Mul,
                Self::endianness(),
                &mul_input,
            )?;
            // add: L += prod
            let mut add_input = Vec::with_capacity(G1_LEN * 2);
            add_input.extend_from_slice(&l);
            add_input.extend_from_slice(&prod);
            let sum = self.backend.alt_bn128_group_op(
                AltBn128Op::G1Add,
                Self::endianness(),
                &add_input,
            )?;
            if sum.len() != G1_LEN {
                return Err(OnChainError::InternalInvariantViolation);
            }
            l.copy_from_slice(&sum);
        }

        // ---------- Negate A internally so we can do a single pairing call ----------
        let neg_a = negate_g1(proof.a, LE)?;

        // ---------- Pairing: e(-A,B) · e(α,β) · e(L,γ) · e(C,δ) = 1 ----------
        let mut pairing_input = Vec::with_capacity(192 * 4);
        // pair 1: -A, B
        pairing_input.extend_from_slice(&neg_a);
        pairing_input.extend_from_slice(proof.b);
        // pair 2: α, β
        pairing_input.extend_from_slice(&vk.alpha_g1);
        pairing_input.extend_from_slice(&vk.beta_g2);
        // pair 3: L, γ
        pairing_input.extend_from_slice(&l);
        pairing_input.extend_from_slice(&vk.gamma_g2);
        // pair 4: C, δ
        pairing_input.extend_from_slice(proof.c);
        pairing_input.extend_from_slice(&vk.delta_g2);

        let pairing_result = self.backend.alt_bn128_group_op(
            AltBn128Op::Pairing,
            Self::endianness(),
            &pairing_input,
        )?;

        // Pairing syscall returns 32 bytes; the last byte is 0x01 on success.
        if pairing_result.len() != 32 || pairing_result[31] != 0x01 {
            return Err(OnChainError::PairingCheckFailed);
        }
        Ok(())
    }
}

/// Negate the y-coordinate of a G1 affine point. Field order `q` is the
/// BN254 base-field modulus.
///
/// `q = 21888242871839275222246405745257275088696311157297823662689037894645226208583`.
const BN254_FQ_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

fn negate_g1(point: &[u8], le: bool) -> Result<[u8; G1_LEN], OnChainError> {
    if point.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let mut out = [0u8; G1_LEN];
    out.copy_from_slice(point);

    let (_x, y_slice) = out.split_at_mut(32);
    // Convert to BE if needed for arithmetic.
    if le {
        y_slice.reverse();
    }
    // Compute (q - y) mod q. If y == 0, leave as 0.
    let zero = [0u8; 32];
    if y_slice == zero {
        // y is already 0; skip subtraction.
    } else {
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let q_b = i16::from(BN254_FQ_MODULUS_BE[i]);
            let y_b = i16::from(y_slice[i]);
            let diff = q_b - y_b - borrow;
            if diff < 0 {
                y_slice[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                y_slice[i] = diff as u8;
                borrow = 0;
            }
        }
        // q > y by construction (y < q because point came from a valid G1 element),
        // so borrow must be 0 here.
        if borrow != 0 {
            return Err(OnChainError::InternalInvariantViolation);
        }
    }
    if le {
        y_slice.reverse();
    }
    Ok(out)
}

impl<B: SyscallBackend + Send + Sync, const LE: bool> ProofSystem for Groth16Verifier<'_, B, LE>
where
    B: 'static,
{
    fn proof_system_id(&self) -> ProofSystemId {
        ProofSystemId::Groth16Bn254
    }

    fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError> {
        Self::verify(self, vk_bytes, proof_bytes, public_inputs_bytes)
    }

    fn estimated_compute_units(&self, vk_bytes: &[u8], _proof_bytes: &[u8]) -> Option<u32> {
        // 5_000 (deser) + n * (3_200 mul + 100 add) + 36_000 (pairing)
        let header = G1_LEN + G2_LEN * 3;
        if vk_bytes.len() < header {
            return Some(0);
        }
        let ic_bytes = vk_bytes.len().saturating_sub(header);
        let n = (ic_bytes / G1_LEN).saturating_sub(1);
        let n_u32 = u32::try_from(n).unwrap_or(u32::MAX);
        Some(5_000_u32.saturating_add(n_u32.saturating_mul(3_300)).saturating_add(36_000))
    }

    fn batch_verify(
        &self,
        vk_bytes: &[u8],
        proofs: &[&[u8]],
        public_inputs: &[&[u8]],
    ) -> Result<(), OnChainError> {
        // Bowe-Gabizon randomized aggregation; one pairing syscall
        // regardless of N. Beats the looped path starting at N = 2
        // and scales nearly linearly with N after that.
        crate::batch::batch_verify::<B, LE>(self.backend, vk_bytes, proofs, public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sizes::PROOF_LEN;

    #[test]
    fn rejects_wrong_proof_length() {
        // Build a minimal-length VK skeleton and feed a too-short proof.
        struct DummyBackend;
        impl SyscallBackend for DummyBackend {
            fn alt_bn128_group_op(
                &self,
                _: AltBn128Op,
                _: InputEndianness,
                _: &[u8],
            ) -> Result<Vec<u8>, OnChainError> {
                Err(OnChainError::AltBn128SyscallFailed)
            }
            fn alt_bn128_compression(
                &self,
                _: mosaic_core::syscall::AltBn128Compress,
                _: &[u8],
            ) -> Result<Vec<u8>, OnChainError> {
                Err(OnChainError::AltBn128CompressionSyscallFailed)
            }
            fn poseidon(
                &self,
                _: mosaic_core::syscall::PoseidonParameters,
                _: InputEndianness,
                _: &[&[u8]],
            ) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::PoseidonSyscallFailed)
            }
            fn sha256(&self, _: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::Sha256SyscallFailed)
            }
            fn keccak256(&self, _: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
                Err(OnChainError::Keccak256SyscallFailed)
            }
        }
        let backend = DummyBackend;
        let v = Groth16Verifier::<_, false>::new(&backend);
        let vk = Groth16VerifyingKey {
            alpha_g1: [0; G1_LEN],
            beta_g2: [0; G2_LEN],
            gamma_g2: [0; G2_LEN],
            delta_g2: [0; G2_LEN],
            ic: alloc::vec![[0; G1_LEN], [0; G1_LEN]],
        };
        let result = v.verify(&vk.to_bytes(), &[0; PROOF_LEN - 1], &[0; FR_LEN]);
        assert!(matches!(result, Err(OnChainError::ProofLengthMismatch)));
    }
}
