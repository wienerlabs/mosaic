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
    canonical::{Groth16Proof, Groth16VerifyingKey},
    sizes::{FR_LEN, G1_LEN, G2_LEN},
};
use mosaic_zk_primitives::fr::lt_r;
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
        // exit before any group op. Session 98: migrated from inline
        // `lt_be(&be_input, &BN254_FR_MODULUS_BE)` to the shared
        // `mosaic_zk_primitives::fr::lt_r` convenience wrapper that
        // pins the modulus comparison in one place.
        for chunk in public_inputs_bytes.chunks_exact(FR_LEN) {
            let mut be_input = [0u8; FR_LEN];
            be_input.copy_from_slice(chunk);
            if LE {
                be_input.reverse();
            }
            if !lt_r(&be_input) {
                return Err(OnChainError::PublicInputOutOfRange);
            }
        }

        // ---------- L = IC[0] + Σ pi[i] · IC[i+1] ----------
        let mut l = vk.ic[0]; // start with IC[0]
        for (i, chunk) in public_inputs_bytes.chunks_exact(FR_LEN).enumerate() {
            let ic_i_plus_1 = vk
                .ic
                .get(i + 1)
                .ok_or(OnChainError::InternalInvariantViolation)?;
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

        // ---------- Pairing: e(-A,B) · e(α,β) · e(L,γ) · e(C,δ) = 1 ----------
        // Session 93: collapses the inline negate-A + 4-pair pairing
        // assembly + result-byte check into the
        // `verify_groth16_pairing_identity` audit gate. Mirrors the
        // session-86/88/90/91 ADR-0006 extraction pattern in
        // Nova / Halo2 / STARK / HyperPlonk.
        verify_groth16_pairing_identity::<B, LE>(
            self.backend,
            proof.a,
            proof.b,
            proof.c,
            &l,
            &vk.alpha_g1,
            &vk.beta_g2,
            &vk.gamma_g2,
            &vk.delta_g2,
        )
    }
}

/// **Session 93 — high-level Groth16 pairing-identity audit gate.**
///
/// Computes the four-pair pairing equation that closes Groth16's
/// soundness story:
///
/// ```text
/// e(-A, B) · e(α, β) · e(L, γ) · e(C, δ) = 1
/// ```
///
/// where `L = IC[0] + Σ pi[i] · IC[i+1]` is the linear combination
/// of public inputs against the VK's input commitments. A satisfying
/// proof produces an Fq12 product that equals the multiplicative
/// identity (the pairing syscall returns 32 bytes with the last byte
/// `0x01`); any divergence is rejected as
/// [`OnChainError::PairingCheckFailed`].
///
/// This is the audit-grade "is the prover's `(A, B, C)` triple
/// consistent with the VK at this public-input commitment?" check —
/// the **only** soundness boundary in Groth16 (the rest of the
/// verifier is parsing + linear combination + length validation).
///
/// Sessions ≤92 inlined the negate-A + 4-pair assembly + result-byte
/// check pattern; session 93 collapses it into a single named
/// primitive following the ADR-0006 contract that Nova / Halo2 /
/// STARK / HyperPlonk already follow. External auditors now have
/// one named function per Phase-2 verifier as well.
///
/// ## Generics
///
/// - `B` — the syscall backend (host or Solana SBF).
/// - `LE` — input endianness flag (`false` = big-endian, the current
///   Solana convention; `true` after SIMD-0204).
///
/// ## Inputs
///
/// - `backend` — the syscall backend implementing `alt_bn128_group_op`.
/// - `proof_a, proof_b, proof_c` — the proof's three group elements
///   (A in G1, B in G2, C in G1) as raw byte slices in the wire
///   layout (`G1_LEN = 64`, `G2_LEN = 128`).
/// - `l_input_combination` — the precomputed `L = IC[0] + Σ pi · IC[i+1]`
///   commitment (64 bytes).
/// - `alpha_g1, beta_g2, gamma_g2, delta_g2` — the four VK setup
///   constants used in the pairing equation.
///
/// ## Errors
///
/// - [`OnChainError::PairingCheckFailed`] — the pairing product is
///   not the Fq12 identity, OR the syscall returned an unexpected
///   payload length.
/// - Syscall errors propagated from `alt_bn128_group_op` (e.g.
///   malformed group element bytes).
#[allow(clippy::too_many_arguments)]
pub fn verify_groth16_pairing_identity<B: SyscallBackend + ?Sized, const LE: bool>(
    backend: &B,
    proof_a: &[u8],
    proof_b: &[u8],
    proof_c: &[u8],
    l_input_combination: &[u8],
    alpha_g1: &[u8],
    beta_g2: &[u8],
    gamma_g2: &[u8],
    delta_g2: &[u8],
) -> Result<(), OnChainError> {
    let endianness = if LE {
        InputEndianness::LittleEndian
    } else {
        InputEndianness::BigEndian
    };

    // Negate A internally so we can fold all four pairings into a
    // single product and check against the identity.
    let neg_a = negate_g1(proof_a, LE)?;

    let mut pairing_input = Vec::with_capacity(192 * 4);
    // pair 1: -A, B
    pairing_input.extend_from_slice(&neg_a);
    pairing_input.extend_from_slice(proof_b);
    // pair 2: α, β
    pairing_input.extend_from_slice(alpha_g1);
    pairing_input.extend_from_slice(beta_g2);
    // pair 3: L, γ
    pairing_input.extend_from_slice(l_input_combination);
    pairing_input.extend_from_slice(gamma_g2);
    // pair 4: C, δ
    pairing_input.extend_from_slice(proof_c);
    pairing_input.extend_from_slice(delta_g2);

    let pairing_result = backend.alt_bn128_group_op(
        AltBn128Op::Pairing,
        endianness,
        &pairing_input,
    )?;

    // Pairing syscall returns 32 bytes; the last byte is 0x01 on success.
    if pairing_result.len() != 32 || pairing_result[31] != 0x01 {
        return Err(OnChainError::PairingCheckFailed);
    }
    Ok(())
}

/// Negate the y-coordinate of a G1 affine point. Field order `q` is the
// Session 99 — `BN254_FQ_MODULUS_BE` lifted to
// `mosaic_zk_primitives::msm::BN254_FQ_MODULUS_BE` and the `negate_g1`
// arithmetic body lifted to `mosaic_zk_primitives::msm::negate_g1`.
// This local `negate_g1` is now a thin wrapper that adds the
// length-validation + endianness-flip surface the verifier needs
// (the shared primitive takes a `&[u8; 64]` BE-encoded point and
// returns `[u8; 64]`; the verifier accepts `&[u8]` slices in either
// LE or BE depending on the SBF runtime's evolving convention).
fn negate_g1(point: &[u8], le: bool) -> Result<[u8; G1_LEN], OnChainError> {
    if point.len() != G1_LEN {
        return Err(OnChainError::InvalidPointEncoding);
    }
    let mut be_point = [0u8; G1_LEN];
    be_point.copy_from_slice(point);
    if le {
        // Convert y-coordinate to BE for the shared primitive.
        be_point[32..].reverse();
    }
    let mut out = mosaic_zk_primitives::msm::negate_g1(&be_point);
    if le {
        // Convert y-coordinate back to LE for the caller.
        out[32..].reverse();
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
        Some(
            5_000_u32
                .saturating_add(n_u32.saturating_mul(3_300))
                .saturating_add(36_000),
        )
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

    // ───────────────────────────────────────────────────────────────────
    // Session 93 — verify_groth16_pairing_identity audit-gate coverage.
    //
    // The audit gate is exercised end-to-end by the existing
    // differential tests against real BN254 fixtures (see
    // `tests/differential/`); these direct unit tests cover the
    // gate's input-validation and error-propagation surface.
    // ───────────────────────────────────────────────────────────────────

    /// Backend that returns a programmable pairing-check verdict.
    /// Used to test the gate's success/failure handling without
    /// pulling in real BN254 arithmetic.
    struct ProgrammablePairingBackend {
        /// Last byte of the 32-byte pairing return payload. `0x01` →
        /// gate accepts; anything else → `PairingCheckFailed`.
        verdict_byte: u8,
    }

    impl SyscallBackend for ProgrammablePairingBackend {
        fn alt_bn128_group_op(
            &self,
            op: AltBn128Op,
            _: InputEndianness,
            _: &[u8],
        ) -> Result<Vec<u8>, OnChainError> {
            match op {
                AltBn128Op::Pairing => {
                    let mut out = alloc::vec![0u8; 32];
                    out[31] = self.verdict_byte;
                    Ok(out)
                }
                AltBn128Op::G1Add | AltBn128Op::G1Mul => {
                    // Identity G1 (64 bytes of zero) for any add/mul —
                    // the gate doesn't care about these in isolation,
                    // they're called on the caller's side (L computation).
                    Ok(alloc::vec![0u8; G1_LEN])
                }
            }
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

    /// `proof_a` for these tests — we don't care about real BN254
    /// validity since the negate_g1 path runs on it. Use the BN254 G1
    /// neutral element-shaped placeholder (64 zero bytes) which negate_g1
    /// rejects as `InvalidPointEncoding` in real arithmetic. To exercise
    /// the gate's success-path test directly we construct a placeholder
    /// generator-shaped point that negate_g1 accepts.
    fn placeholder_g1() -> [u8; G1_LEN] {
        // Identity (0, 0) — `negate_g1` returns identity unchanged.
        [0u8; G1_LEN]
    }
    fn placeholder_g2() -> [u8; G2_LEN] {
        [0u8; G2_LEN]
    }

    /// Programmable backend reports pairing success ⇒ gate accepts.
    /// Pure exercise of the success-byte-check branch (last byte 0x01).
    #[test]
    fn audit_gate_accepts_when_pairing_returns_success_byte() {
        let backend = ProgrammablePairingBackend { verdict_byte: 0x01 };
        let g1 = placeholder_g1();
        let g2 = placeholder_g2();
        verify_groth16_pairing_identity::<_, false>(
            &backend, &g1, &g2, &g1, &g1, &g1, &g2, &g2, &g2,
        )
        .expect("pairing-success backend → gate accepts");
    }

    /// Programmable backend reports pairing failure (last byte ≠ 0x01)
    /// ⇒ gate rejects with PairingCheckFailed.
    #[test]
    fn audit_gate_rejects_when_pairing_returns_failure_byte() {
        let backend = ProgrammablePairingBackend { verdict_byte: 0x00 };
        let g1 = placeholder_g1();
        let g2 = placeholder_g2();
        let res = verify_groth16_pairing_identity::<_, false>(
            &backend, &g1, &g2, &g1, &g1, &g1, &g2, &g2, &g2,
        );
        assert!(
            matches!(res, Err(OnChainError::PairingCheckFailed)),
            "pairing-failure verdict must reject as PairingCheckFailed; got {res:?}",
        );
    }

    /// Probe several non-`0x01` bytes — the gate should reject each.
    /// The success criterion is exact byte equality, not "non-zero",
    /// so any byte except `0x01` should fail.
    #[test]
    fn audit_gate_rejects_any_non_one_verdict_byte() {
        let g1 = placeholder_g1();
        let g2 = placeholder_g2();
        for verdict in [0x00u8, 0x02, 0x42, 0x7F, 0xFE, 0xFF] {
            let backend = ProgrammablePairingBackend { verdict_byte: verdict };
            let res = verify_groth16_pairing_identity::<_, false>(
                &backend, &g1, &g2, &g1, &g1, &g1, &g2, &g2, &g2,
            );
            assert!(
                matches!(res, Err(OnChainError::PairingCheckFailed)),
                "verdict byte 0x{verdict:02X} must reject; got {res:?}",
            );
        }
    }

    /// Backend that returns a wrong-length pairing payload (not 32
    /// bytes) ⇒ gate rejects with PairingCheckFailed. Catches the
    /// failure mode where a syscall returns a malformed payload that
    /// could otherwise look like success at byte index 31.
    #[test]
    fn audit_gate_rejects_wrong_length_pairing_payload() {
        struct WrongLengthBackend;
        impl SyscallBackend for WrongLengthBackend {
            fn alt_bn128_group_op(
                &self,
                op: AltBn128Op,
                _: InputEndianness,
                _: &[u8],
            ) -> Result<Vec<u8>, OnChainError> {
                if matches!(op, AltBn128Op::Pairing) {
                    // Return 16 bytes instead of 32 — gate must reject.
                    Ok(alloc::vec![0x01u8; 16])
                } else {
                    Ok(alloc::vec![0u8; G1_LEN])
                }
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
        let g1 = placeholder_g1();
        let g2 = placeholder_g2();
        let res = verify_groth16_pairing_identity::<_, false>(
            &WrongLengthBackend, &g1, &g2, &g1, &g1, &g1, &g2, &g2, &g2,
        );
        assert!(
            matches!(res, Err(OnChainError::PairingCheckFailed)),
            "wrong-length pairing payload must reject; got {res:?}",
        );
    }

    /// Backend syscall error ⇒ propagates through `?` (NOT collapsed
    /// to PairingCheckFailed). Confirms the gate's error-path
    /// transparency — the underlying syscall error type surfaces.
    #[test]
    fn audit_gate_propagates_syscall_error() {
        struct FailingBackend;
        impl SyscallBackend for FailingBackend {
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
        let g1 = placeholder_g1();
        let g2 = placeholder_g2();
        let res = verify_groth16_pairing_identity::<_, false>(
            &FailingBackend, &g1, &g2, &g1, &g1, &g1, &g2, &g2, &g2,
        );
        assert!(
            matches!(res, Err(OnChainError::AltBn128SyscallFailed)),
            "syscall failure must propagate, not collapse to PairingCheckFailed; got {res:?}",
        );
    }
}
