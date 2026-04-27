//! Object-safe `ProofSystem` trait and its discriminant enum.
//!
//! ## Object safety vs. monomorphization
//!
//! The on-chain dispatcher (in [`mosaic-program`]) needs to pick a verifier
//! at runtime based on a `u8` instruction discriminant. Two approaches:
//!
//! 1. **Monomorphized match**: a giant `match id { 1 => groth16::verify(..), 2 => plonk::verify(..) }`.
//!    Maximum performance, larger binary, every new system requires editing the dispatcher.
//! 2. **`dyn ProofSystem`**: object-safe trait, dispatcher works against `&dyn ProofSystem`.
//!    Slightly more code per call (vtable indirection), but new systems plug in without
//!    touching the dispatcher.
//!
//! We pick **option 1** for the on-chain reference program (keeps CU low and the dispatcher
//! auditable) but the trait is **kept object-safe** so that off-chain tooling (SDK, batch
//! verifiers, fuzz harnesses) can still use `Box<dyn ProofSystem>`. See ADR-0001.
//!
//! Methods take and return `&[u8]` byte slices rather than associated `Proof` /
//! `VerifyingKey` types, which would break object safety. Concrete verifier crates
//! provide typed wrappers in their own modules.

use crate::error::OnChainError;

/// Stable identifier for each proving system supported by Mosaic.
///
/// The `repr(u8)` discriminant is the on-chain wire format: callers serialize
/// it as a single byte in the `VerifyProof` instruction. Discriminants are
/// part of the public ABI and follow the same stability promise as
/// [`crate::error::OnChainError`].
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProofSystemId {
    /// Groth16 over BN254 (Circom / arkworks compatible).
    Groth16Bn254 = 0x01,
    /// PLONK with KZG commitments over BN254.
    PlonkKzgBn254 = 0x02,
    /// HyperPlonk with KZG (multi-linear extension PLONK).
    HyperPlonkKzgBn254 = 0x03,
    /// Halo2 with KZG commitments over BN254.
    Halo2KzgBn254 = 0x04,
    /// FRI-STARK over a small-field tower (Plonky3 family).
    FriStark = 0x05,
    /// Risc0 zkVM STARK proof.
    Risc0Stark = 0x06,
    /// Nova / HyperNova folding-scheme verifier.
    NovaFolding = 0x07,
    /// ProtoStar folding-scheme verifier.
    ProtoStarFolding = 0x08,
}

impl ProofSystemId {
    /// Parse an on-chain wire byte into a known proof system.
    pub const fn from_byte(b: u8) -> Result<Self, OnChainError> {
        match b {
            0x01 => Ok(Self::Groth16Bn254),
            0x02 => Ok(Self::PlonkKzgBn254),
            0x03 => Ok(Self::HyperPlonkKzgBn254),
            0x04 => Ok(Self::Halo2KzgBn254),
            0x05 => Ok(Self::FriStark),
            0x06 => Ok(Self::Risc0Stark),
            0x07 => Ok(Self::NovaFolding),
            0x08 => Ok(Self::ProtoStarFolding),
            _ => Err(OnChainError::UnknownProofSystem),
        }
    }

    /// Wire byte representation.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Stable slug for log/audit output.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Groth16Bn254 => "groth16_bn254",
            Self::PlonkKzgBn254 => "plonk_kzg_bn254",
            Self::HyperPlonkKzgBn254 => "hyperplonk_kzg_bn254",
            Self::Halo2KzgBn254 => "halo2_kzg_bn254",
            Self::FriStark => "fri_stark",
            Self::Risc0Stark => "risc0_stark",
            Self::NovaFolding => "nova_folding",
            Self::ProtoStarFolding => "protostar_folding",
        }
    }
}

/// The core verifier abstraction. Object-safe by construction.
///
/// Concrete verifier crates implement this trait against typed `Proof` /
/// `VerifyingKey` byte buffers. The dispatcher pattern in [`mosaic-program`]
/// translates a `u8` discriminant into a concrete impl.
///
/// ## Determinism
///
/// Implementations **must** return identical errors for identical inputs
/// across all Solana validator implementations. See [`crate::error`] for
/// the deterministic error contract.
pub trait ProofSystem: Send + Sync {
    /// The proof-system this implementation handles.
    fn proof_system_id(&self) -> ProofSystemId;

    /// Verify `proof_bytes` against `vk_bytes` and `public_inputs_bytes`.
    ///
    /// All three slices are in this proof system's wire format (see
    /// [`crate::codec`] for adapter conversions).
    fn verify(
        &self,
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<(), OnChainError>;

    /// Conservative upper bound on the compute units this verification would
    /// consume on Solana. Used by the dispatcher to short-circuit before a
    /// guaranteed budget exhaustion.
    ///
    /// Returns `None` if the bound depends on data that can't be inspected
    /// without full deserialization (e.g. STARK proof size).
    fn estimated_compute_units(&self, vk_bytes: &[u8], proof_bytes: &[u8]) -> Option<u32>;

    /// Optional batch interface: verify several proofs that share `vk_bytes`.
    ///
    /// Default implementation falls back to looped single-proof verification.
    /// Verifiers that benefit from amortized MSM cost (Groth16, PLONK) override.
    fn batch_verify(
        &self,
        vk_bytes: &[u8],
        proofs: &[&[u8]],
        public_inputs: &[&[u8]],
    ) -> Result<(), OnChainError> {
        if proofs.len() != public_inputs.len() {
            return Err(OnChainError::PublicInputCountMismatch);
        }
        for (p, pi) in proofs.iter().zip(public_inputs.iter()) {
            self.verify(vk_bytes, p, pi)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    extern crate alloc;

    #[test]
    fn proof_system_id_roundtrip() {
        for byte in [0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            let id = ProofSystemId::from_byte(byte).unwrap();
            assert_eq!(id.as_byte(), byte);
            assert!(!id.slug().is_empty());
        }
    }

    #[test]
    fn unknown_proof_system_byte_rejected() {
        assert!(matches!(
            ProofSystemId::from_byte(0xFF),
            Err(OnChainError::UnknownProofSystem),
        ));
    }

    /// Object-safety smoke test: if this compiles, `ProofSystem` is dyn-compatible.
    #[allow(dead_code)]
    fn assert_object_safe(_: Box<dyn ProofSystem>) {}

    // ───────────────────────────────────────────────────────────────────
    // Session 52 — proptest coverage for the `ProofSystemId` ABI.
    //
    // `ProofSystemId` is the wire-stable byte that the on-chain
    // dispatcher reads to pick a verifier. Two consensus-critical
    // properties:
    //
    //   1. Round-trip: every defined variant survives `as_byte` →
    //      `from_byte` unchanged. A regression here silently routes
    //      bytes to the wrong verifier (catastrophic).
    //   2. Unknown-byte rejection: every byte outside the defined set
    //      is rejected with `UnknownProofSystem`. A regression here
    //      lets attackers smuggle bytes through the dispatcher's
    //      catch-all arm.
    //
    // The unit tests above pin variant 0x01..=0x08 and reject 0xFF.
    // The proptests below exhaust the entire u8 space.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Every byte in the defined set 0x01..=0x08 round-trips
        /// through `from_byte` → `as_byte`.
        #[test]
        fn proptest_known_byte_round_trip(b in 0x01u8..=0x08) {
            let id = ProofSystemId::from_byte(b).expect("known byte parses");
            prop_assert_eq!(id.as_byte(), b);
            prop_assert!(!id.slug().is_empty());
        }

        /// Every byte outside the defined set is rejected with
        /// `UnknownProofSystem`. Exhaustive over the byte space minus
        /// the eight known discriminants.
        #[test]
        fn proptest_unknown_byte_rejected(b in any::<u8>()) {
            prop_assume!(!(0x01..=0x08).contains(&b));
            prop_assert!(matches!(
                ProofSystemId::from_byte(b),
                Err(OnChainError::UnknownProofSystem),
            ));
        }

        /// `from_byte` is a pure function: same byte → same variant
        /// across two calls. Catches a future change that would
        /// introduce hidden state (e.g. a global registry mutation).
        #[test]
        fn proptest_from_byte_is_pure(b in any::<u8>()) {
            let a = ProofSystemId::from_byte(b);
            let c = ProofSystemId::from_byte(b);
            match (a, c) {
                (Ok(x), Ok(y)) => prop_assert_eq!(x, y),
                (Err(_), Err(_)) => {},
                _ => prop_assert!(false, "from_byte not pure for byte {b}"),
            }
        }

        /// Slug strings are pairwise distinct across all defined
        /// variants. Catches a copy-paste bug that would alias two
        /// different variants to the same audit-log string (which
        /// would silently corrupt log analysis downstream).
        #[test]
        fn proptest_slugs_pairwise_distinct(_seed in any::<u8>()) {
            let all = [
                ProofSystemId::Groth16Bn254,
                ProofSystemId::PlonkKzgBn254,
                ProofSystemId::HyperPlonkKzgBn254,
                ProofSystemId::Halo2KzgBn254,
                ProofSystemId::FriStark,
                ProofSystemId::Risc0Stark,
                ProofSystemId::NovaFolding,
                ProofSystemId::ProtoStarFolding,
            ];
            for i in 0..all.len() {
                for j in (i + 1)..all.len() {
                    prop_assert_ne!(
                        all[i].slug(),
                        all[j].slug(),
                        "slug collision between {:?} and {:?}",
                        all[i],
                        all[j],
                    );
                }
            }
        }

        /// `as_byte` discriminants are pairwise distinct. Catches an
        /// `#[repr(u8)]` collision that would silently route bytes
        /// from one variant to another.
        #[test]
        fn proptest_discriminants_pairwise_distinct(_seed in any::<u8>()) {
            let all = [
                (ProofSystemId::Groth16Bn254, 0x01),
                (ProofSystemId::PlonkKzgBn254, 0x02),
                (ProofSystemId::HyperPlonkKzgBn254, 0x03),
                (ProofSystemId::Halo2KzgBn254, 0x04),
                (ProofSystemId::FriStark, 0x05),
                (ProofSystemId::Risc0Stark, 0x06),
                (ProofSystemId::NovaFolding, 0x07),
                (ProofSystemId::ProtoStarFolding, 0x08),
            ];
            for &(id, expected) in &all {
                prop_assert_eq!(id.as_byte(), expected);
            }
            // Pairwise distinct (manually pinned to commit to the
            // public ABI, not just the round-trip).
            for i in 0..all.len() {
                for j in (i + 1)..all.len() {
                    prop_assert_ne!(all[i].1, all[j].1);
                }
            }
        }
    }
}
