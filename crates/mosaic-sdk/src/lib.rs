//! # mosaic-sdk
//!
//! Client-side helpers for building `VerifyProof` transactions and running
//! pre-flight verification locally before paying the on-chain CU cost.
//!
//! ## What's here
//!
//! - [`VerifyRequest`] — proof-system-agnostic inputs to a single
//!   verification (VK bytes, proof bytes, public inputs, program id).
//! - [`build_verify_proof_ix`] — assemble a Solana `Instruction` from a
//!   [`VerifyRequest`].
//! - [`preflight`] — run host-backend verification against the same
//!   canonical bytes the program will see, surfacing failures locally
//!   rather than via a failed on-chain transaction. Groth16 is always
//!   available; Phase-3 systems opt in through Cargo features
//!   (`plonk`, `hyperplonk`, `halo2`, `nova`, `stark`, or `all-phase3`).
//!
//! ## Feature matrix (session 33)
//!
//! | Feature | Adds | Compile-time dep |
//! |---|---|---|
//! | `default` | Groth16 preflight only | — |
//! | `plonk` | KZG-PLONK BN254 preflight | `mosaic-plonk` |
//! | `hyperplonk` | HyperPlonk-KZG preflight | `mosaic-hyperplonk` |
//! | `halo2` | Halo2-KZG preflight | `mosaic-halo2` |
//! | `nova` | Nova / HyperNova / ProtoStar preflight | `mosaic-nova` |
//! | `stark` | FRI-STARK preflight | `mosaic-stark` |
//! | `all-phase3` | All five Phase-3 systems | all above |
//!
//! For any non-enabled system, [`preflight`] returns an
//! `anyhow::Error` naming the feature needed.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use borsh::BorshSerialize;
use mosaic_core::{
    proof_system::{ProofSystem, ProofSystemId},
    syscall::host::HostBackend,
};
use mosaic_groth16::Groth16Verifier;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

/// Inputs to a single proof verification.
#[derive(Clone, Debug)]
pub struct VerifyRequest {
    /// On-chain program id.
    pub program_id: Pubkey,
    /// Proof system selector.
    pub proof_system: ProofSystemId,
    /// Canonical-format VK bytes.
    pub vk: Vec<u8>,
    /// Canonical-format proof bytes.
    pub proof: Vec<u8>,
    /// Canonical-format public inputs.
    pub public_inputs: Vec<u8>,
    /// Caller-provided account metas (none for the reference program).
    pub accounts: Vec<AccountMeta>,
}

impl VerifyRequest {
    /// Start building a [`VerifyRequest`] with the given program id
    /// and proof system. Public inputs, VK, and proof default to
    /// empty; accounts default to none.
    ///
    /// Session-33 quality-of-life constructor — callers who used to
    /// build a struct literal with six named fields can now chain
    /// setters instead.
    #[must_use]
    pub fn builder(program_id: Pubkey, proof_system: ProofSystemId) -> Self {
        Self {
            program_id,
            proof_system,
            vk: Vec::new(),
            proof: Vec::new(),
            public_inputs: Vec::new(),
            accounts: Vec::new(),
        }
    }

    /// Set the verifying-key canonical bytes.
    #[must_use]
    pub fn with_vk(mut self, vk: Vec<u8>) -> Self {
        self.vk = vk;
        self
    }

    /// Set the proof canonical bytes.
    #[must_use]
    pub fn with_proof(mut self, proof: Vec<u8>) -> Self {
        self.proof = proof;
        self
    }

    /// Set the public-input canonical bytes.
    #[must_use]
    pub fn with_public_inputs(mut self, public_inputs: Vec<u8>) -> Self {
        self.public_inputs = public_inputs;
        self
    }

    /// Set the Solana account metas (no-op for the reference program
    /// which doesn't touch accounts).
    #[must_use]
    pub fn with_accounts(mut self, accounts: Vec<AccountMeta>) -> Self {
        self.accounts = accounts;
        self
    }
}

/// Borsh-compatible payload mirroring `mosaic_program::VerifyProofData`.
/// We avoid a direct dependency on `mosaic-program` (which is `cdylib`)
/// to keep the SDK fully host-buildable.
#[derive(BorshSerialize)]
struct VerifyProofData {
    proof_system_id: u8,
    vk: Vec<u8>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
}

/// Build a `VerifyProof` instruction.
///
/// # Errors
///
/// - Borsh-serialization failure (effectively never for this payload
///   shape).
pub fn build_verify_proof_ix(req: &VerifyRequest) -> Result<Instruction> {
    let payload = VerifyProofData {
        proof_system_id: req.proof_system.as_byte(),
        vk: req.vk.clone(),
        proof: req.proof.clone(),
        public_inputs: req.public_inputs.clone(),
    };
    let mut data = Vec::with_capacity(
        1 + payload.vk.len() + payload.proof.len() + payload.public_inputs.len() + 16,
    );
    data.push(0x01); // InstructionTag::VerifyProof
    payload
        .serialize(&mut data)
        .context("borsh-serialize VerifyProofData")?;
    Ok(Instruction {
        program_id: req.program_id,
        accounts: req.accounts.clone(),
        data,
    })
}

/// Pre-flight verification: run the same verifier on the host backend
/// so the caller catches mismatches before paying for the failed
/// transaction.
///
/// Groth16 is always available. Phase-3 systems (PLONK, HyperPlonk,
/// Halo2, Nova, STARK) require their respective Cargo features;
/// without them, the matching `ProofSystemId` arm returns an error
/// naming the missing feature.
///
/// # Errors
///
/// - The underlying verifier's failure converted to
///   [`anyhow::Error`] (usually a [`mosaic_core::OnChainError`]).
/// - `"preflight not enabled for {slug}; add feature '{name}'"` when
///   the requested proof system's feature is disabled.
/// - `"unimplemented proof system"` for [`ProofSystemId::Risc0`] and
///   other variants without in-tree verifier crates.
pub fn preflight(req: &VerifyRequest) -> Result<()> {
    let backend = HostBackend::new();
    match req.proof_system {
        ProofSystemId::Groth16Bn254 => {
            let v = Groth16Verifier::<_, false>::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("groth16 preflight failed: {e}"))
        }
        #[cfg(feature = "plonk")]
        ProofSystemId::PlonkKzgBn254 => {
            use mosaic_plonk::PlonkKzgBn254;
            let v = PlonkKzgBn254::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("plonk preflight failed: {e}"))
        }
        #[cfg(not(feature = "plonk"))]
        ProofSystemId::PlonkKzgBn254 => Err(anyhow::anyhow!(
            "preflight not enabled for plonk_kzg_bn254; \
             add the 'plonk' feature to mosaic-sdk"
        )),
        #[cfg(feature = "hyperplonk")]
        ProofSystemId::HyperPlonkKzgBn254 => {
            use mosaic_hyperplonk::HyperPlonkKzgBn254;
            let v = HyperPlonkKzgBn254::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("hyperplonk preflight failed: {e}"))
        }
        #[cfg(not(feature = "hyperplonk"))]
        ProofSystemId::HyperPlonkKzgBn254 => Err(anyhow::anyhow!(
            "preflight not enabled for hyperplonk_kzg_bn254; \
             add the 'hyperplonk' feature to mosaic-sdk"
        )),
        #[cfg(feature = "halo2")]
        ProofSystemId::Halo2KzgBn254 => {
            use mosaic_halo2::Halo2KzgBn254;
            let v = Halo2KzgBn254::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("halo2 preflight failed: {e}"))
        }
        #[cfg(not(feature = "halo2"))]
        ProofSystemId::Halo2KzgBn254 => Err(anyhow::anyhow!(
            "preflight not enabled for halo2_kzg_bn254; \
             add the 'halo2' feature to mosaic-sdk"
        )),
        #[cfg(feature = "nova")]
        ProofSystemId::NovaFolding | ProofSystemId::ProtoStarFolding => {
            use mosaic_nova::NovaFolding;
            let v = NovaFolding::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("nova preflight failed: {e}"))
        }
        #[cfg(not(feature = "nova"))]
        ProofSystemId::NovaFolding | ProofSystemId::ProtoStarFolding => Err(anyhow::anyhow!(
            "preflight not enabled for nova_folding_bn254; \
             add the 'nova' feature to mosaic-sdk"
        )),
        #[cfg(feature = "stark")]
        ProofSystemId::FriStark => {
            use mosaic_stark::FriStark;
            let v = FriStark::new(&backend);
            ProofSystem::verify(&v, &req.vk, &req.proof, &req.public_inputs)
                .map_err(|e| anyhow::anyhow!("stark preflight failed: {e}"))
        }
        #[cfg(not(feature = "stark"))]
        ProofSystemId::FriStark => Err(anyhow::anyhow!(
            "preflight not enabled for fri_stark; \
             add the 'stark' feature to mosaic-sdk"
        )),
        other => Err(anyhow::anyhow!(
            "preflight not implemented for {} (no in-tree verifier)",
            other.slug()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> VerifyRequest {
        VerifyRequest::builder(Pubkey::new_unique(), ProofSystemId::Groth16Bn254)
            .with_vk(vec![0u8; 64])
            .with_proof(vec![0u8; 64])
            .with_public_inputs(vec![0u8; 32])
    }

    #[test]
    fn builder_populates_fields() {
        let pk = Pubkey::new_unique();
        let req = VerifyRequest::builder(pk, ProofSystemId::Groth16Bn254)
            .with_vk(vec![1u8; 10])
            .with_proof(vec![2u8; 20])
            .with_public_inputs(vec![3u8; 30])
            .with_accounts(vec![]);
        assert_eq!(req.program_id, pk);
        assert_eq!(req.proof_system, ProofSystemId::Groth16Bn254);
        assert_eq!(req.vk.len(), 10);
        assert_eq!(req.proof.len(), 20);
        assert_eq!(req.public_inputs.len(), 30);
        assert!(req.accounts.is_empty());
    }

    #[test]
    fn build_ix_produces_verifyproof_tag() {
        let req = sample_request();
        let ix = build_verify_proof_ix(&req).unwrap();
        assert_eq!(ix.program_id, req.program_id);
        assert_eq!(ix.data[0], 0x01, "instruction tag must be VerifyProof");
    }

    #[test]
    fn preflight_groth16_surfaces_verifier_error() {
        // Malformed proof bytes → verifier returns an error which
        // preflight() wraps in anyhow.
        let req = sample_request();
        let r = preflight(&req);
        assert!(r.is_err(), "zero-byte proof should fail groth16 preflight");
    }

    #[cfg(not(feature = "plonk"))]
    #[test]
    fn preflight_plonk_without_feature_names_feature() {
        let req = VerifyRequest::builder(
            Pubkey::new_unique(),
            ProofSystemId::PlonkKzgBn254,
        );
        let r = preflight(&req);
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("'plonk' feature"), "error: {msg}");
    }

    #[cfg(not(feature = "halo2"))]
    #[test]
    fn preflight_halo2_without_feature_names_feature() {
        let req = VerifyRequest::builder(
            Pubkey::new_unique(),
            ProofSystemId::Halo2KzgBn254,
        );
        let r = preflight(&req);
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("'halo2' feature"), "error: {msg}");
    }

    #[cfg(not(feature = "nova"))]
    #[test]
    fn preflight_nova_without_feature_names_feature() {
        for id in [
            ProofSystemId::NovaFolding,
            ProofSystemId::ProtoStarFolding,
        ] {
            let req = VerifyRequest::builder(Pubkey::new_unique(), id);
            let r = preflight(&req);
            let msg = r.unwrap_err().to_string();
            assert!(msg.contains("'nova' feature"), "error: {msg}");
        }
    }

    #[cfg(all(feature = "plonk", feature = "halo2", feature = "nova"))]
    #[test]
    fn preflight_multi_feature_dispatches_correctly() {
        // With features enabled, each Phase-3 system routes to its
        // verifier. Malformed bytes still fail — but crucially, they
        // fail with a verifier-side error (not a "feature missing"
        // error). Assert the error message naming differs.
        for (id, expected_prefix) in [
            (ProofSystemId::PlonkKzgBn254, "plonk preflight failed"),
            (ProofSystemId::Halo2KzgBn254, "halo2 preflight failed"),
            (ProofSystemId::NovaFolding, "nova preflight failed"),
            (ProofSystemId::ProtoStarFolding, "nova preflight failed"),
        ] {
            let req = VerifyRequest::builder(Pubkey::new_unique(), id);
            let r = preflight(&req);
            let msg = r.unwrap_err().to_string();
            assert!(
                msg.starts_with(expected_prefix),
                "expected {expected_prefix:?}, got {msg:?}"
            );
        }
    }
}
