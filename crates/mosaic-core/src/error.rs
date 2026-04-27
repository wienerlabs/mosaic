//! Two-layer error model for Mosaic verifiers.
//!
//! ## Why two layers?
//!
//! Solana validators must agree byte-for-byte on every transaction's outcome.
//! If the Agave validator returns `Custom(7)` for a malformed proof while
//! Firedancer returns `Custom(8)`, the network forks. To prevent this, the
//! on-chain layer is a small, finite, repr-u32 enum whose discriminants are
//! part of the public ABI and never change without a protocol-version bump.
//!
//! Off-chain callers (tests, SDK, indexers) want richer information for
//! debugging — file paths, expected vs actual byte lengths, the precise
//! arkworks error chain. That information lives in [`DiagnosticError`], which
//! is feature-gated (`diagnostics`) and never reaches on-chain code.
//!
//! See ADR-0002 for the full reasoning, and SIMD-0129 for the original
//! consensus-failure incident that motivates this design.

use core::fmt;

/// On-chain deterministic error code. Discriminants are part of the public ABI.
///
/// **Stability promise:** existing variants never change discriminant.
/// New variants append at the next free discriminant. Removing a variant
/// requires a protocol-version bump and is recorded in `AUDIT.md`.
///
/// On-chain code converts this to `solana_program::program_error::ProgramError::Custom(code as u32)`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OnChainError {
    // 0x0001..0x000F — input format errors
    /// Proof byte length does not match the expected size for this proof system.
    ProofLengthMismatch = 0x0001,
    /// Verifying-key byte length does not match the expected size.
    VerifyingKeyLengthMismatch = 0x0002,
    /// Public input count does not match the verifying key.
    PublicInputCountMismatch = 0x0003,
    /// A field element exceeds the BN254 scalar field order `r`.
    PublicInputOutOfRange = 0x0004,
    /// A G1 or G2 point byte serialization is malformed.
    InvalidPointEncoding = 0x0005,
    /// A G1 or G2 point lies off-curve or in the wrong subgroup.
    PointNotOnCurve = 0x0006,
    /// A field element byte serialization is malformed.
    InvalidFieldEncoding = 0x0007,
    /// VK and proof headers disagree on a structural parameter (field id,
    /// trace shape, column count, ...). Caller shipped inconsistent
    /// configuration; a real verifier would produce garbage challenges
    /// and fail cryptographically, but surfacing the mismatch up-front
    /// yields a clearer error.
    VerifyingKeyProofMismatch = 0x0008,

    // 0x0010..0x001F — proof system selection
    /// Unknown `ProofSystemId` discriminant.
    UnknownProofSystem = 0x0010,
    /// The verifier for the requested proof system is not yet implemented.
    UnimplementedProofSystem = 0x0011,
    /// The selected proof system does not support the requested operation
    /// (e.g. batch verify on a system without batching).
    UnsupportedOperation = 0x0012,

    // 0x0020..0x002F — verification failure
    /// The pairing check failed (proof is invalid).
    PairingCheckFailed = 0x0020,
    /// FRI low-degree test failed.
    FriCheckFailed = 0x0021,
    /// Polynomial commitment opening verification failed.
    OpeningCheckFailed = 0x0022,
    /// Sumcheck round verification failed.
    SumcheckFailed = 0x0023,
    /// Generic verifier failure with no further detail (defensive default).
    VerificationFailed = 0x002F,

    // 0x0030..0x003F — chunked-upload protocol errors
    /// Chunk index is out of order or duplicated.
    ChunkOutOfOrder = 0x0030,
    /// Final rolling-hash commitment did not match the precommitted digest.
    ChunkCommitmentMismatch = 0x0031,
    /// Total assembled length exceeded the session's declared maximum.
    ChunkOverflow = 0x0032,
    /// Session has already been finalized; no more chunks accepted.
    SessionAlreadyFinalized = 0x0033,
    /// Session was finalized in a different transaction than `commit_and_verify`.
    SessionContextMismatch = 0x0034,
    /// `InitializeSession` called for a PDA that already holds session state.
    SessionAlreadyInitialized = 0x0035,
    /// `CancelExpiredSession` called before `expires_at_slot`.
    SessionNotExpired = 0x0036,

    // 0x0040..0x004F — syscall surface errors
    /// `sol_alt_bn128_group_op` returned a non-zero status.
    AltBn128SyscallFailed = 0x0040,
    /// `sol_alt_bn128_compression` returned a non-zero status.
    AltBn128CompressionSyscallFailed = 0x0041,
    /// `sol_poseidon` returned a non-zero status.
    PoseidonSyscallFailed = 0x0042,
    /// `sol_sha256` syscall returned a non-zero status.
    Sha256SyscallFailed = 0x0043,
    /// `sol_keccak256` syscall returned a non-zero status.
    Keccak256SyscallFailed = 0x0044,

    // 0x0050..0x005F — resource limits
    /// Verification would exceed the declared compute-unit budget.
    ComputeBudgetExceeded = 0x0050,
    /// Bump arena ran out of capacity.
    HeapExhausted = 0x0051,

    // 0x00FF — catch-all
    /// An internal invariant was violated. Should never reach the chain;
    /// presence indicates a bug in Mosaic itself.
    InternalInvariantViolation = 0x00FF,
}

impl OnChainError {
    /// Discriminant as `u32`, for `ProgramError::Custom`.
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Stable short identifier, useful for log messages and indexer parsing.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::ProofLengthMismatch => "proof_length_mismatch",
            Self::VerifyingKeyLengthMismatch => "vk_length_mismatch",
            Self::PublicInputCountMismatch => "public_input_count_mismatch",
            Self::PublicInputOutOfRange => "public_input_out_of_range",
            Self::InvalidPointEncoding => "invalid_point_encoding",
            Self::PointNotOnCurve => "point_not_on_curve",
            Self::InvalidFieldEncoding => "invalid_field_encoding",
            Self::VerifyingKeyProofMismatch => "vk_proof_mismatch",
            Self::UnknownProofSystem => "unknown_proof_system",
            Self::UnimplementedProofSystem => "unimplemented_proof_system",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::PairingCheckFailed => "pairing_check_failed",
            Self::FriCheckFailed => "fri_check_failed",
            Self::OpeningCheckFailed => "opening_check_failed",
            Self::SumcheckFailed => "sumcheck_failed",
            Self::VerificationFailed => "verification_failed",
            Self::ChunkOutOfOrder => "chunk_out_of_order",
            Self::ChunkCommitmentMismatch => "chunk_commitment_mismatch",
            Self::ChunkOverflow => "chunk_overflow",
            Self::SessionAlreadyFinalized => "session_already_finalized",
            Self::SessionContextMismatch => "session_context_mismatch",
            Self::SessionAlreadyInitialized => "session_already_initialized",
            Self::SessionNotExpired => "session_not_expired",
            Self::AltBn128SyscallFailed => "alt_bn128_syscall_failed",
            Self::AltBn128CompressionSyscallFailed => "alt_bn128_compression_syscall_failed",
            Self::PoseidonSyscallFailed => "poseidon_syscall_failed",
            Self::Sha256SyscallFailed => "sha256_syscall_failed",
            Self::Keccak256SyscallFailed => "keccak256_syscall_failed",
            Self::ComputeBudgetExceeded => "compute_budget_exceeded",
            Self::HeapExhausted => "heap_exhausted",
            Self::InternalInvariantViolation => "internal_invariant_violation",
        }
    }
}

impl fmt::Display for OnChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (code 0x{:04X})", self.slug(), self.code())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OnChainError {}

#[cfg(feature = "solana")]
impl From<OnChainError> for solana_program::program_error::ProgramError {
    fn from(err: OnChainError) -> Self {
        Self::Custom(err.code())
    }
}

/// Off-chain diagnostic error. Carries arbitrary text and structured detail
/// for tests, SDK callers, and indexers. **Never** reaches on-chain code.
///
/// Every variant collapses to an [`OnChainError`] via the [`Into`] impl —
/// this is what guarantees on-chain determinism even when the off-chain
/// layer adds new variants.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiagnosticError {
    /// Wraps an [`OnChainError`] with optional context string.
    #[error("{onchain} ({context})")]
    Tagged {
        /// The deterministic on-chain code this maps to.
        onchain: OnChainError,
        /// Free-form context for off-chain consumers.
        context: String,
    },

    /// Byte-length mismatch with expected/actual values for clearer debugging.
    #[error("expected {expected} bytes, got {actual} ({field})")]
    LengthMismatch {
        /// Symbolic name of the buffer (e.g. "proof.a", "vk.gamma_g2").
        field: &'static str,
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
        /// Underlying on-chain error code.
        onchain: OnChainError,
    },

    /// Format adapter failure — e.g. snarkjs JSON parse error.
    #[error("format-adapter failure: {0}")]
    Format(String),

    /// Underlying arkworks serialization error (host-backend only).
    #[cfg(feature = "host-backend")]
    #[cfg_attr(docsrs, doc(cfg(feature = "host-backend")))]
    #[error("arkworks serialization: {0}")]
    Arkworks(ark_serialize::SerializationError),
}

#[cfg(feature = "std")]
impl DiagnosticError {
    /// Project this diagnostic onto its deterministic on-chain code.
    /// This is the **only** legal path from off-chain to on-chain errors.
    #[must_use]
    pub fn into_onchain(self) -> OnChainError {
        match self {
            Self::Tagged { onchain, .. } | Self::LengthMismatch { onchain, .. } => onchain,
            Self::Format(_) => OnChainError::InvalidPointEncoding,
            #[cfg(feature = "host-backend")]
            Self::Arkworks(_) => OnChainError::InvalidPointEncoding,
        }
    }
}

/// Re-export bundling both error layers for convenience.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub type MosaicError = DiagnosticError;

/// In `no_std` builds the diagnostic layer is unavailable; `MosaicError`
/// becomes an alias for the deterministic on-chain enum.
#[cfg(not(feature = "std"))]
pub type MosaicError = OnChainError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminant_stability() {
        // ABI lock — these specific discriminants must never change.
        assert_eq!(OnChainError::ProofLengthMismatch.code(), 0x0001);
        assert_eq!(OnChainError::VerifyingKeyProofMismatch.code(), 0x0008);
        assert_eq!(OnChainError::PairingCheckFailed.code(), 0x0020);
        assert_eq!(OnChainError::ChunkCommitmentMismatch.code(), 0x0031);
        assert_eq!(OnChainError::SessionAlreadyInitialized.code(), 0x0035);
        assert_eq!(OnChainError::SessionNotExpired.code(), 0x0036);
        assert_eq!(OnChainError::AltBn128SyscallFailed.code(), 0x0040);
        assert_eq!(OnChainError::InternalInvariantViolation.code(), 0x00FF);
    }

    #[test]
    fn slug_is_snake_case() {
        for err in [
            OnChainError::ProofLengthMismatch,
            OnChainError::PairingCheckFailed,
            OnChainError::ChunkCommitmentMismatch,
        ] {
            let slug = err.slug();
            assert!(slug.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 52 — proptest coverage for the `OnChainError` ABI.
    //
    // OnChainError is the consensus-critical error taxonomy: every
    // variant's u32 discriminant is part of the program's public ABI
    // (returned via `ProgramError::Custom(code)` to clients). Two
    // properties pinned exhaustively here:
    //
    //   1. **Discriminant stability**: every defined variant's `code()`
    //      matches the value committed in this module's source. The
    //      unit tests above pin a handful of specific points; the
    //      proptest below pins all 30+ variants.
    //
    //   2. **Slug invariants**: every variant's slug is non-empty,
    //      ASCII snake-case, and pairwise distinct from every other
    //      slug. A regression here would silently corrupt audit-log
    //      analysis downstream (two different errors aliasing the
    //      same string).
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    /// All defined OnChainError variants paired with their committed
    /// discriminant codes. Anchors the public ABI so an external
    /// indexer can copy this list as the source of truth.
    const ALL_VARIANTS: &[(OnChainError, u32, &str)] = &[
        (
            OnChainError::ProofLengthMismatch,
            0x0001,
            "proof_length_mismatch",
        ),
        (
            OnChainError::VerifyingKeyLengthMismatch,
            0x0002,
            "vk_length_mismatch",
        ),
        (
            OnChainError::PublicInputCountMismatch,
            0x0003,
            "public_input_count_mismatch",
        ),
        (
            OnChainError::PublicInputOutOfRange,
            0x0004,
            "public_input_out_of_range",
        ),
        (
            OnChainError::InvalidPointEncoding,
            0x0005,
            "invalid_point_encoding",
        ),
        (OnChainError::PointNotOnCurve, 0x0006, "point_not_on_curve"),
        (
            OnChainError::InvalidFieldEncoding,
            0x0007,
            "invalid_field_encoding",
        ),
        (
            OnChainError::VerifyingKeyProofMismatch,
            0x0008,
            "vk_proof_mismatch",
        ),
        (
            OnChainError::UnknownProofSystem,
            0x0010,
            "unknown_proof_system",
        ),
        (
            OnChainError::UnimplementedProofSystem,
            0x0011,
            "unimplemented_proof_system",
        ),
        (
            OnChainError::UnsupportedOperation,
            0x0012,
            "unsupported_operation",
        ),
        (
            OnChainError::PairingCheckFailed,
            0x0020,
            "pairing_check_failed",
        ),
        (OnChainError::FriCheckFailed, 0x0021, "fri_check_failed"),
        (
            OnChainError::OpeningCheckFailed,
            0x0022,
            "opening_check_failed",
        ),
        (OnChainError::SumcheckFailed, 0x0023, "sumcheck_failed"),
        (
            OnChainError::VerificationFailed,
            0x002F,
            "verification_failed",
        ),
        (OnChainError::ChunkOutOfOrder, 0x0030, "chunk_out_of_order"),
        (
            OnChainError::ChunkCommitmentMismatch,
            0x0031,
            "chunk_commitment_mismatch",
        ),
        (OnChainError::ChunkOverflow, 0x0032, "chunk_overflow"),
        (
            OnChainError::SessionAlreadyFinalized,
            0x0033,
            "session_already_finalized",
        ),
        (
            OnChainError::SessionContextMismatch,
            0x0034,
            "session_context_mismatch",
        ),
        (
            OnChainError::SessionAlreadyInitialized,
            0x0035,
            "session_already_initialized",
        ),
        (
            OnChainError::SessionNotExpired,
            0x0036,
            "session_not_expired",
        ),
        (
            OnChainError::AltBn128SyscallFailed,
            0x0040,
            "alt_bn128_syscall_failed",
        ),
        (
            OnChainError::AltBn128CompressionSyscallFailed,
            0x0041,
            "alt_bn128_compression_syscall_failed",
        ),
        (
            OnChainError::PoseidonSyscallFailed,
            0x0042,
            "poseidon_syscall_failed",
        ),
        (
            OnChainError::Sha256SyscallFailed,
            0x0043,
            "sha256_syscall_failed",
        ),
        (
            OnChainError::Keccak256SyscallFailed,
            0x0044,
            "keccak256_syscall_failed",
        ),
        (
            OnChainError::ComputeBudgetExceeded,
            0x0050,
            "compute_budget_exceeded",
        ),
        (OnChainError::HeapExhausted, 0x0051, "heap_exhausted"),
        (
            OnChainError::InternalInvariantViolation,
            0x00FF,
            "internal_invariant_violation",
        ),
    ];

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Every defined variant's `code()` matches the committed
        /// discriminant. Pins the on-chain ABI exhaustively rather
        /// than via a handful of named samples.
        #[test]
        fn proptest_all_discriminants_stable(idx in 0usize..ALL_VARIANTS.len()) {
            let (variant, expected_code, _slug) = ALL_VARIANTS[idx];
            prop_assert_eq!(variant.code(), expected_code);
        }

        /// Every defined variant's `slug()` matches the committed
        /// identifier. Pin against silent renames in the slug match arm.
        #[test]
        fn proptest_all_slugs_stable(idx in 0usize..ALL_VARIANTS.len()) {
            let (variant, _code, expected_slug) = ALL_VARIANTS[idx];
            prop_assert_eq!(variant.slug(), expected_slug);
        }

        /// Every variant's slug is ASCII snake-case (lowercase +
        /// digit + '_' only). Catches a future variant whose slug
        /// accidentally includes uppercase or punctuation, which
        /// would break the downstream indexer convention.
        ///
        /// Digits are allowed because curve names embed them
        /// (`alt_bn128`, `bn254`, `mersenne31`). The unit test
        /// `slug_is_snake_case` above only spot-checks three
        /// variants without digits; this proptest pins the digit
        /// allowance across the whole variant set.
        #[test]
        fn proptest_all_slugs_snake_case(idx in 0usize..ALL_VARIANTS.len()) {
            let (variant, _code, _) = ALL_VARIANTS[idx];
            let slug = variant.slug();
            prop_assert!(!slug.is_empty(), "empty slug for {variant:?}");
            prop_assert!(
                slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "slug {slug:?} for {variant:?} is not snake_case",
            );
        }

        /// All discriminant codes are pairwise distinct. A collision
        /// would alias two different on-chain errors to the same
        /// `ProgramError::Custom(code)`, breaking any client that
        /// dispatches on the code.
        #[test]
        fn proptest_discriminant_codes_pairwise_distinct(_seed in any::<u8>()) {
            for i in 0..ALL_VARIANTS.len() {
                for j in (i + 1)..ALL_VARIANTS.len() {
                    let (a, ca, _) = ALL_VARIANTS[i];
                    let (b, cb, _) = ALL_VARIANTS[j];
                    prop_assert_ne!(
                        ca,
                        cb,
                        "discriminant collision: {:?} and {:?} both = {:#06x}",
                        a,
                        b,
                        ca,
                    );
                }
            }
        }

        /// All slugs are pairwise distinct. A collision would corrupt
        /// audit-log analysis (two errors becoming indistinguishable
        /// in the program log).
        #[test]
        fn proptest_slugs_pairwise_distinct(_seed in any::<u8>()) {
            for i in 0..ALL_VARIANTS.len() {
                for j in (i + 1)..ALL_VARIANTS.len() {
                    let (a, _, sa) = ALL_VARIANTS[i];
                    let (b, _, sb) = ALL_VARIANTS[j];
                    prop_assert_ne!(
                        sa,
                        sb,
                        "slug collision: {:?} and {:?} both = {:?}",
                        a,
                        b,
                        sa,
                    );
                }
            }
        }
    }
}
