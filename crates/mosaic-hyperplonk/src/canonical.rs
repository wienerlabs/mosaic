//! `HyperPlonk` canonical byte layout — **session-3d revision**.
//!
//! Expanded from the session-3 scaffold placeholder to a PLONK-style
//! gate + permutation layout, which is what Espresso's `HyperPlonk`
//! reference impl actually uses. The exact byte ordering still needs
//! to be pinned against an upstream fixture in session 3e; this
//! revision locks the *shape* so the verifier body can reference
//! stable field names.
//!
//! ## Reference impl survey
//!
//! Multiple `HyperPlonk` prover implementations exist today with divergent
//! wire formats:
//!
//! | Impl | Proof size (2^10 circuit) | Notes |
//! |---|---|---|
//! | [Espresso `hyperplonk`](https://github.com/EspressoSystems/hyperplonk) | ~3 KB | Reference; most active |
//! | `arkworks-rs/poly-commit` MLE path | ~2 KB | Pairing-free; WIP |
//! | Privacy-Scaling-Explorations variant | ~4 KB | Includes lookup argument |
//!
//! This revision targets the Espresso-style layout: 4 witness
//! commitments + permutation grand-product + sumcheck round polys +
//! 12 final evaluations (4 wires + 5 selectors + 3 permutation σ) +
//! KZG opening.
//!
//! ## Proof layout
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0   | 64   | `a`: G1 commitment to witness A (as MLE) |
//! | 64  | 64   | `b`: G1 commitment to witness B |
//! | 128 | 64   | `c`: G1 commitment to witness C |
//! | 192 | 64   | `z`: G1 commitment to permutation grand-product MLE |
//! | 256 | 4    | `sumcheck_rounds` (u32 LE) — = log₂(circuit size) |
//! | 260 | 96 × N | `sumcheck_polys` — N round polynomials, each 3 × 32 B Fr coefficients (degree-2 per round for the zero-check sumcheck) |
//! | …   | 32 × 12 | Final evaluations at the sumcheck challenge point: `a, b, c, z, q_m, q_l, q_r, q_o, q_c, σ_1, σ_2, σ_3` |
//! | …   | 64   | KZG batched opening proof at the challenge point |
//!
//! Total size for `sumcheck_rounds = 10` (2^10 circuit):
//! 4·64 + 4 + 10·96 + 12·32 + 64 = **1732 B**. Still fits a single
//! Solana tx (1232 B limit → needs chunked upload for this size, but
//! borderline — circuits up to 2^6 with simple gates fit inline).
//!
//! ## Final-evals bundle convention
//!
//! The 12 × 32-byte evaluations appear in a fixed order matching
//! [`FinalEvalsIndex`]. The verifier's gate + permutation check reads
//! this bundle and feeds values into [`crate::gate::WireEvals`] +
//! [`crate::gate::SelectorEvals`] + the permutation σ struct (session
//! 3d-2).
//!
//! **TODO(mosaic-002-3e)**: Pin this layout against the chosen upstream
//! reference (Espresso) before any adapter in `mosaic-serde` can be
//! written.

use alloc::vec::Vec;
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// Size constants for the `HyperPlonk` canonical layout.
pub mod sizes {
    /// G1 affine point (x || y, each 32-byte BE).
    pub const G1_LEN: usize = 64;
    /// Fr element (BN254 scalar field, big-endian).
    pub const FR_LEN: usize = 32;
    /// Sumcheck round polynomial coefficient count (degree-2 = 3 coeffs).
    pub const SUMCHECK_POLY_COEFFS: usize = 3;
    /// Bytes per sumcheck round polynomial.
    pub const SUMCHECK_POLY_LEN: usize = SUMCHECK_POLY_COEFFS * FR_LEN;
    /// Number of Fr evaluations in the final bundle.
    ///
    /// Layout (session 3d):
    /// - 4 wire evaluations: `a, b, c, z` (indexes 0..4)
    /// - 5 selector evaluations: `q_m, q_l, q_r, q_o, q_c` (indexes 4..9)
    /// - 3 permutation σ evaluations: `σ_1, σ_2, σ_3` (indexes 9..12)
    pub const FINAL_EVALS: usize = 12;
    /// Fixed header length (everything before `sumcheck_polys`): 4 × G1 + u32.
    pub const FIXED_HEADER_LEN: usize = 4 * G1_LEN + 4;
    /// Fixed tail length (final evals + KZG opening): 12 × Fr + G1.
    pub const FIXED_TAIL_LEN: usize = FINAL_EVALS * FR_LEN + G1_LEN;

    /// Minimum proof size (0 sumcheck rounds, edge case).
    pub const MIN_PROOF_LEN: usize = FIXED_HEADER_LEN + FIXED_TAIL_LEN;
    /// Maximum supported sumcheck rounds. Circuits of size 2^28 or
    /// smaller fit; matches arkworks' `TWO_ADICITY` ceiling.
    pub const MAX_SUMCHECK_ROUNDS: u32 = 28;
}

/// Zero-copy view into a `HyperPlonk` proof buffer.
///
/// Because the sumcheck-polynomial count is dynamic (one per round), the
/// `sumcheck_polys` and evaluation slices are raw byte windows rather
/// than fixed-size arrays. Callers iterate in `SUMCHECK_POLY_LEN`
/// chunks for round polynomials.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HyperPlonkProof<'a> {
    /// Witness commitment A (G1).
    pub a: &'a [u8],
    /// Witness commitment B (G1).
    pub b: &'a [u8],
    /// Witness commitment C (G1).
    pub c: &'a [u8],
    /// Permutation grand-product commitment (G1).
    pub z: &'a [u8],
    /// Number of sumcheck rounds (= log₂ of circuit size).
    pub sumcheck_rounds: u32,
    /// All round polynomials concatenated. Length == `sumcheck_rounds * SUMCHECK_POLY_LEN`.
    pub sumcheck_polys: &'a [u8],
    /// Final-round MLE evaluations: `eval_a` || `eval_b` || `eval_c` || `eval_z`.
    pub final_evals: &'a [u8],
    /// KZG opening proof (G1) at the final sumcheck challenge point.
    pub kzg_opening: &'a [u8],
}

impl<'a> HyperPlonkProof<'a> {
    /// Parse a canonical `HyperPlonk` proof. Length-only validation; the
    /// sumcheck polynomials are not checked for Fr-range validity (that
    /// happens inside the verifier during challenge derivation).
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, OnChainError> {
        use sizes::{
            FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN, G1_LEN, MAX_SUMCHECK_ROUNDS, MIN_PROOF_LEN,
            SUMCHECK_POLY_LEN,
        };
        if bytes.len() < MIN_PROOF_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let (a, rest) = bytes.split_at(G1_LEN);
        let (b, rest) = rest.split_at(G1_LEN);
        let (c, rest) = rest.split_at(G1_LEN);
        let (z, rest) = rest.split_at(G1_LEN);
        let (rounds_bytes, rest) = rest.split_at(4);
        let sumcheck_rounds = u32::from_le_bytes([
            rounds_bytes[0],
            rounds_bytes[1],
            rounds_bytes[2],
            rounds_bytes[3],
        ]);
        if sumcheck_rounds > MAX_SUMCHECK_ROUNDS {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let polys_len = (sumcheck_rounds as usize)
            .checked_mul(SUMCHECK_POLY_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let expected_len = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        if bytes.len() != expected_len {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let (sumcheck_polys, rest) = rest.split_at(polys_len);
        let (final_evals, kzg_opening) = rest.split_at(FINAL_EVALS * FR_LEN);
        debug_assert_eq!(kzg_opening.len(), G1_LEN);
        Ok(Self {
            a,
            b,
            c,
            z,
            sumcheck_rounds,
            sumcheck_polys,
            final_evals,
            kzg_opening,
        })
    }

    /// Iterate over the `sumcheck_rounds` round polynomials.
    pub fn round_polys(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.sumcheck_polys.chunks_exact(sizes::SUMCHECK_POLY_LEN)
    }
}

/// **Session 114** — HyperPlonk proof compression utilities.
///
/// HyperPlonk proof shape:
///   5 G1 commits: a, b, c, z, kzg_opening
///   u32 sumcheck_rounds + variable Fr region (sumcheck_polys + final_evals)
///
/// Uncompressed: `5 · 64 + 4 + rounds · 96 + 12 · 32`
///   = 320 + 4 + 96·rounds + 384 = 708 + 96·rounds bytes
/// Compressed:   `5 · 32 + 4 + rounds · 96 + 12 · 32`
///   = 160 + 4 + 96·rounds + 384 = 548 + 96·rounds bytes
/// Saving:       160 bytes (constant, regardless of round count)
///
/// CU cost per `decompress_to_canonical_bytes`: 5 × ~10 K = ~50 K CU.
/// Plus the existing `~505 K` HyperPlonk verify estimate gives ~10 %
/// overhead — comparable to PLONK (9 %).
///
/// ## Wire-format layout (compressed)
///
/// ```text
/// | offset | bytes | content                          |
/// |--------|-------|----------------------------------|
/// |   0    |  32   | compressed G1: a                 |
/// |  32    |  32   | compressed G1: b                 |
/// |  64    |  32   | compressed G1: c                 |
/// |  96    |  32   | compressed G1: z                 |
/// | 128    |   4   | sumcheck_rounds (u32 LE)         |
/// | 132    | 96·R  | sumcheck_polys (R rounds × 3 Fr) |
/// | 132+96R| 384   | final_evals (12 × 32 B Fr)       |
/// | …      |  32   | compressed G1: kzg_opening       |
/// ```
///
/// ## Why a single fixed `COMPRESSED_LEN` is **not** exposed
///
/// The proof carries a dynamic round count (`sumcheck_rounds`) that
/// determines the proof size. Unlike PLONK (whose proof is fixed at
/// 768 B), the HyperPlonk compressed buffer length is
/// `MIN_COMPRESSED_LEN + 96 · rounds`. Callers parse the embedded
/// u32 to derive the expected length — same pattern as Halo2.
impl HyperPlonkProof<'_> {
    /// G1 length under the alt_bn128 compressed encoding.
    const G1_COMPRESSED_LEN: usize = 32;

    /// Compressed proof byte length at zero sumcheck rounds (smallest
    /// well-formed shape). Real HyperPlonk circuits use ≥ 1 round.
    pub const MIN_COMPRESSED_LEN: usize =
        5 * Self::G1_COMPRESSED_LEN + 4 + sizes::FINAL_EVALS * sizes::FR_LEN;

    /// Compute the compressed proof length for a given sumcheck round
    /// count. Returns `None` if `rounds > MAX_SUMCHECK_ROUNDS`.
    #[must_use]
    pub fn compressed_len_for_rounds(rounds: u32) -> Option<usize> {
        if rounds > sizes::MAX_SUMCHECK_ROUNDS {
            return None;
        }
        Some(Self::MIN_COMPRESSED_LEN + (rounds as usize) * sizes::SUMCHECK_POLY_LEN)
    }

    /// Decompress a compressed-format HyperPlonk proof into the
    /// canonical uncompressed wire format.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] — buffer too small to
    ///   parse the round counter, declared `sumcheck_rounds` exceeds
    ///   `MAX_SUMCHECK_ROUNDS`, or input length disagrees with
    ///   `compressed_len_for_rounds(rounds)`.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any of
    ///   the 5 G1 commits fail decompression (off-curve / malformed).
    pub fn decompress_to_canonical_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        compressed: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        use sizes::{FINAL_EVALS, FR_LEN, G1_LEN, MAX_SUMCHECK_ROUNDS, SUMCHECK_POLY_LEN};
        const G1_C: usize = 32;

        if compressed.len() < Self::MIN_COMPRESSED_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }

        // Parse sumcheck_rounds at fixed offset 4·G1_C = 128.
        let rounds_off = 4 * G1_C;
        let sumcheck_rounds = u32::from_le_bytes([
            compressed[rounds_off],
            compressed[rounds_off + 1],
            compressed[rounds_off + 2],
            compressed[rounds_off + 3],
        ]);
        if sumcheck_rounds > MAX_SUMCHECK_ROUNDS {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let polys_len = (sumcheck_rounds as usize)
            .checked_mul(SUMCHECK_POLY_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let expected_clen =
            Self::MIN_COMPRESSED_LEN.saturating_add(polys_len);
        if compressed.len() != expected_clen {
            return Err(OnChainError::ProofLengthMismatch);
        }

        // Build canonical buffer: 5 G1 (uncompressed) + 4 + polys_len + final_evals.
        let canonical_len =
            4 * G1_LEN + 4 + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        let mut out: Vec<u8> = Vec::with_capacity(canonical_len);

        // Decompress 4 leading G1 commits (a, b, c, z).
        let mut o = 0;
        for _ in 0..4 {
            let mut arr = [0u8; G1_C];
            arr.copy_from_slice(&compressed[o..o + G1_C]);
            let full = mosaic_zk_primitives::compression::decompress_g1(backend, &arr)?;
            out.extend_from_slice(&full);
            o += G1_C;
        }
        debug_assert_eq!(o, 4 * G1_C);
        debug_assert_eq!(out.len(), 4 * G1_LEN);

        // Copy sumcheck_rounds u32 + polys + final_evals as-is.
        let pass_through_len = 4 + polys_len + FINAL_EVALS * FR_LEN;
        out.extend_from_slice(&compressed[o..o + pass_through_len]);
        o += pass_through_len;

        // Decompress trailing G1 (kzg_opening).
        let mut arr = [0u8; G1_C];
        arr.copy_from_slice(&compressed[o..o + G1_C]);
        let full = mosaic_zk_primitives::compression::decompress_g1(backend, &arr)?;
        out.extend_from_slice(&full);

        debug_assert_eq!(out.len(), canonical_len);
        Ok(out)
    }

    /// Compress a canonical HyperPlonk proof byte buffer.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] — input buffer fails
    ///   `from_bytes` validation (wrong length, declared rounds out
    ///   of range, etc.).
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any of
    ///   the 5 G1 commits fail compression (off-curve, etc.).
    pub fn compress_from_canonical_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        canonical: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        use sizes::{FINAL_EVALS, FR_LEN, G1_LEN, SUMCHECK_POLY_LEN};
        const G1_C: usize = 32;

        // Round-trip through `from_bytes` so we re-use its length /
        // round-count validation rather than open-coding it here.
        let view = HyperPlonkProof::from_bytes(canonical)?;

        let polys_len = (view.sumcheck_rounds as usize) * SUMCHECK_POLY_LEN;
        let expected_clen =
            Self::compressed_len_for_rounds(view.sumcheck_rounds)
                .ok_or(OnChainError::ProofLengthMismatch)?;
        let mut out: Vec<u8> = Vec::with_capacity(expected_clen);

        // Compress 4 leading G1 commits (a, b, c, z).
        let mut o = 0;
        for _ in 0..4 {
            let mut arr = [0u8; G1_LEN];
            arr.copy_from_slice(&canonical[o..o + G1_LEN]);
            let c = mosaic_zk_primitives::compression::compress_g1(backend, &arr)?;
            out.extend_from_slice(&c);
            o += G1_LEN;
        }
        debug_assert_eq!(out.len(), 4 * G1_C);

        // Copy sumcheck_rounds u32 + polys + final_evals as-is.
        let pass_through_len = 4 + polys_len + FINAL_EVALS * FR_LEN;
        out.extend_from_slice(&canonical[o..o + pass_through_len]);
        o += pass_through_len;

        // Compress trailing G1 (kzg_opening).
        let mut arr = [0u8; G1_LEN];
        arr.copy_from_slice(&canonical[o..o + G1_LEN]);
        let c = mosaic_zk_primitives::compression::compress_g1(backend, &arr)?;
        out.extend_from_slice(&c);

        debug_assert_eq!(out.len(), expected_clen);
        Ok(out)
    }
}

/// Byte offsets into the proof's `final_evals` bundle (12 × 32 B).
///
/// The ordering is fixed and defines the canonical layout contract
/// between provers and verifiers.
pub mod final_evals_index {
    /// Witness `a` evaluation at the sumcheck challenge point.
    pub const A: usize = 0;
    /// Witness `b` evaluation.
    pub const B: usize = 1;
    /// Witness `c` evaluation.
    pub const C: usize = 2;
    /// Permutation grand-product `z` evaluation.
    pub const Z: usize = 3;
    /// Multiplication-selector `q_M` evaluation.
    pub const Q_M: usize = 4;
    /// Left-wire selector `q_L` evaluation.
    pub const Q_L: usize = 5;
    /// Right-wire selector `q_R` evaluation.
    pub const Q_R: usize = 6;
    /// Output-wire selector `q_O` evaluation.
    pub const Q_O: usize = 7;
    /// Constant selector `q_C` evaluation.
    pub const Q_C: usize = 8;
    /// Permutation `σ_1` (left-wire) evaluation.
    pub const SIGMA_1: usize = 9;
    /// Permutation `σ_2` (right-wire) evaluation.
    pub const SIGMA_2: usize = 10;
    /// Permutation `σ_3` (output-wire) evaluation.
    pub const SIGMA_3: usize = 11;
}

/// `HyperPlonk` verifying key.
///
/// Session-3d revision expands the VK from a single `gate_g1`
/// placeholder to the full PLONK-style preprocessing:
/// 5 selector commitments + 3 permutation σ commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperPlonkVerifyingKey {
    /// Number of public inputs.
    pub n_public: u32,
    /// `log₂` of circuit size (defines the boolean hypercube dimension).
    pub num_variables: u32,
    /// G2 SRS element for KZG pairing check.
    pub x2_g2: [u8; 128],
    /// Selector commitment `[Q_M]` — multiplication selector MLE.
    pub q_m_g1: [u8; sizes::G1_LEN],
    /// Selector commitment `[Q_L]` — left-wire linear selector.
    pub q_l_g1: [u8; sizes::G1_LEN],
    /// Selector commitment `[Q_R]` — right-wire linear selector.
    pub q_r_g1: [u8; sizes::G1_LEN],
    /// Selector commitment `[Q_O]` — output-wire linear selector.
    pub q_o_g1: [u8; sizes::G1_LEN],
    /// Selector commitment `[Q_C]` — constant selector.
    pub q_c_g1: [u8; sizes::G1_LEN],
    /// Permutation σ commitment `[σ_1]` — left-wire permutation MLE.
    pub sigma_1_g1: [u8; sizes::G1_LEN],
    /// Permutation σ commitment `[σ_2]` — right-wire permutation MLE.
    pub sigma_2_g1: [u8; sizes::G1_LEN],
    /// Permutation σ commitment `[σ_3]` — output-wire permutation MLE.
    pub sigma_3_g1: [u8; sizes::G1_LEN],
    /// Permutation coset constant `k_1` for the left-wire identity
    /// factor in the PLONK grand-product (canonical 32-byte BE Fr).
    /// Sessions ≤17 hardcoded the triplet `(k_1, k_2, k_3) = (1, 2, 3)`;
    /// session 18 lifts this to a VK-side circuit-specific value so
    /// multi-point reductions can use any three distinct cosets.
    pub k_1: [u8; sizes::FR_LEN],
    /// Permutation coset constant `k_2` for the middle-wire identity
    /// factor. Must differ from `k_1` and `k_3` (otherwise the
    /// permutation argument loses its identity-separation property).
    pub k_2: [u8; sizes::FR_LEN],
    /// Permutation coset constant `k_3` for the output-wire identity
    /// factor. Must differ from `k_1` and `k_2`.
    pub k_3: [u8; sizes::FR_LEN],
}

impl HyperPlonkVerifyingKey {
    /// Number of preprocessed commitments (5 selectors + 3 σ).
    pub const NUM_COMMITS: usize = 8;

    /// Canonical BE-encoded Fr for the small integer `n`. Used to build
    /// the default `(k_1, k_2, k_3) = (1, 2, 3)` cosets in tests; real
    /// circuits pick distinct cosets via the VK ceremony.
    ///
    /// Session-24 forwards to the shared
    /// [`mosaic_zk_primitives::field::fr_be_from_u64`] primitive. The
    /// thin wrapper stays on this VK impl for discoverability —
    /// callers reading the VK definition see the helper without
    /// cross-referencing a different crate.
    #[must_use]
    pub const fn fr_be_from_u64(n: u64) -> [u8; sizes::FR_LEN] {
        mosaic_zk_primitives::field::fr_be_from_u64(n)
    }

    /// Serialized VK length:
    /// `n_public (4) + num_variables (4) + x2_g2 (128) + 8 × G1 (64)
    ///  + 3 × Fr (32)`.
    pub const SERIALIZED_LEN: usize =
        4 + 4 + 128 + Self::NUM_COMMITS * sizes::G1_LEN + 3 * sizes::FR_LEN;

    /// Decode from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let n_public = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let num_variables = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut x2_g2 = [0u8; 128];
        x2_g2.copy_from_slice(&bytes[8..136]);

        let mut off = 136;
        let mut take = || -> [u8; sizes::G1_LEN] {
            let mut out = [0u8; sizes::G1_LEN];
            out.copy_from_slice(&bytes[off..off + sizes::G1_LEN]);
            off += sizes::G1_LEN;
            out
        };
        let q_m_g1 = take();
        let q_l_g1 = take();
        let q_r_g1 = take();
        let q_o_g1 = take();
        let q_c_g1 = take();
        let sigma_1_g1 = take();
        let sigma_2_g1 = take();
        let sigma_3_g1 = take();
        let k_start = off;
        let take_fr = |i: usize| -> [u8; sizes::FR_LEN] {
            let mut out = [0u8; sizes::FR_LEN];
            let from = k_start + i * sizes::FR_LEN;
            out.copy_from_slice(&bytes[from..from + sizes::FR_LEN]);
            out
        };
        let k_1 = take_fr(0);
        let k_2 = take_fr(1);
        let k_3 = take_fr(2);
        Ok(Self {
            n_public,
            num_variables,
            x2_g2,
            q_m_g1,
            q_l_g1,
            q_r_g1,
            q_o_g1,
            q_c_g1,
            sigma_1_g1,
            sigma_2_g1,
            sigma_3_g1,
            k_1,
            k_2,
            k_3,
        })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SERIALIZED_LEN);
        out.extend_from_slice(&self.n_public.to_le_bytes());
        out.extend_from_slice(&self.num_variables.to_le_bytes());
        out.extend_from_slice(&self.x2_g2);
        out.extend_from_slice(&self.q_m_g1);
        out.extend_from_slice(&self.q_l_g1);
        out.extend_from_slice(&self.q_r_g1);
        out.extend_from_slice(&self.q_o_g1);
        out.extend_from_slice(&self.q_c_g1);
        out.extend_from_slice(&self.sigma_1_g1);
        out.extend_from_slice(&self.sigma_2_g1);
        out.extend_from_slice(&self.sigma_3_g1);
        out.extend_from_slice(&self.k_1);
        out.extend_from_slice(&self.k_2);
        out.extend_from_slice(&self.k_3);
        out
    }

    /// Iterate all 8 commitments in canonical order (matches the absorb
    /// order used by the Fiat-Shamir transcript in session 3d-2).
    pub fn commits_iter(&self) -> impl Iterator<Item = &[u8; sizes::G1_LEN]> {
        use core::iter;
        iter::once(&self.q_m_g1)
            .chain(iter::once(&self.q_l_g1))
            .chain(iter::once(&self.q_r_g1))
            .chain(iter::once(&self.q_o_g1))
            .chain(iter::once(&self.q_c_g1))
            .chain(iter::once(&self.sigma_1_g1))
            .chain(iter::once(&self.sigma_2_g1))
            .chain(iter::once(&self.sigma_3_g1))
    }

    // ─────────────────────────────────────────────────────────────────
    // Session 114 — HyperPlonk VK compression utilities.
    //
    // VK shape (canonical):
    //   8 (n_public + num_variables) + 128 (x2_g2) + 8·64 (selectors + σ)
    //   + 3·32 (k_1, k_2, k_3) = 8 + 128 + 512 + 96 = 744 bytes
    //
    // VK shape (compressed):
    //   8 + 64 (compressed G2) + 8·32 (compressed G1) + 96
    //   = 8 + 64 + 256 + 96 = 424 bytes
    // Saving: 320 bytes (43 %)
    //
    // CU cost per `from_compressed_bytes`: 8 × ~10 K (G1) + 1 × ~12 K
    // (G2) = ~92 K CU. The VK is typically uploaded once per circuit
    // and cached, so this cost is amortized aggressively.
    //
    // Wire-format layout (compressed):
    //   |   0 |   4 | n_public (u32 LE)                   |
    //   |   4 |   4 | num_variables (u32 LE)              |
    //   |   8 |  64 | compressed G2: x2_g2                |
    //   |  72 |  32 | compressed G1: q_m_g1               |
    //   | 104 |  32 | compressed G1: q_l_g1               |
    //   | 136 |  32 | compressed G1: q_r_g1               |
    //   | 168 |  32 | compressed G1: q_o_g1               |
    //   | 200 |  32 | compressed G1: q_c_g1               |
    //   | 232 |  32 | compressed G1: sigma_1_g1           |
    //   | 264 |  32 | compressed G1: sigma_2_g1           |
    //   | 296 |  32 | compressed G1: sigma_3_g1           |
    //   | 328 |  32 | k_1 (Fr canonical BE)               |
    //   | 360 |  32 | k_2 (Fr canonical BE)               |
    //   | 392 |  32 | k_3 (Fr canonical BE)               |
    //   = 424 bytes total
    // ─────────────────────────────────────────────────────────────────

    /// Compressed VK byte length.
    ///
    /// `n_public (4) + num_variables (4) + compressed G2 (64) +
    /// 8 × compressed G1 (32) + 3 × Fr (32) = 424`.
    pub const COMPRESSED_LEN: usize = 4 + 4 + 64 + Self::NUM_COMMITS * 32 + 3 * sizes::FR_LEN;

    /// Decompress a compressed VK byte buffer into the canonical
    /// 744-byte uncompressed wire format.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::VerifyingKeyLengthMismatch`] — input is not
    ///   exactly `COMPRESSED_LEN` (424) bytes.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any of
    ///   the 8 G1 commits or the G2 SRS element fails decompression.
    pub fn from_compressed_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        compressed: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        const G1_C: usize = 32;
        const G2_C: usize = 64;
        if compressed.len() != Self::COMPRESSED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        let mut out = Vec::with_capacity(Self::SERIALIZED_LEN);
        // n_public + num_variables: 8 bytes pass-through.
        out.extend_from_slice(&compressed[0..8]);

        // Decompress G2 SRS element (x2_g2).
        let mut g2_arr = [0u8; G2_C];
        g2_arr.copy_from_slice(&compressed[8..8 + G2_C]);
        let g2_full = mosaic_zk_primitives::compression::decompress_g2(backend, &g2_arr)?;
        out.extend_from_slice(&g2_full);

        // Decompress 8 G1 commits in canonical absorb order.
        let mut o = 8 + G2_C;
        for _ in 0..Self::NUM_COMMITS {
            let mut arr = [0u8; G1_C];
            arr.copy_from_slice(&compressed[o..o + G1_C]);
            let full = mosaic_zk_primitives::compression::decompress_g1(backend, &arr)?;
            out.extend_from_slice(&full);
            o += G1_C;
        }

        // Copy 3 Fr coset constants as-is.
        out.extend_from_slice(&compressed[o..o + 3 * sizes::FR_LEN]);
        debug_assert_eq!(out.len(), Self::SERIALIZED_LEN);
        Ok(out)
    }

    /// Compress a canonical 744-byte VK byte buffer.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::VerifyingKeyLengthMismatch`] — input is not
    ///   exactly `SERIALIZED_LEN` (744) bytes.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any of
    ///   the 8 G1 commits or the G2 SRS element fails compression.
    pub fn to_compressed_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        canonical: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        const G2_C: usize = 64;
        if canonical.len() != Self::SERIALIZED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        let mut out = Vec::with_capacity(Self::COMPRESSED_LEN);
        // n_public + num_variables: 8 bytes pass-through.
        out.extend_from_slice(&canonical[0..8]);

        // Compress G2 SRS element (x2_g2 starts at offset 8).
        let mut g2_arr = [0u8; 128];
        g2_arr.copy_from_slice(&canonical[8..8 + 128]);
        let g2_c = mosaic_zk_primitives::compression::compress_g2(backend, &g2_arr)?;
        debug_assert_eq!(g2_c.len(), G2_C);
        out.extend_from_slice(&g2_c);

        // Compress 8 G1 commits.
        let mut o = 8 + 128;
        for _ in 0..Self::NUM_COMMITS {
            let mut arr = [0u8; sizes::G1_LEN];
            arr.copy_from_slice(&canonical[o..o + sizes::G1_LEN]);
            let c = mosaic_zk_primitives::compression::compress_g1(backend, &arr)?;
            out.extend_from_slice(&c);
            o += sizes::G1_LEN;
        }

        // Copy 3 Fr coset constants as-is.
        out.extend_from_slice(&canonical[o..o + 3 * sizes::FR_LEN]);
        debug_assert_eq!(out.len(), Self::COMPRESSED_LEN);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sizes::{FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN, G1_LEN, MIN_PROOF_LEN, SUMCHECK_POLY_LEN};

    fn proof_bytes_for_rounds(rounds: u32) -> Vec<u8> {
        let polys_len = (rounds as usize) * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        let mut buf = vec![0xAB; total];
        // Fill sumcheck_rounds u32 LE at offset 256.
        buf[256..260].copy_from_slice(&rounds.to_le_bytes());
        buf
    }

    #[test]
    fn proof_layout_constants_consistent() {
        assert_eq!(
            MIN_PROOF_LEN,
            4 * G1_LEN + 4 + FINAL_EVALS * FR_LEN + G1_LEN
        );
        // 4·64 + 4 + 12·32 + 64 = 708.
        assert_eq!(MIN_PROOF_LEN, 708);
    }

    #[test]
    fn proof_parses_zero_rounds_edge_case() {
        let buf = proof_bytes_for_rounds(0);
        let p = HyperPlonkProof::from_bytes(&buf).unwrap();
        assert_eq!(p.sumcheck_rounds, 0);
        assert_eq!(p.sumcheck_polys.len(), 0);
        assert_eq!(p.round_polys().count(), 0);
    }

    #[test]
    fn proof_parses_10_rounds_circuit_size_1024() {
        let buf = proof_bytes_for_rounds(10);
        let p = HyperPlonkProof::from_bytes(&buf).unwrap();
        assert_eq!(p.sumcheck_rounds, 10);
        assert_eq!(p.sumcheck_polys.len(), 10 * SUMCHECK_POLY_LEN);
        assert_eq!(p.round_polys().count(), 10);
        for rp in p.round_polys() {
            assert_eq!(rp.len(), SUMCHECK_POLY_LEN);
        }
    }

    #[test]
    fn proof_rejects_rounds_over_max() {
        let bad_rounds = sizes::MAX_SUMCHECK_ROUNDS + 1;
        let polys_len = (bad_rounds as usize) * SUMCHECK_POLY_LEN;
        let total = FIXED_HEADER_LEN + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
        let mut buf = vec![0xAB; total];
        buf[256..260].copy_from_slice(&bad_rounds.to_le_bytes());
        assert!(matches!(
            HyperPlonkProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_wrong_length() {
        let buf = vec![0u8; MIN_PROOF_LEN - 1];
        assert!(matches!(
            HyperPlonkProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    fn sample_vk() -> HyperPlonkVerifyingKey {
        HyperPlonkVerifyingKey {
            n_public: 3,
            num_variables: 10,
            x2_g2: [0xCD; 128],
            q_m_g1: [0x11; G1_LEN],
            q_l_g1: [0x22; G1_LEN],
            q_r_g1: [0x33; G1_LEN],
            q_o_g1: [0x44; G1_LEN],
            q_c_g1: [0x55; G1_LEN],
            sigma_1_g1: [0x66; G1_LEN],
            sigma_2_g1: [0x77; G1_LEN],
            sigma_3_g1: [0x88; G1_LEN],
            k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
            k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
            k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
        }
    }

    #[test]
    fn vk_roundtrip() {
        let vk = sample_vk();
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), HyperPlonkVerifyingKey::SERIALIZED_LEN);
        // Session 18: 4 + 4 + 128 + 8·64 + 3·32 = 648 + 96 = 744 B.
        assert_eq!(bytes.len(), 744);
        let decoded = HyperPlonkVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
    }

    #[test]
    fn vk_rejects_wrong_length() {
        let short = vec![0u8; HyperPlonkVerifyingKey::SERIALIZED_LEN - 1];
        assert!(matches!(
            HyperPlonkVerifyingKey::from_bytes(&short),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }

    #[test]
    fn vk_commits_iter_yields_all_eight() {
        let vk = sample_vk();
        let commits: alloc::vec::Vec<_> = vk.commits_iter().collect();
        assert_eq!(commits.len(), HyperPlonkVerifyingKey::NUM_COMMITS);
        // Order must match canonical: q_m, q_l, q_r, q_o, q_c, σ_1, σ_2, σ_3.
        assert_eq!(commits[0], &vk.q_m_g1);
        assert_eq!(commits[1], &vk.q_l_g1);
        assert_eq!(commits[2], &vk.q_r_g1);
        assert_eq!(commits[3], &vk.q_o_g1);
        assert_eq!(commits[4], &vk.q_c_g1);
        assert_eq!(commits[5], &vk.sigma_1_g1);
        assert_eq!(commits[6], &vk.sigma_2_g1);
        assert_eq!(commits[7], &vk.sigma_3_g1);
    }

    #[test]
    fn final_evals_indices_distinct_and_complete() {
        use final_evals_index::*;
        let all = [
            A, B, C, Z, Q_M, Q_L, Q_R, Q_O, Q_C, SIGMA_1, SIGMA_2, SIGMA_3,
        ];
        // All 12 slots filled.
        assert_eq!(all.len(), FINAL_EVALS);
        // All distinct (no index collision).
        let mut seen = [false; 12];
        for i in all {
            assert!(i < 12, "index {i} out of range");
            assert!(!seen[i], "duplicate index {i}");
            seen[i] = true;
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 38 — proptest coverage for HyperPlonk canonical layout.
    //
    // Mirrors the session-37 Halo2 sweep: byte-layout invariants and
    // adversarial framing. Two crate-specific shapes that don't exist
    // in Halo2:
    //
    //   1. The dynamic dimension is `sumcheck_rounds` (≤
    //      MAX_SUMCHECK_ROUNDS = 28 for arkworks TWO_ADICITY) rather
    //      than four independent counters. This collapses the
    //      "oversized counter" property to a one-axis fuzz.
    //
    //   2. The VK has a fixed serialized length (744 B) — there is no
    //      variable-length tail. So the only adversarial framing
    //      property for the VK is "wrong length ⇒ reject", which we
    //      exhaust over the entire forbidden length space.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    prop_compose! {
        /// Random VK with bounded shape parameters, distinct commit
        /// fill bytes (so a swap between any two commitments would
        /// surface as inequality after round-trip), and a coset triple
        /// that satisfies the "all distinct" invariant.
        fn arb_vk()(
            n_public in 0u32..=8,
            num_variables in 0u32..=20,
            x2_byte in any::<u8>(),
            qm_byte in any::<u8>(),
            ql_byte in any::<u8>(),
            qr_byte in any::<u8>(),
            qo_byte in any::<u8>(),
            qc_byte in any::<u8>(),
            s1_byte in any::<u8>(),
            s2_byte in any::<u8>(),
            s3_byte in any::<u8>(),
        ) -> HyperPlonkVerifyingKey {
            HyperPlonkVerifyingKey {
                n_public,
                num_variables,
                x2_g2: [x2_byte; 128],
                q_m_g1: [qm_byte; G1_LEN],
                q_l_g1: [ql_byte; G1_LEN],
                q_r_g1: [qr_byte; G1_LEN],
                q_o_g1: [qo_byte; G1_LEN],
                q_c_g1: [qc_byte; G1_LEN],
                sigma_1_g1: [s1_byte; G1_LEN],
                sigma_2_g1: [s2_byte; G1_LEN],
                sigma_3_g1: [s3_byte; G1_LEN],
                k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
                k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
                k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
            }
        }
    }

    proptest! {
        /// Any in-range `sumcheck_rounds` produces a parseable proof,
        /// the round-poly iterator yields exactly that count, and each
        /// round poly slice has the canonical 96-byte length.
        #[test]
        fn proptest_proof_parses_any_in_range_rounds(
            rounds in 0u32..=sizes::MAX_SUMCHECK_ROUNDS,
        ) {
            let buf = proof_bytes_for_rounds(rounds);
            let p = HyperPlonkProof::from_bytes(&buf)
                .expect("in-range sumcheck_rounds parses");
            prop_assert_eq!(p.sumcheck_rounds, rounds);
            prop_assert_eq!(p.round_polys().count(), rounds as usize);
            prop_assert_eq!(p.sumcheck_polys.len(), rounds as usize * SUMCHECK_POLY_LEN);
            prop_assert_eq!(p.final_evals.len(), FINAL_EVALS * FR_LEN);
            prop_assert_eq!(p.kzg_opening.len(), G1_LEN);
            for rp in p.round_polys() {
                prop_assert_eq!(rp.len(), SUMCHECK_POLY_LEN);
            }
        }

        /// Any rounds count above the cap must be rejected before the
        /// `checked_mul` size computation runs.
        #[test]
        fn proptest_proof_rejects_rounds_over_max(
            overflow in 1u32..=64,
        ) {
            let bad = sizes::MAX_SUMCHECK_ROUNDS + overflow;
            let polys_len = (bad as usize).saturating_mul(SUMCHECK_POLY_LEN);
            let total = FIXED_HEADER_LEN
                .saturating_add(polys_len)
                .saturating_add(FINAL_EVALS * FR_LEN)
                .saturating_add(G1_LEN);
            // Cap allocation to avoid OOM on shrink (a u32::MAX rounds
            // count would propose a TB of memory on the heap).
            prop_assume!(total < 1 << 20);
            let mut buf = vec![0u8; total];
            buf[256..260].copy_from_slice(&bad.to_le_bytes());
            prop_assert!(matches!(
                HyperPlonkProof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// Trailing garbage of any non-zero length must be rejected.
        #[test]
        fn proptest_proof_rejects_trailing_garbage(
            rounds in 0u32..=sizes::MAX_SUMCHECK_ROUNDS,
            extra in 1usize..=64,
        ) {
            let mut buf = proof_bytes_for_rounds(rounds);
            buf.extend(core::iter::repeat_n(0xDE, extra));
            prop_assert!(matches!(
                HyperPlonkProof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// Truncation past the fixed header must be rejected. Fixed
        /// header carries the rounds counter; truncating the dynamic
        /// payload leaves the parser asking for bytes that aren't there.
        #[test]
        fn proptest_proof_rejects_truncation(
            rounds in 0u32..=sizes::MAX_SUMCHECK_ROUNDS,
            chop in 1usize..=128,
        ) {
            let mut buf = proof_bytes_for_rounds(rounds);
            let new_len = buf.len().saturating_sub(chop);
            // Truncation below MIN_PROOF_LEN already rejected by the
            // `bytes.len() < MIN_PROOF_LEN` guard — those cases are
            // covered by `proof_rejects_wrong_length` above.
            prop_assume!(new_len >= MIN_PROOF_LEN);
            prop_assume!(new_len < buf.len());
            buf.truncate(new_len);
            prop_assert!(matches!(
                HyperPlonkProof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// VK encode then decode is the identity for any well-formed VK.
        #[test]
        fn proptest_vk_roundtrip(vk in arb_vk()) {
            let bytes = vk.to_bytes();
            prop_assert_eq!(bytes.len(), HyperPlonkVerifyingKey::SERIALIZED_LEN);
            let decoded = HyperPlonkVerifyingKey::from_bytes(&bytes)
                .expect("well-formed VK round-trips");
            prop_assert_eq!(vk, decoded);
        }

        /// Any VK byte buffer whose length differs from
        /// `SERIALIZED_LEN` must be rejected (the VK has no variable-
        /// length tail, so any mismatch is fatal). Excludes the exact
        /// canonical length.
        #[test]
        fn proptest_vk_rejects_any_wrong_length(
            len in 0usize..=2 * HyperPlonkVerifyingKey::SERIALIZED_LEN,
        ) {
            prop_assume!(len != HyperPlonkVerifyingKey::SERIALIZED_LEN);
            let buf = vec![0u8; len];
            prop_assert!(matches!(
                HyperPlonkVerifyingKey::from_bytes(&buf),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }

        /// Trailing garbage on encoded VK bytes must be rejected.
        /// Catches "decoder ignored trailing bytes" failure modes.
        #[test]
        fn proptest_vk_rejects_trailing_garbage(
            vk in arb_vk(),
            extra in 1usize..=32,
        ) {
            let mut bytes = vk.to_bytes();
            bytes.extend(core::iter::repeat_n(0xFF, extra));
            prop_assert!(matches!(
                HyperPlonkVerifyingKey::from_bytes(&bytes),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }

        /// `commits_iter()` is a faithful enumeration: the order it
        /// yields matches direct field reads, and the count matches
        /// `NUM_COMMITS`. Catches reorderings that would silently break
        /// the Fiat-Shamir absorb sequence (which depends on this
        /// iteration order — see `derive_challenges`).
        #[test]
        fn proptest_vk_commits_iter_order_stable(vk in arb_vk()) {
            let collected: alloc::vec::Vec<&[u8; G1_LEN]> = vk.commits_iter().collect();
            prop_assert_eq!(collected.len(), HyperPlonkVerifyingKey::NUM_COMMITS);
            prop_assert_eq!(collected[0], &vk.q_m_g1);
            prop_assert_eq!(collected[1], &vk.q_l_g1);
            prop_assert_eq!(collected[2], &vk.q_r_g1);
            prop_assert_eq!(collected[3], &vk.q_o_g1);
            prop_assert_eq!(collected[4], &vk.q_c_g1);
            prop_assert_eq!(collected[5], &vk.sigma_1_g1);
            prop_assert_eq!(collected[6], &vk.sigma_2_g1);
            prop_assert_eq!(collected[7], &vk.sigma_3_g1);
        }
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 114 — HyperPlonk compressed proof + VK round-trip tests.
    //
    // HyperPlonk proof shape: 5 G1 + variable Fr region.
    //   Uncompressed (R=10): 1 668 B   Compressed: 1 508 B
    //   Saving (constant): 160 B (≈10 % at R=10, lower at higher R).
    //
    // HyperPlonk VK shape: 8 G1 + 1 G2 + Fr/u32 fields.
    //   Uncompressed: 744 B   Compressed: 424 B   Saving: 320 B (43 %).
    // ───────────────────────────────────────────────────────────────────
    mod compression {
        use super::*;
        use mosaic_core::syscall::host::HostBackend;
        use mosaic_zk_primitives::g1_consts::{g1_generator_bytes, g2_generator_bytes};

        /// Build a realistic proof: 5 G1 commits = generator, all Fr = 0,
        /// `sumcheck_rounds = 10`. Decompression must succeed because
        /// the generator is on-curve.
        fn realistic_proof(rounds: u32) -> Vec<u8> {
            use sizes::{FINAL_EVALS, FIXED_HEADER_LEN, FR_LEN, G1_LEN, SUMCHECK_POLY_LEN};
            let g1_gen = g1_generator_bytes();
            let polys_len = (rounds as usize) * SUMCHECK_POLY_LEN;
            let canonical_len =
                4 * G1_LEN + 4 + polys_len + FINAL_EVALS * FR_LEN + G1_LEN;
            let mut buf = Vec::with_capacity(canonical_len);
            // 4 leading G1 commits (a, b, c, z).
            for _ in 0..4 {
                buf.extend_from_slice(&g1_gen);
            }
            // sumcheck_rounds u32 LE.
            buf.extend_from_slice(&rounds.to_le_bytes());
            // sumcheck_polys + final_evals (all zero).
            buf.extend(core::iter::repeat(0u8).take(polys_len + FINAL_EVALS * FR_LEN));
            // Trailing kzg_opening G1.
            buf.extend_from_slice(&g1_gen);
            debug_assert_eq!(buf.len(), canonical_len);
            // Sanity: header offset matches the rounds fixed location.
            debug_assert_eq!(FIXED_HEADER_LEN, 4 * G1_LEN + 4);
            buf
        }

        fn realistic_vk_bytes() -> Vec<u8> {
            let g1_gen = g1_generator_bytes();
            let g2_gen = g2_generator_bytes();
            HyperPlonkVerifyingKey {
                n_public: 3,
                num_variables: 10,
                x2_g2: g2_gen,
                q_m_g1: g1_gen,
                q_l_g1: g1_gen,
                q_r_g1: g1_gen,
                q_o_g1: g1_gen,
                q_c_g1: g1_gen,
                sigma_1_g1: g1_gen,
                sigma_2_g1: g1_gen,
                sigma_3_g1: g1_gen,
                k_1: HyperPlonkVerifyingKey::fr_be_from_u64(1),
                k_2: HyperPlonkVerifyingKey::fr_be_from_u64(2),
                k_3: HyperPlonkVerifyingKey::fr_be_from_u64(3),
            }
            .to_bytes()
        }

        // ── Proof tests ─────────────────────────────────────────────

        #[test]
        fn proof_round_trip_at_r10() {
            let backend = HostBackend::new();
            let canonical = realistic_proof(10);
            let compressed =
                HyperPlonkProof::compress_from_canonical_bytes(&backend, &canonical)
                    .expect("compress");
            assert_eq!(
                compressed.len(),
                HyperPlonkProof::compressed_len_for_rounds(10).unwrap()
            );
            let decoded =
                HyperPlonkProof::decompress_to_canonical_bytes(&backend, &compressed)
                    .expect("decompress");
            assert_eq!(decoded, canonical);
        }

        #[test]
        fn proof_round_trip_at_r0_edge_case() {
            let backend = HostBackend::new();
            let canonical = realistic_proof(0);
            let compressed =
                HyperPlonkProof::compress_from_canonical_bytes(&backend, &canonical)
                    .expect("compress R=0");
            assert_eq!(compressed.len(), HyperPlonkProof::MIN_COMPRESSED_LEN);
            let decoded =
                HyperPlonkProof::decompress_to_canonical_bytes(&backend, &compressed)
                    .unwrap();
            assert_eq!(decoded, canonical);
        }

        #[test]
        fn proof_compressed_saves_160_bytes_per_proof() {
            let backend = HostBackend::new();
            for rounds in [0u32, 1, 10, sizes::MAX_SUMCHECK_ROUNDS] {
                let canonical = realistic_proof(rounds);
                let compressed = HyperPlonkProof::compress_from_canonical_bytes(
                    &backend, &canonical,
                )
                .unwrap();
                assert_eq!(
                    canonical.len() - compressed.len(),
                    5 * (sizes::G1_LEN - 32),
                    "expected 5·(G1_LEN - G1_C) = 160 bytes saved at rounds={rounds}",
                );
            }
        }

        #[test]
        fn proof_decompress_rejects_wrong_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; HyperPlonkProof::MIN_COMPRESSED_LEN - 1];
            let r = HyperPlonkProof::decompress_to_canonical_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
        }

        #[test]
        fn proof_decompress_rejects_oversized_rounds_counter() {
            let backend = HostBackend::new();
            let mut buf = vec![0u8; HyperPlonkProof::MIN_COMPRESSED_LEN];
            // Set sumcheck_rounds = MAX + 1 at fixed offset 128.
            let bad = sizes::MAX_SUMCHECK_ROUNDS + 1;
            buf[128..132].copy_from_slice(&bad.to_le_bytes());
            let r = HyperPlonkProof::decompress_to_canonical_bytes(&backend, &buf);
            assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
        }

        #[test]
        fn proof_compress_rejects_canonical_with_wrong_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; sizes::MIN_PROOF_LEN - 1];
            let r =
                HyperPlonkProof::compress_from_canonical_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
        }

        #[test]
        fn proof_decompress_rejects_off_curve_g1() {
            // Random non-zero bytes will (almost certainly) fail
            // sqrt-decompression at the syscall.
            let backend = HostBackend::new();
            let mut buf = vec![0u8; HyperPlonkProof::MIN_COMPRESSED_LEN];
            // First compressed G1 byte non-zero / non-curve.
            buf[0] = 0xAB;
            buf[1] = 0xCD;
            let r = HyperPlonkProof::decompress_to_canonical_bytes(&backend, &buf);
            // Either decompress fails (off-curve) or length check
            // catches the pad earlier — both are valid rejections.
            assert!(r.is_err());
        }

        // ── VK tests ────────────────────────────────────────────────

        #[test]
        fn vk_round_trip_with_real_generators() {
            let backend = HostBackend::new();
            let canonical = realistic_vk_bytes();
            assert_eq!(canonical.len(), HyperPlonkVerifyingKey::SERIALIZED_LEN);
            let compressed =
                HyperPlonkVerifyingKey::to_compressed_bytes(&backend, &canonical)
                    .expect("vk compress");
            assert_eq!(compressed.len(), HyperPlonkVerifyingKey::COMPRESSED_LEN);
            let decoded =
                HyperPlonkVerifyingKey::from_compressed_bytes(&backend, &compressed)
                    .expect("vk decompress");
            assert_eq!(decoded, canonical);
        }

        #[test]
        fn vk_compressed_saves_320_bytes() {
            let backend = HostBackend::new();
            let canonical = realistic_vk_bytes();
            let compressed =
                HyperPlonkVerifyingKey::to_compressed_bytes(&backend, &canonical)
                    .unwrap();
            assert_eq!(canonical.len(), 744);
            assert_eq!(compressed.len(), 424);
            assert_eq!(canonical.len() - compressed.len(), 320);
        }

        #[test]
        fn vk_compressed_preserves_non_curve_fields_byte_for_byte() {
            let backend = HostBackend::new();
            let canonical = realistic_vk_bytes();
            let compressed =
                HyperPlonkVerifyingKey::to_compressed_bytes(&backend, &canonical)
                    .unwrap();

            // n_public + num_variables (8 bytes pass-through).
            assert_eq!(compressed[0..8], canonical[0..8]);

            // 3 Fr coset constants at the tail (96 bytes pass-through).
            let canon_k_off = canonical.len() - 3 * sizes::FR_LEN;
            let comp_k_off = compressed.len() - 3 * sizes::FR_LEN;
            assert_eq!(
                compressed[comp_k_off..],
                canonical[canon_k_off..],
                "k_1, k_2, k_3 must pass through unchanged",
            );
        }

        #[test]
        fn vk_decompress_rejects_wrong_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; HyperPlonkVerifyingKey::COMPRESSED_LEN - 1];
            let r =
                HyperPlonkVerifyingKey::from_compressed_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
        }

        #[test]
        fn vk_compress_rejects_wrong_length() {
            let backend = HostBackend::new();
            let too_short = vec![0u8; HyperPlonkVerifyingKey::SERIALIZED_LEN - 1];
            let r =
                HyperPlonkVerifyingKey::to_compressed_bytes(&backend, &too_short);
            assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
        }

        #[test]
        fn vk_decompress_rejects_off_curve_g2() {
            // Non-zero non-curve bytes for G2 → syscall rejects.
            let backend = HostBackend::new();
            let mut buf = vec![0u8; HyperPlonkVerifyingKey::COMPRESSED_LEN];
            // Compressed G2 starts at offset 8; first byte non-zero.
            buf[8] = 0xAB;
            let r = HyperPlonkVerifyingKey::from_compressed_bytes(&backend, &buf);
            assert!(r.is_err());
        }

        /// Round-trip stability under bit-level perturbation of the
        /// pass-through region (n_public, num_variables, k_1..k_3).
        /// Exhausts the fact that compression touches only the curve
        /// fields; non-curve bytes survive unchanged.
        proptest! {
            #[test]
            fn proptest_vk_pass_through_bits_survive_compression(
                np in 0u32..=8,
                nv in 0u32..=20,
                k1_byte in any::<u8>(),
                k2_byte in any::<u8>(),
                k3_byte in any::<u8>(),
            ) {
                let backend = HostBackend::new();
                let g1_gen = g1_generator_bytes();
                let g2_gen = g2_generator_bytes();
                // Build a VK with curve fields = generator and Fr cosets
                // filled with the random bytes (still inside Fr range
                // because top byte is < 0x73 for any single-byte fill).
                let vk = HyperPlonkVerifyingKey {
                    n_public: np,
                    num_variables: nv,
                    x2_g2: g2_gen,
                    q_m_g1: g1_gen,
                    q_l_g1: g1_gen,
                    q_r_g1: g1_gen,
                    q_o_g1: g1_gen,
                    q_c_g1: g1_gen,
                    sigma_1_g1: g1_gen,
                    sigma_2_g1: g1_gen,
                    sigma_3_g1: g1_gen,
                    // Force top byte to 0 to stay strictly below the
                    // BN254 modulus (< 0x3064...). Lower 31 bytes use
                    // the random fill.
                    k_1: { let mut a = [0u8; 32]; a[1..].fill(k1_byte); a },
                    k_2: { let mut a = [0u8; 32]; a[1..].fill(k2_byte); a },
                    k_3: { let mut a = [0u8; 32]; a[1..].fill(k3_byte); a },
                };
                let canonical = vk.to_bytes();
                let compressed =
                    HyperPlonkVerifyingKey::to_compressed_bytes(&backend, &canonical)
                        .unwrap();
                let decoded =
                    HyperPlonkVerifyingKey::from_compressed_bytes(&backend, &compressed)
                        .unwrap();
                prop_assert_eq!(decoded, canonical);
            }
        }
    }
}
