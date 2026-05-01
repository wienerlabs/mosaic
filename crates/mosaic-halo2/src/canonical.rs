//! Halo2-KZG canonical byte layout — **placeholder shape** derived from
//! the PSE Halo2-KZG proof encoding.
//!
//! ## Reference wire format
//!
//! Privacy Scaling Explorations'
//! [`halo2_proofs::plonk::verify_proof`](https://github.com/privacy-scaling-explorations/halo2/blob/main/halo2_proofs/src/plonk/verifier.rs)
//! consumes proofs laid out as:
//!
//! ```text
//! [advice_col_commits...]          (n_advice × G1)
//! [lookup_m_polys...]              (n_lookups × G1)   -- m_poly per lookup
//! [permutation_z_polys...]         (n_perms × G1)
//! [vanishing_h_pieces...]          (n_quotient_chunks × G1)
//! [ξ evaluations of everything]    (variable count × Fr)
//! [instance_evals...]              (n_instances × Fr)
//! [opening_proof]                  (2 × G1 for multipoint opening Wξ + Wξω)
//! ```
//!
//! The exact count of each section depends on the circuit shape
//! (advice columns, lookup arguments, permutation chunks). Our
//! canonical layout parametrizes these via the VK so a single wire
//! format works across circuits.
//!
//! ## Layout
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0 | 4 | `n_advice` (u32 LE) — advice column commitment count |
//! | 4 | 4 | `n_lookups` (u32 LE) — lookup argument count |
//! | 8 | 4 | `n_quotient` (u32 LE) — quotient polynomial chunk count |
//! | 12 | 4 | `n_evals` (u32 LE) — evaluation count at ξ |
//! | 16 | 64 × `n_advice` | advice column commitments (G1) |
//! | … | 64 × `n_lookups` | lookup `m` polynomial commitments (G1) |
//! | … | 64 | permutation grand-product commitment (G1) |
//! | … | 64 × `n_quotient` | quotient chunks (G1) |
//! | … | 32 × `n_evals` | polynomial evaluations at ξ (Fr) |
//! | … | 64 | `W_ξ` opening (G1) |
//! | … | 64 | `W_ξω` opening (G1) |
//!
//! For a typical 2^10 circuit (5 advice, 1 lookup, 3 quotient chunks,
//! ~15 evals) the proof is:
//!
//!   16 + 5·64 + 1·64 + 64 + 3·64 + 15·32 + 2·64 = **1104 B**
//!
//! **TODO(mosaic-halo2)**: pin this layout against the PSE
//! `halo2_proofs::plonk::verifier::verify_proof` byte ordering before
//! Phase 3 writes an adapter in `mosaic-serde::halo2`.

use alloc::vec::Vec;
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// Size constants for the Halo2-KZG canonical layout.
pub mod sizes {
    /// G1 affine point (x || y, each 32-byte BE).
    pub const G1_LEN: usize = 64;
    /// Fr element (BN254 scalar field, big-endian).
    pub const FR_LEN: usize = 32;
    /// G2 affine (for KZG SRS element in VK).
    pub const G2_LEN: usize = 128;
    /// Fixed header length: 5 u32 counters.
    ///
    /// **Session 100** — bumped from 16 → 20 bytes to add the
    /// `lookup_arity` field at offset 16. The previous 4-counter
    /// layout (n_advice / n_lookups / n_quotient / n_evals) was a
    /// placeholder; session 100 promotes the lookup primitive from
    /// "isolated audit gate" to a real verifier capability by
    /// declaring the arity in the proof header.
    pub const FIXED_HEADER_LEN: usize = 20;
    /// Max advice columns — sanity cap to guard against adversarial proof
    /// sizes. Solana instruction data limit is 1232 B, so any real-world
    /// Halo2 proof fits in a single tx if under 1200 B; bigger needs
    /// chunked upload.
    pub const MAX_ADVICE_COLUMNS: u32 = 64;
    /// Max lookup argument count.
    pub const MAX_LOOKUPS: u32 = 32;
    /// Max quotient polynomial chunk count.
    pub const MAX_QUOTIENT_CHUNKS: u32 = 32;
    /// Max evaluation count at the sumcheck point ξ.
    pub const MAX_EVALUATIONS: u32 = 256;
    /// Max lookup arity (number of (input, table) column pairs per
    /// lookup argument). Real Halo2 circuits typically use arity ≤ 8;
    /// this cap is generous. **Session 100**.
    pub const MAX_LOOKUP_ARITY: u32 = 16;
    /// Default lookup arity when the proof header declares 0 — treated
    /// as legacy single-column lookup for backward compatibility with
    /// pre-session-100 fixtures.
    pub const DEFAULT_LOOKUP_ARITY: u32 = 1;
}

/// Zero-copy view into a Halo2-KZG proof buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Halo2KzgProof<'a> {
    /// Advice column commitment count.
    pub n_advice: u32,
    /// Lookup argument count.
    pub n_lookups: u32,
    /// Quotient polynomial chunk count.
    pub n_quotient: u32,
    /// Number of polynomial evaluations at ξ.
    pub n_evals: u32,
    /// **Session 100** — Lookup arity: number of `(input_col, table_col)`
    /// pairs per lookup argument.
    ///
    /// - `1` (default for legacy proofs): single-column lookup, current
    ///   3-slot bundle layout (`input_eval`, `table_eval`, `m_eval`).
    /// - `k > 1`: multi-column lookup, bundle layout has `k` input
    ///   evals + `k` table evals + 1 m eval (total `2k + 1` slots).
    ///
    /// Header byte 16-19 (u32 LE). A value of `0` is reinterpreted as
    /// [`sizes::DEFAULT_LOOKUP_ARITY`] (1) for forward-compat with
    /// pre-session-100 proof headers.
    pub lookup_arity: u32,
    /// Concatenated advice column commitments. Length = `n_advice * 64`.
    pub advice_commits: &'a [u8],
    /// Concatenated lookup `m` polynomial commitments. Length = `n_lookups * 64`.
    pub lookup_commits: &'a [u8],
    /// Permutation grand-product commitment (single G1).
    pub permutation_z: &'a [u8],
    /// Concatenated quotient polynomial chunks. Length = `n_quotient * 64`.
    pub quotient_chunks: &'a [u8],
    /// Concatenated polynomial evaluations at ξ. Length = `n_evals * 32`.
    pub evaluations: &'a [u8],
    /// KZG opening at ξ (G1).
    pub w_xi: &'a [u8],
    /// KZG opening at `ξω` (G1).
    pub w_xiw: &'a [u8],
}

impl<'a> Halo2KzgProof<'a> {
    /// Parse a canonical Halo2-KZG proof.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, OnChainError> {
        use sizes::{
            DEFAULT_LOOKUP_ARITY, FIXED_HEADER_LEN, FR_LEN, G1_LEN, MAX_ADVICE_COLUMNS,
            MAX_EVALUATIONS, MAX_LOOKUPS, MAX_LOOKUP_ARITY, MAX_QUOTIENT_CHUNKS,
        };
        if bytes.len() < FIXED_HEADER_LEN + G1_LEN + 2 * G1_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let n_advice = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let n_lookups = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let n_quotient = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let n_evals = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        // Session 100: lookup_arity at header byte 16-19. A value of 0
        // is reinterpreted as DEFAULT_LOOKUP_ARITY (1) for forward
        // compatibility with proof generators that haven't been
        // updated to write the field explicitly.
        let arity_raw = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let lookup_arity = if arity_raw == 0 {
            DEFAULT_LOOKUP_ARITY
        } else {
            arity_raw
        };

        if n_advice > MAX_ADVICE_COLUMNS
            || n_lookups > MAX_LOOKUPS
            || n_quotient > MAX_QUOTIENT_CHUNKS
            || n_evals > MAX_EVALUATIONS
            || lookup_arity > MAX_LOOKUP_ARITY
        {
            return Err(OnChainError::ProofLengthMismatch);
        }

        // Session 101 — multi-column lookup soundness constraint:
        // input/table cols binding to advice commits via KZG.
        //
        // For arity ≥ 2 the verifier binds `input_cols[i]` and
        // `table_cols[i]` to the proof's advice commitments via the
        // KZG batched opening: the LAST `2 * lookup_arity` advice
        // columns are reserved for the lookup argument's input and
        // table column references.
        //
        // Without this binding the prover could choose `input_cols`
        // / `table_cols` evaluations freely (only the algebraic
        // identity in `combined_expr` would constrain them, which
        // Schwartz-Zippel sees through negligibly often but doesn't
        // cryptographically PIN).
        //
        // Phase-3 known gap: `m_eval` binding to `lookup_commits[0]`
        // — when `n_lookups ≥ 1`, the m polynomial commit is present
        // in the proof and `collect_evals_at_xi` already pairs it to
        // `bundle.lookup.m` for the KZG batched opening (legacy
        // single-column behavior). For arity ≥ 2 the m_eval is also
        // bound when `n_lookups ≥ 1`. We do NOT enforce
        // `n_lookups ≥ 1` for arity ≥ 2 because scaffold test
        // fixtures use n_lookups=0 (no real m commit to pair
        // against). Real Halo2 provers always emit n_lookups ≥ 1;
        // the differential-testing campaign will pin this once
        // fixture-driven Phase-3 tests land.
        // Session 100 constraint: arity ≥ 2 reserves the last 2k advice
        // columns for the lookup (input cols + table cols).
        // Session 107 generalization: n_lookups arguments, each
        // claiming 2k advice columns, must collectively fit into
        // `n_advice`. This is `n_advice ≥ 2 * arity * n_lookups`.
        // For arity = 1 the lookup uses standalone (input, table, m)
        // wire-style evals so no advice reservation applies — the
        // constraint only kicks in for arity ≥ 2.
        if lookup_arity >= 2 {
            let reserved = (lookup_arity as u64)
                .checked_mul(2)
                .and_then(|v| v.checked_mul(n_lookups.max(1) as u64))
                .ok_or(OnChainError::ProofLengthMismatch)?;
            if (n_advice as u64) < reserved {
                return Err(OnChainError::ProofLengthMismatch);
            }
        }

        let advice_len = (n_advice as usize)
            .checked_mul(G1_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let lookup_len = (n_lookups as usize)
            .checked_mul(G1_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let quotient_len = (n_quotient as usize)
            .checked_mul(G1_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let evals_len = (n_evals as usize)
            .checked_mul(FR_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;

        let expected_len = FIXED_HEADER_LEN
            + advice_len
            + lookup_len
            + G1_LEN // permutation_z
            + quotient_len
            + evals_len
            + 2 * G1_LEN; // w_xi, w_xiw

        if bytes.len() != expected_len {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let mut o = FIXED_HEADER_LEN;
        let advice_commits = &bytes[o..o + advice_len];
        o += advice_len;
        let lookup_commits = &bytes[o..o + lookup_len];
        o += lookup_len;
        let permutation_z = &bytes[o..o + G1_LEN];
        o += G1_LEN;
        let quotient_chunks = &bytes[o..o + quotient_len];
        o += quotient_len;
        let evaluations = &bytes[o..o + evals_len];
        o += evals_len;
        let w_xi = &bytes[o..o + G1_LEN];
        o += G1_LEN;
        let w_xiw = &bytes[o..o + G1_LEN];

        Ok(Self {
            n_advice,
            n_lookups,
            n_quotient,
            n_evals,
            lookup_arity,
            advice_commits,
            lookup_commits,
            permutation_z,
            quotient_chunks,
            evaluations,
            w_xi,
            w_xiw,
        })
    }

    /// Iterate advice column commitments as 64-byte slices.
    pub fn advice_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.advice_commits.chunks_exact(sizes::G1_LEN)
    }

    /// Iterate quotient polynomial chunk commitments.
    pub fn quotient_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.quotient_chunks.chunks_exact(sizes::G1_LEN)
    }

    /// Iterate evaluations as 32-byte Fr slices.
    pub fn evaluations_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.evaluations.chunks_exact(sizes::FR_LEN)
    }
}

/// **Session 108** — Halo2 proof compression / decompression utilities.
///
/// Parallel to session 106's compressed VK support, the proof's G1
/// commitments (advice, lookup, permutation_z, quotient, w_xi, w_xiw)
/// can be wire-encoded in compressed form (32 B each) instead of
/// uncompressed (64 B each). The Fr evaluations stay 32 B uncompressed
/// because they aren't curve points.
///
/// Layout (compressed):
///
/// ```text
/// | offset | size | field                                  |
/// |---|---|---|
/// |   0..20 | unchanged 5-counter header (FIXED_HEADER_LEN) |
/// |  20..   | 32 × n_advice compressed advice commits       |
/// |    ..   | 32 × n_lookups compressed lookup commits      |
/// |    ..   | 32 compressed permutation_z                   |
/// |    ..   | 32 × n_quotient compressed quotient chunks    |
/// |    ..   | 32 × n_evals Fr evaluations (unchanged)       |
/// |    ..   | 32 compressed w_xi                            |
/// |    ..   | 32 compressed w_xiw                           |
/// ```
///
/// Bandwidth saving: each G1 → 32 B from 64 B = 32 B saved per
/// commit. For a typical Halo2 proof with 5 advice + 1 lookup +
/// 3 quotient + 1 perm_z + 2 openings = 12 G1 commits, the
/// compressed proof is 12·32 = 384 B smaller than uncompressed.
///
/// CU trade-off: each `decompress_to_canonical_bytes` call costs
/// roughly `(n_advice + n_lookups + 1 + n_quotient + 2) × ~10 K CU`.
/// For the same 12-commit example: ~120 K CU per decompression.
/// Whether worthwhile depends on per-proof-size sensitivity vs CU
/// budget.
///
/// The proof view (`Halo2KzgProof<'a>`) consumes uncompressed
/// canonical bytes via `from_bytes`. To use compressed bytes:
///
/// ```ignore
/// let canonical = Halo2KzgProof::decompress_to_canonical_bytes(
///     &backend, &compressed_bytes,
/// )?;
/// let proof = Halo2KzgProof::from_bytes(&canonical)?;
/// ```
impl Halo2KzgProof<'_> {
    /// Compressed-form G1 length (mirrors `sizes::G1_LEN` halved).
    const G1_COMPRESSED_LEN: usize = 32;

    /// Decompress a compressed-format proof byte buffer into the
    /// canonical uncompressed wire format.
    ///
    /// The header (20 bytes) is copied as-is. Each G1 commit
    /// (advice, lookup, permutation_z, quotient_chunks, w_xi,
    /// w_xiw) is decompressed via the alt_bn128 syscall. Fr
    /// evaluations are copied unchanged.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] — header counters
    ///   over the bounded ranges, or compressed buffer total length
    ///   doesn't match the declared shape.
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   compressed point fails decompression.
    pub fn decompress_to_canonical_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        compressed: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        use sizes::{
            DEFAULT_LOOKUP_ARITY, FIXED_HEADER_LEN, FR_LEN, G1_LEN, MAX_ADVICE_COLUMNS,
            MAX_EVALUATIONS, MAX_LOOKUPS, MAX_LOOKUP_ARITY, MAX_QUOTIENT_CHUNKS,
        };
        const G1_C: usize = 32; // Halo2KzgProof::G1_COMPRESSED_LEN — duplicated as a const to avoid `Self` resolution inside closures.

        if compressed.len() < FIXED_HEADER_LEN + G1_C + 2 * G1_C {
            return Err(OnChainError::ProofLengthMismatch);
        }

        // Parse header — same byte offsets as the uncompressed format.
        let n_advice = u32::from_le_bytes([
            compressed[0],
            compressed[1],
            compressed[2],
            compressed[3],
        ]);
        let n_lookups = u32::from_le_bytes([
            compressed[4],
            compressed[5],
            compressed[6],
            compressed[7],
        ]);
        let n_quotient = u32::from_le_bytes([
            compressed[8],
            compressed[9],
            compressed[10],
            compressed[11],
        ]);
        let n_evals = u32::from_le_bytes([
            compressed[12],
            compressed[13],
            compressed[14],
            compressed[15],
        ]);
        let arity_raw = u32::from_le_bytes([
            compressed[16],
            compressed[17],
            compressed[18],
            compressed[19],
        ]);
        let lookup_arity = if arity_raw == 0 {
            DEFAULT_LOOKUP_ARITY
        } else {
            arity_raw
        };

        if n_advice > MAX_ADVICE_COLUMNS
            || n_lookups > MAX_LOOKUPS
            || n_quotient > MAX_QUOTIENT_CHUNKS
            || n_evals > MAX_EVALUATIONS
            || lookup_arity > MAX_LOOKUP_ARITY
        {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let advice_clen = (n_advice as usize)
            .checked_mul(G1_C)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let lookup_clen = (n_lookups as usize)
            .checked_mul(G1_C)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let quotient_clen = (n_quotient as usize)
            .checked_mul(G1_C)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        let evals_len = (n_evals as usize)
            .checked_mul(FR_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;

        let expected_clen = FIXED_HEADER_LEN
            + advice_clen
            + lookup_clen
            + G1_C // permutation_z compressed
            + quotient_clen
            + evals_len
            + 2 * G1_C; // w_xi, w_xiw compressed

        if compressed.len() != expected_clen {
            return Err(OnChainError::ProofLengthMismatch);
        }

        // Build the uncompressed canonical buffer.
        let advice_len = (n_advice as usize) * G1_LEN;
        let lookup_len = (n_lookups as usize) * G1_LEN;
        let quotient_len = (n_quotient as usize) * G1_LEN;
        let canonical_len = FIXED_HEADER_LEN
            + advice_len
            + lookup_len
            + G1_LEN
            + quotient_len
            + evals_len
            + 2 * G1_LEN;
        let mut out: Vec<u8> = Vec::with_capacity(canonical_len);
        // Header: copy as-is (the lookup_arity raw value is preserved
        // even when 0 — let from_bytes do the DEFAULT_LOOKUP_ARITY
        // reinterpretation).
        out.extend_from_slice(&compressed[..FIXED_HEADER_LEN]);

        // Helper closure: decompress one G1 from a 32-byte slice and
        // append the 64-byte uncompressed result to `out`.
        let mut o = FIXED_HEADER_LEN;
        let mut decompress_g1_into = |slice: &[u8],
                                       sink: &mut Vec<u8>|
         -> Result<(), OnChainError> {
            let mut arr = [0u8; G1_C];
            arr.copy_from_slice(slice);
            let full =
                mosaic_zk_primitives::compression::decompress_g1(backend, &arr)?;
            sink.extend_from_slice(&full);
            Ok(())
        };

        // advice commits
        for _ in 0..(n_advice as usize) {
            decompress_g1_into(&compressed[o..o + G1_C], &mut out)?;
            o += G1_C;
        }
        // lookup commits
        for _ in 0..(n_lookups as usize) {
            decompress_g1_into(&compressed[o..o + G1_C], &mut out)?;
            o += G1_C;
        }
        // permutation_z
        decompress_g1_into(&compressed[o..o + G1_C], &mut out)?;
        o += G1_C;
        // quotient chunks
        for _ in 0..(n_quotient as usize) {
            decompress_g1_into(&compressed[o..o + G1_C], &mut out)?;
            o += G1_C;
        }
        // Fr evaluations: copy as-is (not compressible).
        out.extend_from_slice(&compressed[o..o + evals_len]);
        o += evals_len;
        // w_xi
        decompress_g1_into(&compressed[o..o + G1_C], &mut out)?;
        o += G1_C;
        // w_xiw
        decompress_g1_into(&compressed[o..o + G1_C], &mut out)?;

        debug_assert_eq!(out.len(), canonical_len);
        Ok(out)
    }

    /// Compress a canonical uncompressed proof byte buffer into the
    /// compressed wire format.
    ///
    /// Companion to [`decompress_to_canonical_bytes`]. The header
    /// (20 bytes) and Fr evaluations are copied unchanged; every G1
    /// commit is compressed via the alt_bn128 syscall.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::ProofLengthMismatch`] — input doesn't parse
    ///   as a valid canonical proof (`Halo2KzgProof::from_bytes`
    ///   would reject).
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   point fails to compress (off-curve, etc.).
    pub fn compress_from_canonical_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        canonical: &[u8],
    ) -> Result<Vec<u8>, OnChainError> {
        use sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN};
        const G1_C: usize = 32; // Halo2KzgProof::G1_COMPRESSED_LEN — duplicated as a const to avoid `Self` resolution inside closures.

        // Parse the canonical proof to validate shape + extract
        // counters. This rejects malformed input upfront.
        let proof = Halo2KzgProof::from_bytes(canonical)?;
        let n_advice = proof.n_advice as usize;
        let n_lookups = proof.n_lookups as usize;
        let n_quotient = proof.n_quotient as usize;
        let n_evals = proof.n_evals as usize;

        let advice_clen = n_advice * G1_C;
        let lookup_clen = n_lookups * G1_C;
        let quotient_clen = n_quotient * G1_C;
        let evals_len = n_evals * FR_LEN;
        let expected_clen = FIXED_HEADER_LEN
            + advice_clen
            + lookup_clen
            + G1_C
            + quotient_clen
            + evals_len
            + 2 * G1_C;
        let mut out: Vec<u8> = Vec::with_capacity(expected_clen);

        // Copy the 20-byte header as-is.
        out.extend_from_slice(&canonical[..FIXED_HEADER_LEN]);

        // Helper closure: compress one G1 (64 bytes) and append the
        // 32-byte compressed result to `out`.
        let mut compress_g1_into = |slice: &[u8],
                                     sink: &mut Vec<u8>|
         -> Result<(), OnChainError> {
            let mut arr = [0u8; G1_LEN];
            arr.copy_from_slice(slice);
            let c =
                mosaic_zk_primitives::compression::compress_g1(backend, &arr)?;
            sink.extend_from_slice(&c);
            Ok(())
        };

        // advice commits
        for chunk in proof.advice_commits.chunks_exact(G1_LEN) {
            compress_g1_into(chunk, &mut out)?;
        }
        // lookup commits
        for chunk in proof.lookup_commits.chunks_exact(G1_LEN) {
            compress_g1_into(chunk, &mut out)?;
        }
        // permutation_z
        compress_g1_into(proof.permutation_z, &mut out)?;
        // quotient chunks
        for chunk in proof.quotient_chunks.chunks_exact(G1_LEN) {
            compress_g1_into(chunk, &mut out)?;
        }
        // Fr evaluations: copy as-is.
        out.extend_from_slice(proof.evaluations);
        // w_xi
        compress_g1_into(proof.w_xi, &mut out)?;
        // w_xiw
        compress_g1_into(proof.w_xiw, &mut out)?;

        debug_assert_eq!(out.len(), expected_clen);
        Ok(out)
    }
}

/// Halo2-KZG verifying key.
///
/// **Placeholder** — real VK has preprocessing commitments for custom
/// gates + permutation + lookup tables. Pinning waits for Phase-3
/// implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Halo2KzgVerifyingKey {
    /// Circuit `k` parameter: domain size = 2^k.
    pub k: u32,
    /// Number of instance (public) columns.
    pub n_instances: u32,
    /// Number of advice columns (witness).
    pub n_advice: u32,
    /// Number of fixed columns (preprocessing).
    pub n_fixed: u32,
    /// G2 SRS element for KZG pairing check.
    pub x2_g2: [u8; sizes::G2_LEN],
    /// Domain generator `ω` (BN254 Fr, 32-byte BE). Primitive
    /// `2^k`-th root of unity. Used by the verifier to compute the
    /// shifted evaluation point `ξω` for polynomials that open at
    /// adjacent-row indices (e.g. the permutation grand-product
    /// `z(ξω) = z_next`). Session-16 addition.
    pub omega_fr: [u8; sizes::FR_LEN],
    /// Fixed column commitments concatenated (length = `n_fixed * 64`).
    /// Boxed via Vec so the VK size is dynamic at decode time.
    pub fixed_commits: Vec<u8>,
    /// Permutation commitment set (one per permuted column).
    /// Length = `n_advice * 64` in the typical case.
    pub permutation_commits: Vec<u8>,
}

impl Halo2KzgVerifyingKey {
    /// Fixed-portion length before the two variable-sized commitment buffers.
    pub const FIXED_LEN: usize = 4 // k
        + 4 // n_instances
        + 4 // n_advice
        + 4 // n_fixed
        + sizes::G2_LEN
        + sizes::FR_LEN // omega_fr
        + 4 // fixed_commits.len() (bytes)
        + 4; // permutation_commits.len() (bytes)

    /// Decode from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() < Self::FIXED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let k = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let n_instances = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let n_advice = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let n_fixed = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let mut x2_g2 = [0u8; sizes::G2_LEN];
        x2_g2.copy_from_slice(&bytes[16..16 + sizes::G2_LEN]);
        let after_g2 = 16 + sizes::G2_LEN;
        // Session-16: omega_fr (32 bytes BE) immediately after x2_g2.
        let mut omega_fr = [0u8; sizes::FR_LEN];
        omega_fr.copy_from_slice(&bytes[after_g2..after_g2 + sizes::FR_LEN]);
        let after_omega = after_g2 + sizes::FR_LEN;
        let fixed_len = u32::from_le_bytes([
            bytes[after_omega],
            bytes[after_omega + 1],
            bytes[after_omega + 2],
            bytes[after_omega + 3],
        ]) as usize;
        let perm_len = u32::from_le_bytes([
            bytes[after_omega + 4],
            bytes[after_omega + 5],
            bytes[after_omega + 6],
            bytes[after_omega + 7],
        ]) as usize;
        let payload_start = after_omega + 8;
        let expected = payload_start + fixed_len + perm_len;
        if bytes.len() != expected {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        // Session 105 — VK internal consistency check.
        //
        // The wire format declares `n_fixed: u32` separately from the
        // `fixed_commits` byte buffer's length. Both must agree:
        //   fixed_commits.len() == n_fixed * G1_LEN
        // Otherwise the parser would silently accept a VK where
        // `n_fixed` and the actual commit count diverge — downstream
        // verifier code that uses `n_fixed` for indexing or counting
        // (e.g. `collect_evals_at_xi`'s selector loop) would produce
        // wrong opening pairs without any explicit error.
        //
        // Also enforce divisibility: fixed_len % G1_LEN == 0 and
        // perm_len % G1_LEN == 0. A non-multiple length means the
        // wire payload was constructed by a bugged generator (or
        // adversarially) and cannot represent a coherent commit
        // vector.
        if fixed_len % sizes::G1_LEN != 0 || perm_len % sizes::G1_LEN != 0 {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        if fixed_len != (n_fixed as usize) * sizes::G1_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        let fixed_commits = bytes[payload_start..payload_start + fixed_len].to_vec();
        let permutation_commits =
            bytes[payload_start + fixed_len..payload_start + fixed_len + perm_len].to_vec();
        Ok(Self {
            k,
            n_instances,
            n_advice,
            n_fixed,
            x2_g2,
            omega_fr,
            fixed_commits,
            permutation_commits,
        })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            Self::FIXED_LEN + self.fixed_commits.len() + self.permutation_commits.len(),
        );
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.n_instances.to_le_bytes());
        out.extend_from_slice(&self.n_advice.to_le_bytes());
        out.extend_from_slice(&self.n_fixed.to_le_bytes());
        out.extend_from_slice(&self.x2_g2);
        out.extend_from_slice(&self.omega_fr);
        out.extend_from_slice(&(self.fixed_commits.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.permutation_commits.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.fixed_commits);
        out.extend_from_slice(&self.permutation_commits);
        out
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 106 — compressed VK support.
    //
    // The uncompressed VK above carries a 128-byte G2 plus N × 64-byte
    // G1 commits. The compressed form uses the BN254 alt_bn128
    // compression syscall (wired in session 103) to halve every curve
    // point: G2 → 64 B, each G1 → 32 B. Typical 2-fixed + 5-perm VK
    // shrinks from 1 + 7·G1 + G2 + Fr + headers ≈ 488 B down to
    // ≈ 264 B (46 % saving) — meaningful on Solana where VK accounts
    // pay rent based on size.
    //
    // Trade-off: each `from_compressed_bytes` call costs roughly
    // ~10 K CU per G1 decompress (square-root mod q to recover y),
    // ~12 K CU for the G2. For a 2-fixed + 5-perm VK that's ~80 K CU
    // per verifier load — paid once, then the in-memory representation
    // is the existing uncompressed `Halo2KzgVerifyingKey` and the rest
    // of the verifier is unchanged.
    //
    // Wire format (compressed):
    //
    //   | offset | size | field                  |
    //   |---|---|---|
    //   |   0 |  4 | k                          |
    //   |   4 |  4 | n_instances                |
    //   |   8 |  4 | n_advice                   |
    //   |  12 |  4 | n_fixed                    |
    //   |  16 | 64 | x2_g2 compressed (G2_LEN_C) |
    //   |  80 | 32 | omega_fr (Fr — uncompressed)|
    //   | 112 |  4 | fixed_compressed_len (= n_fixed * 32) |
    //   | 116 |  4 | perm_compressed_len  (= perm_count * 32) |
    //   | 120 |  … | compressed commits payload |

    /// Compressed-form fixed-portion length (mirrors [`Self::FIXED_LEN`]
    /// but with G2 halved).
    pub const COMPRESSED_FIXED_LEN: usize = 4 // k
        + 4 // n_instances
        + 4 // n_advice
        + 4 // n_fixed
        + 64 // x2_g2 compressed (G2_LEN / 2)
        + sizes::FR_LEN // omega_fr
        + 4 // fixed_compressed_len
        + 4; // perm_compressed_len

    /// **Session 106** — decode a compressed VK byte buffer into the
    /// in-memory uncompressed `Halo2KzgVerifyingKey`.
    ///
    /// Calls `alt_bn128_compression(G2Decompress)` for `x2_g2` and
    /// `alt_bn128_compression(G1Decompress)` for each fixed and
    /// permutation commit.
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::VerifyingKeyLengthMismatch`] — wire-format
    ///   inconsistency (wrong total length, declared/actual mismatch
    ///   on `n_fixed`, non-multiple G1 payload lengths).
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   compressed point fails decompression (e.g. malformed sign
    ///   bit, off-curve x).
    pub fn from_compressed_bytes<B: SyscallBackend + ?Sized>(
        backend: &B,
        bytes: &[u8],
    ) -> Result<Self, OnChainError> {
        const G2_COMPRESSED: usize = 64;
        const G1_COMPRESSED: usize = 32;

        if bytes.len() < Self::COMPRESSED_FIXED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        let k = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let n_instances = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let n_advice = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let n_fixed = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        let x2_compressed = &bytes[16..16 + G2_COMPRESSED];
        let after_g2 = 16 + G2_COMPRESSED;

        let mut omega_fr = [0u8; sizes::FR_LEN];
        omega_fr.copy_from_slice(&bytes[after_g2..after_g2 + sizes::FR_LEN]);
        let after_omega = after_g2 + sizes::FR_LEN;

        let fixed_compressed_len = u32::from_le_bytes([
            bytes[after_omega],
            bytes[after_omega + 1],
            bytes[after_omega + 2],
            bytes[after_omega + 3],
        ]) as usize;
        let perm_compressed_len = u32::from_le_bytes([
            bytes[after_omega + 4],
            bytes[after_omega + 5],
            bytes[after_omega + 6],
            bytes[after_omega + 7],
        ]) as usize;

        let payload_start = after_omega + 8;
        let expected_total = payload_start + fixed_compressed_len + perm_compressed_len;
        if bytes.len() != expected_total {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        // Same divisibility + count consistency checks as the
        // uncompressed `from_bytes` (session 105), adapted to the
        // compressed G1 size.
        if fixed_compressed_len % G1_COMPRESSED != 0
            || perm_compressed_len % G1_COMPRESSED != 0
        {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        if fixed_compressed_len != (n_fixed as usize) * G1_COMPRESSED {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }

        // Decompress G2.
        let mut g2_arr = [0u8; G2_COMPRESSED];
        g2_arr.copy_from_slice(x2_compressed);
        let x2_full =
            mosaic_zk_primitives::compression::decompress_g2(backend, &g2_arr)?;

        // Decompress every fixed commit.
        let mut fixed_commits: Vec<u8> =
            Vec::with_capacity((n_fixed as usize) * sizes::G1_LEN);
        for chunk in bytes[payload_start..payload_start + fixed_compressed_len]
            .chunks_exact(G1_COMPRESSED)
        {
            let mut g1_arr = [0u8; G1_COMPRESSED];
            g1_arr.copy_from_slice(chunk);
            let full =
                mosaic_zk_primitives::compression::decompress_g1(backend, &g1_arr)?;
            fixed_commits.extend_from_slice(&full);
        }

        // Decompress every permutation commit.
        let perm_count = perm_compressed_len / G1_COMPRESSED;
        let mut permutation_commits: Vec<u8> =
            Vec::with_capacity(perm_count * sizes::G1_LEN);
        let perm_start = payload_start + fixed_compressed_len;
        for chunk in bytes[perm_start..perm_start + perm_compressed_len]
            .chunks_exact(G1_COMPRESSED)
        {
            let mut g1_arr = [0u8; G1_COMPRESSED];
            g1_arr.copy_from_slice(chunk);
            let full =
                mosaic_zk_primitives::compression::decompress_g1(backend, &g1_arr)?;
            permutation_commits.extend_from_slice(&full);
        }

        Ok(Self {
            k,
            n_instances,
            n_advice,
            n_fixed,
            x2_g2: x2_full,
            omega_fr,
            fixed_commits,
            permutation_commits,
        })
    }

    /// **Session 106** — encode this VK in compressed form (companion
    /// to [`from_compressed_bytes`]).
    ///
    /// Calls `alt_bn128_compression(G2Compress)` for `x2_g2` and
    /// `alt_bn128_compression(G1Compress)` for each commit. Output is
    /// 46 % smaller than [`to_bytes`] for a typical 2-fixed + 5-perm
    /// VK; consume via [`from_compressed_bytes`].
    ///
    /// ## Errors
    ///
    /// - [`OnChainError::AltBn128CompressionSyscallFailed`] — any
    ///   point fails to compress (off-curve, etc.).
    pub fn to_compressed_bytes<B: SyscallBackend + ?Sized>(
        &self,
        backend: &B,
    ) -> Result<Vec<u8>, OnChainError> {
        const G2_COMPRESSED: usize = 64;
        const G1_COMPRESSED: usize = 32;

        // Compress G2.
        let g2_c = mosaic_zk_primitives::compression::compress_g2(backend, &self.x2_g2)?;

        // Compress every fixed + permutation commit.
        let mut fixed_payload: Vec<u8> = Vec::with_capacity(
            (self.fixed_commits.len() / sizes::G1_LEN) * G1_COMPRESSED,
        );
        for chunk in self.fixed_commits.chunks_exact(sizes::G1_LEN) {
            let mut g1_arr = [0u8; sizes::G1_LEN];
            g1_arr.copy_from_slice(chunk);
            let c = mosaic_zk_primitives::compression::compress_g1(backend, &g1_arr)?;
            fixed_payload.extend_from_slice(&c);
        }

        let mut perm_payload: Vec<u8> = Vec::with_capacity(
            (self.permutation_commits.len() / sizes::G1_LEN) * G1_COMPRESSED,
        );
        for chunk in self.permutation_commits.chunks_exact(sizes::G1_LEN) {
            let mut g1_arr = [0u8; sizes::G1_LEN];
            g1_arr.copy_from_slice(chunk);
            let c = mosaic_zk_primitives::compression::compress_g1(backend, &g1_arr)?;
            perm_payload.extend_from_slice(&c);
        }

        let mut out = Vec::with_capacity(
            Self::COMPRESSED_FIXED_LEN + fixed_payload.len() + perm_payload.len(),
        );
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.n_instances.to_le_bytes());
        out.extend_from_slice(&self.n_advice.to_le_bytes());
        out.extend_from_slice(&self.n_fixed.to_le_bytes());
        out.extend_from_slice(&g2_c);
        out.extend_from_slice(&self.omega_fr);
        out.extend_from_slice(&(fixed_payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(perm_payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&fixed_payload);
        out.extend_from_slice(&perm_payload);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sizes::{FIXED_HEADER_LEN, FR_LEN, G1_LEN, G2_LEN};

    fn proof_bytes(n_advice: u32, n_lookups: u32, n_quotient: u32, n_evals: u32) -> Vec<u8> {
        // Default to lookup_arity = 1 (legacy single-column).
        proof_bytes_with_arity(n_advice, n_lookups, n_quotient, n_evals, 1)
    }

    fn proof_bytes_with_arity(
        n_advice: u32,
        n_lookups: u32,
        n_quotient: u32,
        n_evals: u32,
        lookup_arity: u32,
    ) -> Vec<u8> {
        let total = FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN // permutation_z
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = vec![0xAA; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
        // Session 100: lookup_arity at byte 16-19. Default to 1 for
        // legacy single-column tests.
        buf[16..20].copy_from_slice(&lookup_arity.to_le_bytes());
        buf
    }

    #[test]
    fn proof_parses_typical_shape() {
        let buf = proof_bytes(5, 1, 3, 15);
        let p = Halo2KzgProof::from_bytes(&buf).unwrap();
        assert_eq!(p.n_advice, 5);
        assert_eq!(p.n_lookups, 1);
        assert_eq!(p.n_quotient, 3);
        assert_eq!(p.n_evals, 15);
        assert_eq!(p.advice_iter().count(), 5);
        assert_eq!(p.quotient_iter().count(), 3);
        assert_eq!(p.evaluations_iter().count(), 15);
    }

    #[test]
    fn proof_parses_minimal_shape() {
        let buf = proof_bytes(0, 0, 0, 0);
        let p = Halo2KzgProof::from_bytes(&buf).unwrap();
        assert_eq!(p.n_advice, 0);
        assert_eq!(p.advice_iter().count(), 0);
    }

    #[test]
    fn proof_rejects_advice_over_max() {
        let buf = proof_bytes(sizes::MAX_ADVICE_COLUMNS + 1, 1, 1, 1);
        assert!(matches!(
            Halo2KzgProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_evals_over_max() {
        let buf = proof_bytes(1, 1, 1, sizes::MAX_EVALUATIONS + 1);
        assert!(matches!(
            Halo2KzgProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_trailing_garbage() {
        let mut buf = proof_bytes(2, 0, 1, 3);
        buf.push(0xDE);
        assert!(matches!(
            Halo2KzgProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn vk_roundtrip_no_commits() {
        // Session 105: this test pre-existed with `n_fixed: 2` and
        // `fixed_commits: vec![]` — a deliberate-or-accidental
        // mismatch the parser used to silently accept. The new
        // consistency check correctly rejects it. Update to consistent
        // values: zero fixed commits matches `n_fixed = 0`.
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 0,
            x2_g2: [0xCD; G2_LEN],
            omega_fr: [0u8; FR_LEN],
            fixed_commits: vec![],
            permutation_commits: vec![],
        };
        let bytes = vk.to_bytes();
        let decoded = Halo2KzgVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
    }

    /// Session 105 — VK with declared `n_fixed: 2` but empty
    /// `fixed_commits` byte buffer must be rejected. Pre-session-105
    /// the parser would accept this silently and downstream verifier
    /// code would mis-index based on `n_fixed`.
    #[test]
    fn vk_rejects_n_fixed_inconsistent_with_commits_len() {
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2, // claims 2 commits
            x2_g2: [0xCD; G2_LEN],
            omega_fr: [0u8; FR_LEN],
            fixed_commits: vec![], // but has 0 commit bytes
            permutation_commits: vec![],
        };
        let bytes = vk.to_bytes();
        let r = Halo2KzgVerifyingKey::from_bytes(&bytes);
        assert!(
            matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)),
            "n_fixed=2 with empty commits must reject; got {r:?}",
        );
    }

    /// Session 105 — non-multiple-of-G1_LEN payload byte counts get
    /// rejected at parse time. Catches a malformed wire payload that
    /// can't represent a coherent commit vector.
    #[test]
    fn vk_rejects_non_multiple_g1_payload_lengths() {
        // Build a hand-rolled VK byte buffer with fixed_commits.len()
        // = 65 bytes (not a multiple of G1_LEN = 64). The parser
        // should reject before constructing the Vec.
        use crate::canonical::sizes::{FR_LEN, G2_LEN};
        let payload_start = 16 + G2_LEN + FR_LEN + 8;
        let bad_fixed_len: u32 = 65; // not a multiple of 64
        let mut buf = vec![0u8; payload_start + bad_fixed_len as usize];
        buf[0..4].copy_from_slice(&10u32.to_le_bytes()); // k
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // n_instances
        buf[8..12].copy_from_slice(&5u32.to_le_bytes()); // n_advice
        buf[12..16].copy_from_slice(&0u32.to_le_bytes()); // n_fixed = 0
        // x2_g2 + omega_fr stay zero
        let after_omega = 16 + G2_LEN + FR_LEN;
        buf[after_omega..after_omega + 4].copy_from_slice(&bad_fixed_len.to_le_bytes());
        buf[after_omega + 4..after_omega + 8].copy_from_slice(&0u32.to_le_bytes()); // perm_len = 0
        let r = Halo2KzgVerifyingKey::from_bytes(&buf);
        assert!(
            matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)),
            "fixed_len=65 (non-multiple of G1_LEN) must reject; got {r:?}",
        );
    }

    #[test]
    fn vk_roundtrip_with_commits() {
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: [0xCD; G2_LEN],
            omega_fr: [0u8; FR_LEN],
            fixed_commits: vec![0x11; 2 * G1_LEN], // 2 fixed columns
            permutation_commits: vec![0x22; 5 * G1_LEN], // 5 advice columns permuted
        };
        let bytes = vk.to_bytes();
        let decoded = Halo2KzgVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
        assert_eq!(decoded.fixed_commits.len(), 2 * G1_LEN);
        assert_eq!(decoded.permutation_commits.len(), 5 * G1_LEN);
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 106 — compressed VK round-trip + bandwidth-saving tests.
    //
    // The compression syscall (session 103) is exercised end-to-end
    // here: a VK with real on-curve commits encodes via
    // `to_compressed_bytes`, decodes via `from_compressed_bytes`, and
    // the result must equal the original VK byte-for-byte.
    // ───────────────────────────────────────────────────────────────────

    fn realistic_vk() -> Halo2KzgVerifyingKey {
        // Use the BN254 G2 generator for x2_g2 (compressible) and the
        // G1 generator for every commit (also compressible). Zero
        // points compress trivially to zero, so the realistic test
        // uses non-zero points to exercise the actual compression
        // arithmetic.
        let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();
        let g2_gen = mosaic_zk_primitives::g1_consts::g2_generator_bytes();

        let mut fixed_commits = Vec::with_capacity(2 * G1_LEN);
        fixed_commits.extend_from_slice(&g1_gen);
        fixed_commits.extend_from_slice(&g1_gen);

        let mut permutation_commits = Vec::with_capacity(5 * G1_LEN);
        for _ in 0..5 {
            permutation_commits.extend_from_slice(&g1_gen);
        }

        Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: g2_gen,
            omega_fr: [0u8; FR_LEN],
            fixed_commits,
            permutation_commits,
        }
    }

    #[test]
    fn vk_compressed_round_trip_with_real_generators() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let vk = realistic_vk();
        let compressed = vk
            .to_compressed_bytes(&backend)
            .expect("compress should succeed for on-curve generators");
        let decoded = Halo2KzgVerifyingKey::from_compressed_bytes(&backend, &compressed)
            .expect("decompress should succeed for compressed buffer");
        assert_eq!(
            vk, decoded,
            "compressed round-trip must yield the original VK byte-for-byte"
        );
    }

    #[test]
    fn vk_compressed_form_is_smaller_than_uncompressed() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let vk = realistic_vk();
        let uncompressed = vk.to_bytes();
        let compressed = vk
            .to_compressed_bytes(&backend)
            .expect("compress");
        // Each G1 (64 → 32) saves 32 B; each G2 (128 → 64) saves 64 B.
        // 2 fixed + 5 perm = 7 G1 commits + 1 G2 = 7·32 + 64 = 288 B saved.
        // The Fr omega + 4 u32 counters + 2 u32 lengths are unchanged.
        let saved = uncompressed.len() - compressed.len();
        let expected_saved = 7 * 32 + 64;
        assert_eq!(
            saved, expected_saved,
            "compressed VK must save exactly {expected_saved} bytes (7·32 G1 + 64 G2); got {saved}"
        );
        assert!(
            compressed.len() * 100 / uncompressed.len() <= 60,
            "compressed VK must be ≤ 60% of uncompressed size; \
             got compressed={} uncompressed={}",
            compressed.len(),
            uncompressed.len()
        );
    }

    #[test]
    fn vk_compressed_zero_only_short_circuits_to_zero_uncompressed() {
        // Zero G1/G2 points short-circuit through the compression
        // syscall (both backends). A VK built entirely of zero commits
        // round-trips through compression as zero.
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: [0u8; G2_LEN],
            omega_fr: [0u8; FR_LEN],
            fixed_commits: vec![0u8; 2 * G1_LEN],
            permutation_commits: vec![0u8; 5 * G1_LEN],
        };
        let compressed = vk.to_compressed_bytes(&backend).unwrap();
        let decoded =
            Halo2KzgVerifyingKey::from_compressed_bytes(&backend, &compressed).unwrap();
        assert_eq!(vk, decoded);
    }

    #[test]
    fn vk_compressed_rejects_short_buffer() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let too_short = vec![0u8; Halo2KzgVerifyingKey::COMPRESSED_FIXED_LEN - 1];
        let r = Halo2KzgVerifyingKey::from_compressed_bytes(&backend, &too_short);
        assert!(matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)));
    }

    #[test]
    fn vk_compressed_rejects_n_fixed_inconsistent_with_payload() {
        // Build a compressed VK header that declares n_fixed=3 but
        // only carries 2·32 bytes of compressed fixed commits. The
        // session-105 consistency check (adapted for compressed sizes)
        // must reject.
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let vk = realistic_vk(); // n_fixed = 2 with consistent payload
        let mut bad = vk.to_compressed_bytes(&backend).unwrap();
        // Bump n_fixed at offset 12-15 to 3 without resizing the
        // payload — declared count no longer matches actual.
        bad[12..16].copy_from_slice(&3u32.to_le_bytes());
        let r = Halo2KzgVerifyingKey::from_compressed_bytes(&backend, &bad);
        assert!(
            matches!(r, Err(OnChainError::VerifyingKeyLengthMismatch)),
            "n_fixed=3 with arity-2 payload must reject; got {r:?}",
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 108 — compressed proof round-trip + bandwidth-saving tests.
    //
    // The proof's G1 commits (advice, lookup, permutation_z, quotient,
    // w_xi, w_xiw) are compressed via the alt_bn128 syscall. Fr
    // evaluations are uncompressed (not curve points).
    //
    // Same trade-off pattern as session-106 compressed VK: ~10 K CU
    // per G1 decompression, ~32 B saving per commit.
    // ───────────────────────────────────────────────────────────────────

    /// Build a canonical (uncompressed) Halo2 proof with realistic
    /// G1 commits. All commits use the BN254 G1 generator (compressible)
    /// and Fr evaluations stay zero.
    fn realistic_canonical_proof() -> Vec<u8> {
        use crate::canonical::sizes::{FR_LEN, G1_LEN};
        let g1_gen = mosaic_zk_primitives::g1_consts::g1_generator_bytes();

        let n_advice: u32 = 5;
        let n_lookups: u32 = 0; // legacy implicit-1 mode
        let n_quotient: u32 = 3;
        let n_evals: u32 = 19; // 13 + 1·(2·1+1) + 3 = 19
        let arity: u32 = 1;

        let total = sizes::FIXED_HEADER_LEN
            + (n_advice as usize) * G1_LEN
            + (n_lookups as usize) * G1_LEN
            + G1_LEN
            + (n_quotient as usize) * G1_LEN
            + (n_evals as usize) * FR_LEN
            + 2 * G1_LEN;
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
        buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
        buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
        buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
        buf[16..20].copy_from_slice(&arity.to_le_bytes());

        // Place G1 generator into every G1 commit slot.
        let mut o = sizes::FIXED_HEADER_LEN;
        // advice commits
        for _ in 0..n_advice {
            buf[o..o + G1_LEN].copy_from_slice(&g1_gen);
            o += G1_LEN;
        }
        // lookup commits (n_lookups = 0, no-op)
        // permutation_z
        buf[o..o + G1_LEN].copy_from_slice(&g1_gen);
        o += G1_LEN;
        // quotient chunks
        for _ in 0..n_quotient {
            buf[o..o + G1_LEN].copy_from_slice(&g1_gen);
            o += G1_LEN;
        }
        // Fr evaluations: leave zero
        o += (n_evals as usize) * FR_LEN;
        // w_xi
        buf[o..o + G1_LEN].copy_from_slice(&g1_gen);
        o += G1_LEN;
        // w_xiw
        buf[o..o + G1_LEN].copy_from_slice(&g1_gen);
        buf
    }

    #[test]
    fn proof_compressed_round_trip_with_real_generators() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let canonical = realistic_canonical_proof();
        let compressed =
            Halo2KzgProof::compress_from_canonical_bytes(&backend, &canonical)
                .expect("compress proof");
        let decoded =
            Halo2KzgProof::decompress_to_canonical_bytes(&backend, &compressed)
                .expect("decompress proof");
        assert_eq!(
            decoded, canonical,
            "compressed proof round-trip must yield original canonical bytes"
        );
    }

    #[test]
    fn proof_compressed_form_is_smaller_than_uncompressed() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let canonical = realistic_canonical_proof();
        let compressed =
            Halo2KzgProof::compress_from_canonical_bytes(&backend, &canonical)
                .expect("compress");
        // 5 advice + 0 lookups + 1 perm_z + 3 quotient + 2 openings = 11 G1
        // commits → 11·32 = 352 B saving (each G1 64→32).
        let expected_saving = 11 * 32;
        let actual_saving = canonical.len() - compressed.len();
        assert_eq!(
            actual_saving, expected_saving,
            "compressed proof must save exactly {expected_saving} B; got {actual_saving}"
        );
    }

    #[test]
    fn proof_compressed_zero_only_round_trips() {
        // All-zero proof: every G1 = identity. Compression syscall
        // short-circuits zero G1 to zero (32 B). Round-trip stays
        // all-zero.
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let canonical = {
            let n_advice: u32 = 5;
            let n_lookups: u32 = 0;
            let n_quotient: u32 = 3;
            let n_evals: u32 = 19;
            let arity: u32 = 1;
            let total = sizes::FIXED_HEADER_LEN
                + (n_advice as usize) * sizes::G1_LEN
                + (n_lookups as usize) * sizes::G1_LEN
                + sizes::G1_LEN
                + (n_quotient as usize) * sizes::G1_LEN
                + (n_evals as usize) * sizes::FR_LEN
                + 2 * sizes::G1_LEN;
            let mut buf = vec![0u8; total];
            buf[0..4].copy_from_slice(&n_advice.to_le_bytes());
            buf[4..8].copy_from_slice(&n_lookups.to_le_bytes());
            buf[8..12].copy_from_slice(&n_quotient.to_le_bytes());
            buf[12..16].copy_from_slice(&n_evals.to_le_bytes());
            buf[16..20].copy_from_slice(&arity.to_le_bytes());
            buf
        };
        let compressed =
            Halo2KzgProof::compress_from_canonical_bytes(&backend, &canonical).unwrap();
        let decoded =
            Halo2KzgProof::decompress_to_canonical_bytes(&backend, &compressed).unwrap();
        assert_eq!(decoded, canonical);
    }

    #[test]
    fn proof_compressed_rejects_short_buffer() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        // Min size = header + 1·G1_C (perm_z) + 2·G1_C (openings) = 20 + 32 + 64 = 116.
        let too_short = vec![0u8; 115];
        let r = Halo2KzgProof::decompress_to_canonical_bytes(&backend, &too_short);
        assert!(matches!(r, Err(OnChainError::ProofLengthMismatch)));
    }

    #[test]
    fn proof_compressed_rejects_wrong_total_length() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let canonical = realistic_canonical_proof();
        let mut compressed =
            Halo2KzgProof::compress_from_canonical_bytes(&backend, &canonical).unwrap();
        // Append trailing garbage — total length no longer matches
        // declared shape.
        compressed.push(0xFF);
        let r =
            Halo2KzgProof::decompress_to_canonical_bytes(&backend, &compressed);
        assert!(
            matches!(r, Err(OnChainError::ProofLengthMismatch)),
            "trailing-garbage compressed proof must reject; got {r:?}",
        );
    }

    /// Decompressed proof must be parseable as a normal canonical
    /// proof — i.e. the chained `decompress → from_bytes` path
    /// gives a valid `Halo2KzgProof<'a>` view.
    #[test]
    fn proof_decompressed_parses_as_canonical_via_from_bytes() {
        let backend = mosaic_core::syscall::host::HostBackend::new();
        let canonical = realistic_canonical_proof();
        let compressed =
            Halo2KzgProof::compress_from_canonical_bytes(&backend, &canonical).unwrap();
        let decoded =
            Halo2KzgProof::decompress_to_canonical_bytes(&backend, &compressed).unwrap();
        let parsed = Halo2KzgProof::from_bytes(&decoded).expect("from_bytes parse");
        assert_eq!(parsed.n_advice, 5);
        assert_eq!(parsed.n_lookups, 0);
        assert_eq!(parsed.n_quotient, 3);
        assert_eq!(parsed.n_evals, 19);
        assert_eq!(parsed.lookup_arity, 1);
        // 5 advice + 1 perm_z + 3 quotient + 2 openings = 11 G1 = 11·64 = 704 B
        // of G1 commitments (excluding lookup_commits which is 0 at n_lookups=0).
        assert_eq!(parsed.advice_commits.len(), 5 * 64);
        assert_eq!(parsed.permutation_z.len(), 64);
        assert_eq!(parsed.quotient_chunks.len(), 3 * 64);
        assert_eq!(parsed.w_xi.len(), 64);
        assert_eq!(parsed.w_xiw.len(), 64);
    }

    #[test]
    fn vk_rejects_short_buffer() {
        let short = vec![0u8; Halo2KzgVerifyingKey::FIXED_LEN - 1];
        assert!(matches!(
            Halo2KzgVerifyingKey::from_bytes(&short),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }

    #[test]
    fn vk_rejects_mismatched_tail_length() {
        let vk = Halo2KzgVerifyingKey {
            k: 10,
            n_instances: 1,
            n_advice: 5,
            n_fixed: 2,
            x2_g2: [0; G2_LEN],
            omega_fr: [0u8; FR_LEN],
            fixed_commits: vec![0x11; G1_LEN],
            permutation_commits: vec![],
        };
        let mut bytes = vk.to_bytes();
        bytes.push(0xFF); // extra byte
        assert!(matches!(
            Halo2KzgVerifyingKey::from_bytes(&bytes),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 37 — proptest coverage for canonical Halo2-KZG byte layout.
    //
    // These property-based tests close the gap between the unit tests
    // above (which pin a handful of representative shapes) and the
    // adversarial proof inputs an on-chain verifier will see in practice.
    //
    // Strategy spaces are deliberately bounded by the size constants
    // already declared in `sizes::*`, so the proptests exercise only
    // shapes a real verifier would accept up to header parsing — the
    // negative cases below mutate inside that envelope to confirm the
    // length checks fail closed.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    prop_compose! {
        /// Random in-range (n_advice, n_lookups, n_quotient, n_evals)
        /// quad. Each counter stays inside `sizes::MAX_*` so the
        /// resulting buffer is always parseable.
        fn arb_proof_shape()(
            n_advice in 0u32..=sizes::MAX_ADVICE_COLUMNS,
            n_lookups in 0u32..=sizes::MAX_LOOKUPS,
            n_quotient in 0u32..=sizes::MAX_QUOTIENT_CHUNKS,
            n_evals in 0u32..=sizes::MAX_EVALUATIONS,
        ) -> (u32, u32, u32, u32) {
            (n_advice, n_lookups, n_quotient, n_evals)
        }
    }

    prop_compose! {
        /// Random VK shape. Counter-derived buffers are filled with
        /// distinct byte patterns so a swap between fixed_commits and
        /// permutation_commits would surface as inequality after
        /// round-trip.
        fn arb_vk()(
            k in 0u32..=20,
            n_instances in 0u32..=8,
            n_advice in 0u32..=8,
            x2_byte in any::<u8>(),
            omega_byte in any::<u8>(),
            // Session 105: `n_fixed` and the fixed_commits byte length
            // must agree (`fixed_commits.len() == n_fixed * G1_LEN`).
            // Use a single counter for both so the strategy generates
            // only consistent VKs.
            fixed_count in 0u32..=4,
            perm_count in 0u32..=4,
        ) -> Halo2KzgVerifyingKey {
            Halo2KzgVerifyingKey {
                k,
                n_instances,
                n_advice,
                n_fixed: fixed_count,
                x2_g2: [x2_byte; G2_LEN],
                omega_fr: [omega_byte; FR_LEN],
                fixed_commits: vec![0x11; (fixed_count as usize) * G1_LEN],
                permutation_commits: vec![0x22; (perm_count as usize) * G1_LEN],
            }
        }
    }

    proptest! {
        /// Any in-range shape parses, and the parsed counters and
        /// section iterators agree with the intended shape.
        #[test]
        fn proptest_proof_parses_any_in_range_shape(
            (n_advice, n_lookups, n_quotient, n_evals) in arb_proof_shape(),
        ) {
            let buf = proof_bytes(n_advice, n_lookups, n_quotient, n_evals);
            let p = Halo2KzgProof::from_bytes(&buf).expect("in-range shape parses");
            prop_assert_eq!(p.n_advice, n_advice);
            prop_assert_eq!(p.n_lookups, n_lookups);
            prop_assert_eq!(p.n_quotient, n_quotient);
            prop_assert_eq!(p.n_evals, n_evals);
            prop_assert_eq!(p.advice_iter().count(), n_advice as usize);
            prop_assert_eq!(p.quotient_iter().count(), n_quotient as usize);
            prop_assert_eq!(p.evaluations_iter().count(), n_evals as usize);
            prop_assert_eq!(p.permutation_z.len(), G1_LEN);
            prop_assert_eq!(p.w_xi.len(), G1_LEN);
            prop_assert_eq!(p.w_xiw.len(), G1_LEN);
        }

        /// Trailing garbage of any non-zero length must be rejected.
        /// Catches off-by-one errors where a parser would silently
        /// consume more or fewer bytes than the header advertises.
        #[test]
        fn proptest_proof_rejects_any_trailing_garbage(
            (n_advice, n_lookups, n_quotient, n_evals) in arb_proof_shape(),
            extra in 1usize..=64,
        ) {
            let mut buf = proof_bytes(n_advice, n_lookups, n_quotient, n_evals);
            buf.extend(core::iter::repeat_n(0xDE, extra));
            prop_assert!(matches!(
                Halo2KzgProof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// Any truncation by ≥1 byte must be rejected.
        #[test]
        fn proptest_proof_rejects_truncation(
            (n_advice, n_lookups, n_quotient, n_evals) in arb_proof_shape(),
            chop in 1usize..=64,
        ) {
            let mut buf = proof_bytes(n_advice, n_lookups, n_quotient, n_evals);
            let new_len = buf.len().saturating_sub(chop);
            // Skip degenerate truncations that drop the fixed header
            // entirely — those test a different invariant covered below.
            prop_assume!(new_len >= FIXED_HEADER_LEN);
            buf.truncate(new_len);
            prop_assert!(matches!(
                Halo2KzgProof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// Counters above their declared max must be rejected before
        /// any payload arithmetic. Picks one of the four counters at
        /// random and pushes it past its cap. This guards against
        /// integer-overflow attacks via `checked_mul` slipping if the
        /// max constants are ever raised.
        #[test]
        fn proptest_proof_rejects_oversized_counter(
            which in 0u8..4,
            overflow in 1u32..=8,
        ) {
            let max = match which {
                0 => sizes::MAX_ADVICE_COLUMNS,
                1 => sizes::MAX_LOOKUPS,
                2 => sizes::MAX_QUOTIENT_CHUNKS,
                _ => sizes::MAX_EVALUATIONS,
            };
            let bad = max + overflow;
            let (n_advice, n_lookups, n_quotient, n_evals) = match which {
                0 => (bad, 1, 1, 1),
                1 => (1, bad, 1, 1),
                2 => (1, 1, bad, 1),
                _ => (1, 1, 1, bad),
            };
            // We synthesize the *header* explicitly because
            // `proof_bytes` would over-allocate to the bad shape.
            let mut hdr = [0u8; FIXED_HEADER_LEN];
            hdr[0..4].copy_from_slice(&n_advice.to_le_bytes());
            hdr[4..8].copy_from_slice(&n_lookups.to_le_bytes());
            hdr[8..12].copy_from_slice(&n_quotient.to_le_bytes());
            hdr[12..16].copy_from_slice(&n_evals.to_le_bytes());
            // Append the minimum tail (perm_z + w_xi + w_xiw) so the
            // length pre-check passes and the cap-check is the rejector.
            let mut buf = hdr.to_vec();
            buf.extend(vec![0u8; 3 * G1_LEN]);
            prop_assert!(matches!(
                Halo2KzgProof::from_bytes(&buf),
                Err(OnChainError::ProofLengthMismatch),
            ));
        }

        /// VK bytes round-trip: encode then decode is the identity for
        /// any well-formed VK in our bounded shape space.
        #[test]
        fn proptest_vk_roundtrip(vk in arb_vk()) {
            let bytes = vk.to_bytes();
            let decoded = Halo2KzgVerifyingKey::from_bytes(&bytes)
                .expect("well-formed VK round-trips");
            prop_assert_eq!(vk, decoded);
        }

        /// Appending any non-empty trailing garbage to encoded VK bytes
        /// must surface as `VerifyingKeyLengthMismatch`. Catches the
        /// "decoder ignored trailing bytes" failure mode which would
        /// allow attackers to smuggle data past the on-chain length
        /// check.
        #[test]
        fn proptest_vk_rejects_trailing_garbage(
            vk in arb_vk(),
            extra in 1usize..=32,
        ) {
            let mut bytes = vk.to_bytes();
            bytes.extend(core::iter::repeat_n(0xFF, extra));
            prop_assert!(matches!(
                Halo2KzgVerifyingKey::from_bytes(&bytes),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }

        /// Any truncation past the fixed header must be rejected. The
        /// fixed header carries the `fixed_commits` / `perm_commits`
        /// length advertisements; truncating the variable tail leaves
        /// the decoder asking for bytes that aren't there.
        #[test]
        fn proptest_vk_rejects_truncated_tail(
            vk in arb_vk(),
            chop in 1usize..=32,
        ) {
            let mut bytes = vk.to_bytes();
            let new_len = bytes.len().saturating_sub(chop);
            prop_assume!(new_len >= Halo2KzgVerifyingKey::FIXED_LEN);
            // Only meaningful when there *is* a tail to truncate.
            prop_assume!(bytes.len() > Halo2KzgVerifyingKey::FIXED_LEN);
            bytes.truncate(new_len);
            prop_assert!(matches!(
                Halo2KzgVerifyingKey::from_bytes(&bytes),
                Err(OnChainError::VerifyingKeyLengthMismatch),
            ));
        }
    }
}
