//! FRI-STARK canonical byte layout — **placeholder shape** derived from
//! Plonky3 / Winterfell proof encodings.
//!
//! ## Target encodings
//!
//! Plonky3 emits proofs via `p3_fri::proof::FriProof` + a per-protocol
//! wrapper (e.g. `p3_uni_stark::proof::Proof`). Winterfell emits
//! `winter_air::proof::StarkProof`. Both follow the same high-level
//! shape:
//!
//! ```text
//! [trace_commitment]               (32 B digest)
//! [constraint_commitment]          (32 B digest)
//! [fri_layer_commitments...]       (num_layers × 32 B)
//! [ood_evals...]                   (variable × field_elem_bytes)
//! [fri_final_polynomial]           (variable × field_elem_bytes)
//! [query_responses...]             (num_queries × (opening + auth_path))
//! [pow_nonce]                      (8 B)
//! ```
//!
//! The exact layout varies by folding rate, query count, and field
//! element encoding (LE bytes in Plonky3, BE bytes in Winterfell).
//! Phase 3 pins this layout against a specific reference implementation
//! in an ADR amendment.
//!
//! ## Our placeholder shape
//!
//! Header is fixed-size. Variable tails are length-prefixed. Field
//! element size is determined by `field_id`.
//!
//! | Offset | Length | Field |
//! |---|---|---|
//! | 0 | 1 | `field_id` (u8) — 0=Goldilocks, 1=BabyBear, 2=Mersenne31 |
//! | 1 | 1 | `log_blowup` (u8) — FRI blowup factor exponent |
//! | 2 | 1 | `num_fri_layers` (u8) |
//! | 3 | 1 | `pow_bits` (u8) — PoW grinding difficulty |
//! | 4 | 2 | `num_queries` (u16 LE) |
//! | 6 | 2 | `trace_log_height` (u16 LE) |
//! | 8 | 4 | `trace_width` (u32 LE) |
//! | 12 | 4 | reserved |
//! | 16 | 32 | `trace_commitment` (digest) |
//! | 48 | 32 | `constraint_commitment` (digest) |
//! | 80 | 32 × `num_fri_layers` | FRI layer commitments |
//! | … | 4 | `ood_evals.len()` (u32 LE, bytes) |
//! | … | var | `ood_evals` bytes |
//! | … | 4 | `fri_final_poly.len()` (u32 LE, bytes) |
//! | … | var | `fri_final_poly` bytes |
//! | … | 4 | `query_responses.len()` (u32 LE, bytes) |
//! | … | var | `query_responses` bytes |
//! | … | 8 | `pow_nonce` (u64 LE) |
//!
//! For a typical 2¹⁶-row Goldilocks trace with 80 queries, 16 FRI layers,
//! and 50 OOD evaluations the proof is roughly:
//!
//!   16 + 64 + 16·32 + 50·8 + ~500·8 + 80·(~300) + 8 ≈ **30 KB**
//!
//! Well above Solana's 1232 B transaction limit — **STARK verification
//! requires the chunked-upload protocol** (`mosaic-chunked`). The
//! canonical layout here is what the chunked committer reassembles
//! before dispatch.

use alloc::vec::Vec;
use mosaic_core::OnChainError;

/// Size + cap constants for the FRI-STARK canonical layout.
pub mod sizes {
    /// Hash digest length (SHA-256 / BLAKE3-256).
    pub const DIGEST_LEN: usize = 32;
    /// Fixed header length (see canonical layout table).
    pub const FIXED_HEADER_LEN: usize = 16;
    /// Proof-of-work nonce length.
    pub const POW_NONCE_LEN: usize = 8;
    /// Max FRI layers — 2⁶⁴ exceeds any realistic domain but cap at 64
    /// for sanity (max realistic log₂ domain ≈ 32).
    pub const MAX_FRI_LAYERS: u8 = 64;
    /// Max query count — Plonky3 defaults range 80–150; cap liberally.
    pub const MAX_QUERIES: u16 = 512;
    /// Max trace log-height — caps domain at 2³², well above realistic
    /// 2²⁰–2²⁴ range for current machines.
    pub const MAX_TRACE_LOG_HEIGHT: u16 = 32;
    /// Max trace width — cap at 2¹⁰ columns; Plonky3 circuits fit under.
    pub const MAX_TRACE_WIDTH: u32 = 1024;
    /// Max PoW grinding bits — 32 is already extremely hard; cap here.
    pub const MAX_POW_BITS: u8 = 32;
    /// Max variable-tail length (bytes). Guards against pathological
    /// input without capping realistic 200 KB proofs (ample margin).
    pub const MAX_TAIL_LEN: u32 = 1_048_576; // 1 MiB
}

/// Base field identifier. Plonky3 supports several; we encode a tag
/// in the proof so the verifier can dispatch to the right arithmetic.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StarkFieldId {
    /// Goldilocks (p = 2⁶⁴ − 2³² + 1). Default in Plonky3.
    Goldilocks = 0,
    /// BabyBear (p = 15 · 2²⁷ + 1). Used in RISC-V STARK backends.
    BabyBear = 1,
    /// Mersenne31 (p = 2³¹ − 1). Used in Circle-STARK.
    Mersenne31 = 2,
}

impl StarkFieldId {
    /// Field-element byte width (canonical LE encoding).
    #[must_use]
    pub const fn field_elem_bytes(self) -> usize {
        match self {
            Self::Goldilocks => 8,
            Self::BabyBear | Self::Mersenne31 => 4,
        }
    }

    /// Decode from the raw tag byte. Unknown tags are rejected to guard
    /// against silent format regressions.
    pub fn from_byte(b: u8) -> Result<Self, OnChainError> {
        match b {
            0 => Ok(Self::Goldilocks),
            1 => Ok(Self::BabyBear),
            2 => Ok(Self::Mersenne31),
            _ => Err(OnChainError::UnknownProofSystem),
        }
    }
}

/// Per-query per-layer Goldilocks opening size: two field elements
/// (f(x), f(-x)), each 8 bytes LE.
pub const FRI_LAYER_OPENING_LEN: usize = 2 * 8;

/// Zero-copy view into a FRI-STARK proof buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FriStarkProof<'a> {
    /// Base field identifier.
    pub field_id: StarkFieldId,
    /// FRI blowup factor exponent (domain = trace_height × 2^log_blowup).
    pub log_blowup: u8,
    /// Number of FRI layers (typically log₂(domain) − 1).
    pub num_fri_layers: u8,
    /// Proof-of-work grinding difficulty bits.
    pub pow_bits: u8,
    /// Number of query phase rounds.
    pub num_queries: u16,
    /// Trace log-height (rows = 2^log_height).
    pub trace_log_height: u16,
    /// Trace column count.
    pub trace_width: u32,
    /// Execution trace Merkle root.
    pub trace_commitment: &'a [u8],
    /// Constraint composition polynomial Merkle root.
    pub constraint_commitment: &'a [u8],
    /// FRI layer commitment digests (length = `num_fri_layers × 32`).
    pub fri_layer_commits: &'a [u8],
    /// Out-of-domain evaluations of the trace + constraint polys.
    pub ood_evals: &'a [u8],
    /// FRI final polynomial coefficients.
    pub fri_final_poly: &'a [u8],
    /// Query phase responses (opening values + Merkle auth paths).
    pub query_responses: &'a [u8],
    /// Per-FRI-layer fold openings (session 13b). Flat buffer of
    /// `num_queries × num_fri_layers × 16` bytes carrying `(f(x),
    /// f(-x))` Goldilocks pairs. Empty when `num_fri_layers = 0`.
    pub fri_layer_openings: &'a [u8],
    /// Claimed final-layer scalar after all FRI folds
    /// (session 13b). Single Goldilocks value, 8-byte LE. All queries
    /// must fold to this same scalar (scaffold assumption: final
    /// polynomial is constant; Session 14 extends to multi-coefficient
    /// final polynomials).
    pub final_layer_value: [u8; 8],
    /// Proof-of-work nonce used for grinding.
    pub pow_nonce: u64,
}

impl<'a> FriStarkProof<'a> {
    /// Per-query byte count for the structured `query_responses`
    /// layout (session 8 revision): each query carries **two**
    /// `(leaf, auth_path)` pairs — one for the trace commitment and
    /// one for the constraint commitment.
    ///
    /// Total length:
    /// `2 · (DIGEST_LEN + depth · DIGEST_LEN) = 2 · (1 + depth) · 32 B`
    /// where `depth = trace_log_height + log_blowup`.
    #[must_use]
    pub fn per_query_bytes(&self) -> usize {
        let depth = (self.trace_log_height as usize) + (self.log_blowup as usize);
        2 * (sizes::DIGEST_LEN + depth * sizes::DIGEST_LEN)
    }

    /// Iterate query responses as `(trace_leaf, trace_path,
    /// constraint_leaf, constraint_path)` 4-tuples.
    ///
    /// Each query carries openings against two Merkle commitments:
    /// the **trace** commitment (containing the executed program's
    /// state at each row) and the **constraint** commitment
    /// (containing the constraint-composition polynomial's
    /// evaluations). The verifier must check both paths for
    /// full soundness.
    ///
    /// Returns `None` if the buffer isn't consistent with the
    /// declared `(num_queries, depth)`.
    pub fn query_response_iter(
        &self,
    ) -> Option<impl Iterator<Item = (&'a [u8], &'a [u8], &'a [u8], &'a [u8])> + '_> {
        use sizes::DIGEST_LEN;
        let depth = (self.trace_log_height as usize) + (self.log_blowup as usize);
        let single_len = DIGEST_LEN + depth * DIGEST_LEN;
        let per_query = 2 * single_len;
        let expected_len = (self.num_queries as usize) * per_query;
        if self.query_responses.len() != expected_len {
            return None;
        }
        Some(self.query_responses.chunks_exact(per_query).map(move |chunk| {
            let (trace, constraint) = chunk.split_at(single_len);
            let (t_leaf, t_path) = trace.split_at(DIGEST_LEN);
            let (c_leaf, c_path) = constraint.split_at(DIGEST_LEN);
            (t_leaf, t_path, c_leaf, c_path)
        }))
    }

    /// Parse a canonical FRI-STARK proof. Performs bounds + sanity
    /// checks; does *not* verify cryptographic content.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, OnChainError> {
        use sizes::{
            DIGEST_LEN, FIXED_HEADER_LEN, MAX_FRI_LAYERS, MAX_POW_BITS, MAX_QUERIES, MAX_TAIL_LEN,
            MAX_TRACE_LOG_HEIGHT, MAX_TRACE_WIDTH, POW_NONCE_LEN,
        };

        // Minimum length: header + two root digests + pow nonce +
        // four length prefixes (ood / final / queries / fri_layer_openings,
        // even if zero) + 8 bytes final_layer_value.
        let minimum = FIXED_HEADER_LEN + 2 * DIGEST_LEN + POW_NONCE_LEN + 4 * 4 + 8;
        if bytes.len() < minimum {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let field_id = StarkFieldId::from_byte(bytes[0])?;
        let log_blowup = bytes[1];
        let num_fri_layers = bytes[2];
        let pow_bits = bytes[3];
        let num_queries = u16::from_le_bytes([bytes[4], bytes[5]]);
        let trace_log_height = u16::from_le_bytes([bytes[6], bytes[7]]);
        let trace_width = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        if num_fri_layers > MAX_FRI_LAYERS
            || num_queries > MAX_QUERIES
            || trace_log_height > MAX_TRACE_LOG_HEIGHT
            || trace_width > MAX_TRACE_WIDTH
            || pow_bits > MAX_POW_BITS
        {
            return Err(OnChainError::ProofLengthMismatch);
        }

        let mut off = FIXED_HEADER_LEN;

        // Two fixed digests: trace + constraint.
        if bytes.len() < off + 2 * DIGEST_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let trace_commitment = &bytes[off..off + DIGEST_LEN];
        off += DIGEST_LEN;
        let constraint_commitment = &bytes[off..off + DIGEST_LEN];
        off += DIGEST_LEN;

        // FRI layer commitments.
        let fri_layer_bytes = (num_fri_layers as usize)
            .checked_mul(DIGEST_LEN)
            .ok_or(OnChainError::ProofLengthMismatch)?;
        if bytes.len() < off + fri_layer_bytes {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let fri_layer_commits = &bytes[off..off + fri_layer_bytes];
        off += fri_layer_bytes;

        // Four length-prefixed variable sections (ood / final /
        // queries / fri_layer_openings — new in session 13b).
        let (ood_evals, new_off) = read_var_tail(bytes, off, MAX_TAIL_LEN)?;
        off = new_off;
        let (fri_final_poly, new_off) = read_var_tail(bytes, off, MAX_TAIL_LEN)?;
        off = new_off;
        let (query_responses, new_off) = read_var_tail(bytes, off, MAX_TAIL_LEN)?;
        off = new_off;
        let (fri_layer_openings, new_off) = read_var_tail(bytes, off, MAX_TAIL_LEN)?;
        off = new_off;

        // Expected fri_layer_openings length check (session 13b
        // structural invariant):
        //   num_queries × num_fri_layers × FRI_LAYER_OPENING_LEN
        let expected_fri_openings_len = (num_queries as usize)
            .checked_mul(num_fri_layers as usize)
            .and_then(|n| n.checked_mul(FRI_LAYER_OPENING_LEN))
            .ok_or(OnChainError::ProofLengthMismatch)?;
        if fri_layer_openings.len() != expected_fri_openings_len {
            return Err(OnChainError::ProofLengthMismatch);
        }

        // Trailing: final_layer_value (8 bytes LE Goldilocks) + pow_nonce.
        if bytes.len() != off + 8 + POW_NONCE_LEN {
            return Err(OnChainError::ProofLengthMismatch);
        }
        let mut final_layer_value = [0u8; 8];
        final_layer_value.copy_from_slice(&bytes[off..off + 8]);
        off += 8;
        let pow_nonce = u64::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);

        Ok(Self {
            field_id,
            log_blowup,
            num_fri_layers,
            pow_bits,
            num_queries,
            trace_log_height,
            trace_width,
            trace_commitment,
            constraint_commitment,
            fri_layer_commits,
            ood_evals,
            fri_final_poly,
            query_responses,
            fri_layer_openings,
            final_layer_value,
            pow_nonce,
        })
    }

    /// Per-query per-layer opening iterator: yields
    /// `(f(x), f(-x))` Goldilocks scalars for each (query, layer)
    /// pair in row-major order (all layers of query 0, then all
    /// layers of query 1, …).
    ///
    /// Returns `None` if the buffer length doesn't match the declared
    /// `num_queries × num_fri_layers × FRI_LAYER_OPENING_LEN`. The
    /// pre-check in `from_bytes` makes this rare but keeps the
    /// Option as a belt-and-suspenders guard.
    pub fn fri_layer_opening_iter(
        &self,
    ) -> Option<impl Iterator<Item = (&'a [u8], &'a [u8])> + '_> {
        let expected = (self.num_queries as usize)
            * (self.num_fri_layers as usize)
            * FRI_LAYER_OPENING_LEN;
        if self.fri_layer_openings.len() != expected {
            return None;
        }
        Some(
            self.fri_layer_openings
                .chunks_exact(FRI_LAYER_OPENING_LEN)
                .map(|chunk| chunk.split_at(8)),
        )
    }

    /// Iterate FRI layer digests as 32-byte slices.
    pub fn fri_layer_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.fri_layer_commits.chunks_exact(sizes::DIGEST_LEN)
    }

    /// Iterate OOD evaluations as `field_elem_bytes`-sized slices.
    pub fn ood_evals_iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.ood_evals
            .chunks_exact(self.field_id.field_elem_bytes())
    }
}

/// Read a u32-length-prefixed variable section from the buffer. Advances
/// offset past the length prefix and the payload.
fn read_var_tail(
    bytes: &[u8],
    off: usize,
    max_len: u32,
) -> Result<(&[u8], usize), OnChainError> {
    if bytes.len() < off + 4 {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let len = u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]);
    if len > max_len {
        return Err(OnChainError::ProofLengthMismatch);
    }
    let len_usize = len as usize;
    let payload_start = off + 4;
    if bytes.len() < payload_start + len_usize {
        return Err(OnChainError::ProofLengthMismatch);
    }
    Ok((
        &bytes[payload_start..payload_start + len_usize],
        payload_start + len_usize,
    ))
}

/// FRI-STARK verifying key. Session 13b extension: now carries a
/// Goldilocks domain generator `omega_g` so the verifier can compute
/// per-query x-values `ω^query_idx` for the FRI fold chain walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriStarkVerifyingKey {
    /// Base field for this AIR.
    pub field_id: StarkFieldId,
    /// Number of columns in the execution trace.
    pub trace_width: u32,
    /// log₂ of the trace height (rows = 2^log_height).
    pub trace_log_height: u16,
    /// log₂ of the FRI blowup factor (domain size = trace × 2^log_blowup).
    pub log_blowup: u8,
    /// AIR (Algebraic Intermediate Representation) hash — uniquely
    /// identifies the constraint system this VK is for.
    pub air_hash: [u8; 32],
    /// Domain generator `ω` for the Goldilocks evaluation domain,
    /// encoded as 8-byte LE. Must be a primitive
    /// `2^(trace_log_height + log_blowup)`-th root of unity in
    /// Goldilocks. Used by the verifier to compute per-query x-values
    /// `x_q = ω^q` at FRI layer 0.
    ///
    /// For non-Goldilocks `field_id` variants, this slot carries a
    /// field-specific generator encoded per the field's canonical form.
    pub omega_g: [u8; 8],
}

impl FriStarkVerifyingKey {
    /// Canonical serialized length.
    pub const SERIALIZED_LEN: usize = 1 // field_id
        + 4 // trace_width
        + 2 // trace_log_height
        + 1 // log_blowup
        + 32 // air_hash
        + 8; // omega_g

    /// Decode from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OnChainError> {
        if bytes.len() != Self::SERIALIZED_LEN {
            return Err(OnChainError::VerifyingKeyLengthMismatch);
        }
        let field_id = StarkFieldId::from_byte(bytes[0])?;
        let trace_width = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let trace_log_height = u16::from_le_bytes([bytes[5], bytes[6]]);
        let log_blowup = bytes[7];
        let mut air_hash = [0u8; 32];
        air_hash.copy_from_slice(&bytes[8..40]);
        let mut omega_g = [0u8; 8];
        omega_g.copy_from_slice(&bytes[40..48]);
        Ok(Self {
            field_id,
            trace_width,
            trace_log_height,
            log_blowup,
            air_hash,
            omega_g,
        })
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SERIALIZED_LEN);
        out.push(self.field_id as u8);
        out.extend_from_slice(&self.trace_width.to_le_bytes());
        out.extend_from_slice(&self.trace_log_height.to_le_bytes());
        out.push(self.log_blowup);
        out.extend_from_slice(&self.air_hash);
        out.extend_from_slice(&self.omega_g);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use sizes::{DIGEST_LEN, FIXED_HEADER_LEN, POW_NONCE_LEN};

    /// Build a minimal well-formed STARK proof for decoder round-trip.
    fn proof_bytes(
        field_id: StarkFieldId,
        num_fri_layers: u8,
        num_queries: u16,
        trace_log_height: u16,
        trace_width: u32,
    ) -> Vec<u8> {
        let ood_bytes = 10 * field_id.field_elem_bytes();
        let final_bytes = 4 * field_id.field_elem_bytes();
        let query_bytes = (num_queries as usize) * 64;
        let fri_openings_bytes =
            (num_queries as usize) * (num_fri_layers as usize) * FRI_LAYER_OPENING_LEN;

        let total = FIXED_HEADER_LEN
            + 2 * DIGEST_LEN
            + (num_fri_layers as usize) * DIGEST_LEN
            + 4 + ood_bytes
            + 4 + final_bytes
            + 4 + query_bytes
            + 4 + fri_openings_bytes
            + 8 // final_layer_value
            + POW_NONCE_LEN;

        let mut buf = vec![0u8; total];
        buf[0] = field_id as u8;
        buf[1] = 1; // log_blowup
        buf[2] = num_fri_layers;
        buf[3] = 0; // pow_bits
        buf[4..6].copy_from_slice(&num_queries.to_le_bytes());
        buf[6..8].copy_from_slice(&trace_log_height.to_le_bytes());
        buf[8..12].copy_from_slice(&trace_width.to_le_bytes());

        let mut off = FIXED_HEADER_LEN + 2 * DIGEST_LEN + (num_fri_layers as usize) * DIGEST_LEN;
        buf[off..off + 4].copy_from_slice(&(ood_bytes as u32).to_le_bytes());
        off += 4 + ood_bytes;
        buf[off..off + 4].copy_from_slice(&(final_bytes as u32).to_le_bytes());
        off += 4 + final_bytes;
        buf[off..off + 4].copy_from_slice(&(query_bytes as u32).to_le_bytes());
        off += 4 + query_bytes;
        buf[off..off + 4].copy_from_slice(&(fri_openings_bytes as u32).to_le_bytes());
        off += 4 + fri_openings_bytes;
        // final_layer_value (8 bytes, left zero).
        off += 8;
        // pow nonce
        buf[off..off + POW_NONCE_LEN].copy_from_slice(&0xABCD_EF12_3456_7890u64.to_le_bytes());
        buf
    }

    #[test]
    fn proof_parses_typical_goldilocks_shape() {
        let buf = proof_bytes(StarkFieldId::Goldilocks, 16, 80, 16, 32);
        let p = FriStarkProof::from_bytes(&buf).unwrap();
        assert_eq!(p.field_id, StarkFieldId::Goldilocks);
        assert_eq!(p.num_fri_layers, 16);
        assert_eq!(p.num_queries, 80);
        assert_eq!(p.trace_width, 32);
        assert_eq!(p.fri_layer_iter().count(), 16);
        assert_eq!(p.ood_evals_iter().count(), 10);
        assert_eq!(p.pow_nonce, 0xABCD_EF12_3456_7890);
    }

    #[test]
    fn proof_parses_babybear_shape() {
        let buf = proof_bytes(StarkFieldId::BabyBear, 8, 40, 10, 8);
        let p = FriStarkProof::from_bytes(&buf).unwrap();
        assert_eq!(p.field_id, StarkFieldId::BabyBear);
        assert_eq!(p.field_id.field_elem_bytes(), 4);
    }

    #[test]
    fn proof_rejects_unknown_field_id() {
        let mut buf = proof_bytes(StarkFieldId::Goldilocks, 4, 10, 10, 4);
        buf[0] = 0xFF;
        assert!(matches!(
            FriStarkProof::from_bytes(&buf),
            Err(OnChainError::UnknownProofSystem),
        ));
    }

    #[test]
    fn proof_rejects_excessive_query_count() {
        // num_queries = MAX_QUERIES + 1
        let over = sizes::MAX_QUERIES + 1;
        let buf = proof_bytes(StarkFieldId::Goldilocks, 4, over, 10, 4);
        assert!(matches!(
            FriStarkProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_excessive_fri_layers() {
        let buf = proof_bytes(StarkFieldId::Goldilocks, sizes::MAX_FRI_LAYERS + 1, 10, 10, 4);
        assert!(matches!(
            FriStarkProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_trailing_garbage() {
        let mut buf = proof_bytes(StarkFieldId::Goldilocks, 4, 10, 10, 4);
        buf.push(0xDE);
        assert!(matches!(
            FriStarkProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_tail_over_cap() {
        let mut buf = proof_bytes(StarkFieldId::Goldilocks, 4, 10, 10, 4);
        // Overwrite first var-tail length prefix with max+1.
        let prefix_off = FIXED_HEADER_LEN + 2 * DIGEST_LEN + 4 * DIGEST_LEN;
        buf[prefix_off..prefix_off + 4]
            .copy_from_slice(&(sizes::MAX_TAIL_LEN + 1).to_le_bytes());
        assert!(matches!(
            FriStarkProof::from_bytes(&buf),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn proof_rejects_short_buffer() {
        let short = vec![0u8; FIXED_HEADER_LEN];
        assert!(matches!(
            FriStarkProof::from_bytes(&short),
            Err(OnChainError::ProofLengthMismatch),
        ));
    }

    #[test]
    fn vk_roundtrip() {
        let vk = FriStarkVerifyingKey {
            field_id: StarkFieldId::Goldilocks,
            trace_width: 32,
            trace_log_height: 16,
            log_blowup: 1,
            air_hash: [0xAA; 32],
            omega_g: [0xCD; 8],
        };
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), FriStarkVerifyingKey::SERIALIZED_LEN);
        let decoded = FriStarkVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, decoded);
    }

    #[test]
    fn vk_rejects_wrong_length() {
        let short = vec![0u8; FriStarkVerifyingKey::SERIALIZED_LEN - 1];
        assert!(matches!(
            FriStarkVerifyingKey::from_bytes(&short),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
        let long = vec![0u8; FriStarkVerifyingKey::SERIALIZED_LEN + 1];
        assert!(matches!(
            FriStarkVerifyingKey::from_bytes(&long),
            Err(OnChainError::VerifyingKeyLengthMismatch),
        ));
    }

    #[test]
    fn field_id_elem_widths() {
        assert_eq!(StarkFieldId::Goldilocks.field_elem_bytes(), 8);
        assert_eq!(StarkFieldId::BabyBear.field_elem_bytes(), 4);
        assert_eq!(StarkFieldId::Mersenne31.field_elem_bytes(), 4);
    }
}
