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
use mosaic_core::OnChainError;

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
        if lookup_arity >= 2 && n_advice < 2 * lookup_arity {
            return Err(OnChainError::ProofLengthMismatch);
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
