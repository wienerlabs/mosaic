//! Big-endian Fr-range helpers for PLONK challenge derivation.
//!
//! PLONK's Fiat-Shamir challenges are reduced mod the BN254 scalar field
//! order `r`. Full Fr arithmetic (mul, add, inv) requires arkworks, which
//! Phase-2 session 2 will pull into the `solana` feature. This session 1
//! module provides only the *range* operations — check in-range and
//! reduce mod-r — that keyword Phase-2 session 1 transcript work needs
//! without any field-arithmetic dependency.

/// Fr element byte length (BN254 scalar field, 32 bytes).
pub const FR_LEN: usize = 32;

/// BN254 scalar field order `r` in big-endian.
///
/// `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
pub const BN254_FR_MODULUS_BE: [u8; FR_LEN] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Big-endian unsigned-integer comparison over 32-byte slices.
/// Returns true iff `a < b`.
#[must_use]
pub fn lt_be(a: &[u8; FR_LEN], b: &[u8; FR_LEN]) -> bool {
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return x < y;
        }
    }
    false
}

/// Returns true iff `a` is a valid Fr element (0 ≤ a < r).
#[must_use]
pub fn lt_r(a: &[u8; FR_LEN]) -> bool {
    lt_be(a, &BN254_FR_MODULUS_BE)
}

/// Reduce a 32-byte big-endian integer mod r, in place.
///
/// Hash outputs are ≤ 2^256 - 1 and r ≈ 0.74 × 2^253, so the quotient
/// `floor(hash / r)` is at most `ceil(2^256 / r) = 5`. We subtract r up
/// to 5 times (guarded with an explicit upper bound) to land in [0, r).
///
/// This is **not** a constant-time reduction — callers should not supply
/// secret witness data. PLONK Fiat-Shamir challenges are public so this
/// is appropriate here; anywhere else, route through arkworks Fr.
pub fn reduce_mod_r(x: &mut [u8; FR_LEN]) {
    // At most 5 subtractions suffice for 256-bit input / 253-bit modulus.
    for _ in 0..6 {
        if lt_r(x) {
            return;
        }
        sub_r(x);
    }
    // Defence in depth — an infinite loop here would be a bug.
    debug_assert!(lt_r(x), "reduce_mod_r failed to converge");
}

/// In-place big-endian subtraction `x ← x - r`. Panics in debug builds if
/// `x < r` (the caller should have already returned in that case).
///
/// Session-31 cast-safety rewrite: the previous implementation used
/// `i16` arithmetic with `as u8` truncation which flagged 4 clippy
/// `cast_possible_truncation` / `cast_sign_loss` warnings. Every branch
/// was provably in u8 range, but the casts were opaque to static
/// analysis. Replaced with the canonical `overflowing_sub` borrow-
/// chain pattern — no intermediate `i16` widening, no `as` casts,
/// and the borrow flag arithmetic is pure `bool` → `u8`.
fn sub_r(x: &mut [u8; FR_LEN]) {
    let r = &BN254_FR_MODULUS_BE;
    let mut borrow_in: u8 = 0;
    for i in (0..FR_LEN).rev() {
        let (partial, b1) = x[i].overflowing_sub(r[i]);
        let (result, b2) = partial.overflowing_sub(borrow_in);
        x[i] = result;
        // borrow_out is set if either step wrapped. Both bools
        // promote to 0 / 1; bit-OR collapses to a single borrow flag.
        borrow_in = u8::from(b1) | u8::from(b2);
    }
    debug_assert_eq!(borrow_in, 0, "sub_r called when x < r");
}

/// Parse a big-endian byte slice into an exactly-FR_LEN array, checking
/// the value is a valid Fr element. Returns the parsed array or an error.
///
/// # Errors
///
/// - [`mosaic_core::OnChainError::InvalidFieldEncoding`] — input slice
///   length is not exactly `FR_LEN` (32) bytes.
/// - [`mosaic_core::OnChainError::PublicInputOutOfRange`] — decoded
///   value is `>= r` (BN254 scalar-field modulus).
pub fn parse_fr_be(bytes: &[u8]) -> Result<[u8; FR_LEN], mosaic_core::OnChainError> {
    if bytes.len() != FR_LEN {
        return Err(mosaic_core::OnChainError::InvalidFieldEncoding);
    }
    let mut out = [0u8; FR_LEN];
    out.copy_from_slice(bytes);
    if !lt_r(&out) {
        return Err(mosaic_core::OnChainError::PublicInputOutOfRange);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_r_is_not_less_than_r() {
        assert!(!lt_r(&BN254_FR_MODULUS_BE));
    }

    #[test]
    fn r_minus_one_is_less_than_r() {
        let mut rm1 = BN254_FR_MODULUS_BE;
        rm1[FR_LEN - 1] -= 1;
        assert!(lt_r(&rm1));
    }

    #[test]
    fn reduce_mod_r_is_identity_on_in_range() {
        let mut x = [0u8; FR_LEN];
        x[FR_LEN - 1] = 7;
        let expected = x;
        reduce_mod_r(&mut x);
        assert_eq!(x, expected);
    }

    #[test]
    fn reduce_mod_r_handles_r_itself() {
        let mut x = BN254_FR_MODULUS_BE;
        reduce_mod_r(&mut x);
        assert_eq!(x, [0u8; FR_LEN]);
    }

    #[test]
    fn reduce_mod_r_handles_r_plus_1() {
        let mut x = BN254_FR_MODULUS_BE;
        x[FR_LEN - 1] = x[FR_LEN - 1].wrapping_add(1); // r + 1 (no carry since last byte = 0x01)
        reduce_mod_r(&mut x);
        let mut expected = [0u8; FR_LEN];
        expected[FR_LEN - 1] = 1;
        assert_eq!(x, expected);
    }

    #[test]
    fn reduce_mod_r_handles_max_u256() {
        let mut x = [0xFFu8; FR_LEN];
        reduce_mod_r(&mut x);
        assert!(lt_r(&x));
    }

    #[test]
    fn reduce_mod_r_always_lands_in_range() {
        // Property test: apply reduce_mod_r to 200 different seeded inputs;
        // each result must be in [0, r). Covers inputs from tiny to near-2^256.
        for seed in 0u64..200 {
            let mut x = [0u8; FR_LEN];
            // Spread the seed across all 32 bytes so different seeds exercise
            // different reduce paths (single subtraction, 2-3 subtractions).
            for (i, byte) in x.iter_mut().enumerate() {
                *byte = ((seed.wrapping_mul(7).wrapping_add(i as u64)) & 0xFF) as u8;
            }
            // Force the high byte high some of the time to hit the
            // multi-subtraction path.
            if seed % 3 == 0 {
                x[0] = 0xE0;
            }
            reduce_mod_r(&mut x);
            assert!(lt_r(&x), "seed {seed}: result >= r");
        }
    }

    #[test]
    fn reduce_mod_r_is_idempotent() {
        // Applying reduce twice must match applying once.
        let mut x = [0xDEu8; FR_LEN];
        reduce_mod_r(&mut x);
        let once = x;
        reduce_mod_r(&mut x);
        assert_eq!(x, once);
    }

    #[test]
    fn parse_fr_be_rejects_wrong_length() {
        let short = [0u8; FR_LEN - 1];
        assert!(parse_fr_be(&short).is_err());
    }

    #[test]
    fn parse_fr_be_rejects_out_of_range() {
        let r = BN254_FR_MODULUS_BE;
        assert!(parse_fr_be(&r).is_err());
    }

    #[test]
    fn parse_fr_be_accepts_valid() {
        let mut v = [0u8; FR_LEN];
        v[FR_LEN - 1] = 42;
        let parsed = parse_fr_be(&v).unwrap();
        assert_eq!(parsed, v);
    }

    // ---- Property-based tests (session 34) ----
    //
    // The hand-rolled borrow-chain arithmetic in `sub_r` and
    // `reduce_mod_r` resists ordinary unit tests — correctness
    // depends on cross-byte borrow propagation, which is easy to
    // get wrong at boundary values. `proptest` samples across the
    // entire 32-byte input space and shrinks failing cases so a
    // regression gets a minimal repro automatically.

    use proptest::prelude::*;

    /// Strategy: any 32-byte value (not necessarily in field range).
    fn any_32_bytes() -> impl Strategy<Value = [u8; FR_LEN]> {
        proptest::array::uniform32(any::<u8>())
    }

    /// Strategy: a 32-byte value guaranteed to be strictly less than
    /// the BN254 Fr modulus. We pick arbitrary bytes and then reduce
    /// once — reduce is the operation under test, but lt_r is an
    /// independent primitive (table comparison) we trust.
    fn in_range_32_bytes() -> impl Strategy<Value = [u8; FR_LEN]> {
        any_32_bytes().prop_map(|mut b| {
            reduce_mod_r(&mut b);
            b
        })
    }

    proptest! {
        /// After `reduce_mod_r`, the result must be strictly less
        /// than `r`. Holds for any 32-byte input (including the
        /// all-ones upper bound at `2^256 − 1`).
        #[test]
        fn prop_reduce_mod_r_lands_in_range(bytes in any_32_bytes()) {
            let mut x = bytes;
            reduce_mod_r(&mut x);
            prop_assert!(lt_r(&x), "reduce_mod_r produced out-of-range value: {x:?}");
        }

        /// Reducing a value that's already in range must be the
        /// identity operation — no mutation beyond the initial lt_r
        /// short-circuit.
        #[test]
        fn prop_reduce_mod_r_is_idempotent(bytes in in_range_32_bytes()) {
            let mut once = bytes;
            reduce_mod_r(&mut once);
            let mut twice = once;
            reduce_mod_r(&mut twice);
            prop_assert_eq!(once, twice);
            // Also: reducing an in-range value doesn't mutate it.
            prop_assert_eq!(bytes, once);
        }

        /// `parse_fr_be` accepts any in-range 32-byte input and
        /// round-trips the bytes verbatim.
        #[test]
        fn prop_parse_fr_be_round_trips_in_range(bytes in in_range_32_bytes()) {
            let parsed = parse_fr_be(&bytes).expect("in-range input must parse");
            prop_assert_eq!(parsed, bytes);
        }

        /// Session-31 borrow-chain invariant: `sub_r(r + delta) =
        /// delta` for any in-range `delta`. We construct `x = r +
        /// delta` by adding delta to r byte-by-byte with carry (also
        /// hand-rolled), then call sub_r and check the result equals
        /// delta. Catches any off-by-one in the borrow propagation.
        ///
        /// Scope: delta ∈ [0, 2^64 − 1] (u64 fits in the low 8 bytes,
        /// avoids complex carry cases in the addition helper while
        /// still exercising sub_r's full 32-byte sweep).
        #[test]
        fn prop_sub_r_recovers_delta(delta_lo in any::<u64>()) {
            let mut delta_be = [0u8; FR_LEN];
            delta_be[24..32].copy_from_slice(&delta_lo.to_be_bytes());
            if !lt_r(&delta_be) {
                // Skip the u64 value wrapping above r (very rare
                // because r ≈ 2^253, but proptest will still try it
                // occasionally).
                return Ok(());
            }
            let mut x = BN254_FR_MODULUS_BE;
            // x += delta_be (add with carry, big-endian).
            let mut carry: u16 = 0;
            for i in (0..FR_LEN).rev() {
                let sum = u16::from(x[i]) + u16::from(delta_be[i]) + carry;
                x[i] = (sum & 0xff) as u8;
                carry = sum >> 8;
            }
            prop_assert_eq!(carry, 0, "r + delta (delta < r) must not overflow 32 bytes");
            // Now sub_r(x) must recover delta_be exactly.
            sub_r(&mut x);
            prop_assert_eq!(x, delta_be);
        }
    }
}
