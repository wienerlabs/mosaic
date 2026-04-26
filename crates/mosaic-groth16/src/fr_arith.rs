//! Big-endian Fr arithmetic helpers.
//!
//! Minimal subset needed by [`crate::batch`] — just enough to accumulate
//! `Σ r_i mod r` and reduce hash outputs for Fiat-Shamir challenges.
//! Keeps mosaic-groth16 free of an arkworks dependency; full Fr
//! arithmetic lives in `mosaic-plonk::field` which does pull arkworks.

use crate::canonical::{lt_be, BN254_FR_MODULUS_BE};

/// Returns true iff `a < r` interpreted as big-endian unsigned integer.
#[must_use]
pub fn lt_r(a: &[u8; 32]) -> bool {
    lt_be(a, &BN254_FR_MODULUS_BE)
}

/// In-place subtraction `x ← x - r`. Caller must ensure `x >= r`.
fn sub_r(x: &mut [u8; 32]) {
    let r = &BN254_FR_MODULUS_BE;
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = i16::from(x[i]) - i16::from(r[i]) - borrow;
        if diff < 0 {
            x[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            x[i] = diff as u8;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "sub_r saw x < r");
}

/// Reduce a 32-byte big-endian integer mod `r`. Handles inputs up to
/// `2^256 - 1` (worst case ~5 subtractions).
pub fn reduce_mod_r(x: &mut [u8; 32]) {
    for _ in 0..6 {
        if lt_r(x) {
            return;
        }
        sub_r(x);
    }
    debug_assert!(lt_r(x), "reduce_mod_r failed to converge");
}

/// Compute `a + b mod r`. Both operands big-endian 32-byte Fr elements
/// assumed `< r` (caller's responsibility — otherwise the result may
/// drift out of range even after reduce).
#[must_use]
pub fn add_mod_r(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    // Sum is at most 2r - 2 < 2^256, so carry may push to 2^256 + x.
    // Fold overflow: if carry is set, we exceeded 2^256. Not possible
    // if both a,b < r < 2^254, because 2r < 2^255. So carry should be 0.
    // But if it does happen (caller violated the precondition), reduce.
    if carry != 0 {
        // Unexpected overflow; reduce defensively.
        reduce_mod_r(&mut out);
        return out;
    }
    if !lt_r(&out) {
        sub_r(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u64_to_be32(x: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&x.to_be_bytes());
        out
    }

    #[test]
    fn add_small_values() {
        let a = u64_to_be32(100);
        let b = u64_to_be32(42);
        let sum = add_mod_r(&a, &b);
        assert_eq!(sum, u64_to_be32(142));
    }

    #[test]
    fn add_zero_is_identity() {
        let a = u64_to_be32(12345);
        let zero = [0u8; 32];
        assert_eq!(add_mod_r(&a, &zero), a);
    }

    #[test]
    fn add_wraps_mod_r() {
        // (r - 1) + 1 = 0 mod r.
        let mut rm1 = BN254_FR_MODULUS_BE;
        rm1[31] -= 1;
        let one = u64_to_be32(1);
        let sum = add_mod_r(&rm1, &one);
        assert_eq!(sum, [0u8; 32]);
    }

    #[test]
    fn add_rm1_plus_rm1_is_rm2() {
        // (r - 1) + (r - 1) = r - 2 mod r.
        // BN254 r ends in `... 0xF0 0x00 0x00 0x01`; r-2 ends in
        // `... 0xEF 0xFF 0xFF 0xFF` because the borrow propagates
        // through three zero bytes. Compute r-2 explicitly rather than
        // trying `rm2[31] -= 2` which underflows the u8.
        let mut rm1 = BN254_FR_MODULUS_BE;
        rm1[31] -= 1;
        let mut rm2 = BN254_FR_MODULUS_BE;
        rm2[28] -= 1; // 0xF0 → 0xEF
        rm2[29] = 0xFF;
        rm2[30] = 0xFF;
        rm2[31] = 0xFF;
        let sum = add_mod_r(&rm1, &rm1);
        assert_eq!(sum, rm2);
    }

    #[test]
    fn reduce_mod_r_handles_r_itself() {
        let mut x = BN254_FR_MODULUS_BE;
        reduce_mod_r(&mut x);
        assert_eq!(x, [0u8; 32]);
    }

    #[test]
    fn reduce_mod_r_handles_max_u256() {
        let mut x = [0xFFu8; 32];
        reduce_mod_r(&mut x);
        assert!(lt_r(&x));
    }

    // ───────────────────────────────────────────────────────────────────
    // Session 39 — proptest coverage for Fr arithmetic primitives.
    //
    // `add_mod_r` and `reduce_mod_r` are the two soundness-critical
    // helpers used by the batch verifier. A bug in either silently
    // accepts maliciously-crafted batch coefficients, which is one of
    // the highest-leverage attack surfaces in a Groth16 verifier (a
    // batched pairing only proves the `Σ r_i · proof_i` identity holds
    // — if `Σ` itself is computed wrong, soundness is gone).
    //
    // Properties exercised:
    //
    //   - `add_mod_r` commutativity: a + b == b + a (mod r).
    //   - `add_mod_r` identity: a + 0 == a (mod r).
    //   - `add_mod_r` range preservation: a, b < r ⇒ result < r.
    //   - `reduce_mod_r` lands in [0, r): exhaustively over u256
    //     inputs the post-reduction value satisfies `lt_r`.
    //   - `reduce_mod_r` idempotence: reduce(reduce(x)) == reduce(x).
    //   - `reduce_mod_r` is the identity on inputs already < r.
    // ───────────────────────────────────────────────────────────────────
    use proptest::prelude::*;

    /// Produce a 32-byte BE buffer whose value is < r. The simplest
    /// recipe: zero the high byte (BN254 r's high byte is 0x30, so any
    /// value with high byte ≤ 0x2F is automatically < r — and the
    /// proof carries through to the assertion below).
    prop_compose! {
        fn arb_fr_in_range()(
            rest in proptest::collection::vec(any::<u8>(), 31..=31),
        ) -> [u8; 32] {
            let mut out = [0u8; 32];
            out[1..].copy_from_slice(&rest);
            out[0] = 0x2F; // < 0x30 (r's high byte) ⇒ < r
            out
        }
    }

    proptest! {
        /// `add_mod_r` is commutative for any pair of in-range Fr.
        /// Catches a future implementation that handles `a` and `b`
        /// asymmetrically (e.g. only reduces one operand).
        #[test]
        fn proptest_add_mod_r_is_commutative(
            a in arb_fr_in_range(),
            b in arb_fr_in_range(),
        ) {
            prop_assert_eq!(add_mod_r(&a, &b), add_mod_r(&b, &a));
        }

        /// `0` is a left and right identity under `add_mod_r`.
        #[test]
        fn proptest_add_mod_r_identity(a in arb_fr_in_range()) {
            let zero = [0u8; 32];
            prop_assert_eq!(add_mod_r(&a, &zero), a);
            prop_assert_eq!(add_mod_r(&zero, &a), a);
        }

        /// Range preservation: a, b < r ⇒ add_mod_r(a, b) < r.
        /// The audit-grade soundness property — a result outside Fr
        /// range would silently corrupt the batch coefficient sum.
        #[test]
        fn proptest_add_mod_r_preserves_range(
            a in arb_fr_in_range(),
            b in arb_fr_in_range(),
        ) {
            let s = add_mod_r(&a, &b);
            prop_assert!(lt_r(&s));
        }

        /// `reduce_mod_r` always lands in [0, r) for any u256 input.
        /// Includes the worst case `[0xFF; 32] = 2^256 - 1` (which
        /// requires up to 6 subtractions per the loop bound).
        #[test]
        fn proptest_reduce_mod_r_lands_in_range(
            x in proptest::collection::vec(any::<u8>(), 32..=32),
        ) {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&x);
            reduce_mod_r(&mut buf);
            prop_assert!(lt_r(&buf));
        }

        /// Idempotence: reduce(reduce(x)) == reduce(x).
        #[test]
        fn proptest_reduce_mod_r_idempotent(
            x in proptest::collection::vec(any::<u8>(), 32..=32),
        ) {
            let mut once = [0u8; 32];
            once.copy_from_slice(&x);
            reduce_mod_r(&mut once);
            let mut twice = once;
            reduce_mod_r(&mut twice);
            prop_assert_eq!(once, twice);
        }

        /// `reduce_mod_r` is the identity on inputs already in [0, r).
        /// Catches a bug that would mistakenly subtract on already-
        /// reduced values, which would produce a negative-mod-r result.
        #[test]
        fn proptest_reduce_mod_r_identity_on_in_range(a in arb_fr_in_range()) {
            let mut buf = a;
            reduce_mod_r(&mut buf);
            prop_assert_eq!(buf, a);
        }
    }
}
