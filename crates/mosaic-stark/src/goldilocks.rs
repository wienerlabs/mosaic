//! Goldilocks field arithmetic (`p = 2^64 − 2^32 + 1`).
//!
//! The Goldilocks prime is Plonky3's default small-prime field: small
//! enough to fit in a single `u64`, large enough that its extensions
//! support a 128-bit security target. This module implements the
//! minimal arithmetic set the FRI-STARK verifier needs to close the
//! remaining scaffold caveats:
//!
//! - **Per-FRI-layer fold consistency**
//!   `f_{i+1}(x²) = (f(x) + f(-x))/2 + β · (f(x) − f(-x))/(2x)`
//! - **Out-of-domain quotient consistency**
//!   `constraint(z) == Σ α^i · quotient_i(z)`
//!
//! Both reduce to sequences of add / sub / mul / inverse over Fp_Goldilocks.
//!
//! ## Canonical form + reduction
//!
//! Every [`Goldilocks`] value is canonical — i.e., in `[0, p)`. The
//! invariant is restored at every arithmetic step. `p = 2^64 − 2^32 + 1`
//! (fits just below `u64::MAX`), so:
//!
//! - Addition: `u64` add with one modular correction.
//! - Subtraction: `u64` sub with one modular correction.
//! - Multiplication: promote to `u128`, reduce via standard modulo.
//!   The `u128 % p` operation on SBF compiles to a sequence of u64
//!   arithmetic via Solana's built-in `__umodti3`; CU cost is TBD
//!   and measured in session 11's FRI-layer bench.
//! - Inversion: Fermat's little theorem, `x^(p − 2)`, via square-and-
//!   multiply over the 64-bit exponent.
//!
//! ## Endianness
//!
//! Plonky3 and Winterfell both serialize Goldilocks as **little-endian**
//! 8-byte values. This module matches that convention; callers parse
//! transcript-derived field elements via [`Goldilocks::from_bytes_le`].

use mosaic_core::OnChainError;

/// Goldilocks prime: `p = 2^64 − 2^32 + 1`.
///
/// `= 18_446_744_069_414_584_321` decimal.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Goldilocks field element in canonical form `[0, p)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Goldilocks(u64);

impl Goldilocks {
    /// Additive identity (0).
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Multiplicative identity (1).
    #[must_use]
    pub const fn one() -> Self {
        Self(1)
    }

    /// Construct from a `u64`, reducing if out of canonical range.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        if v >= P {
            Self(v - P)
        } else {
            Self(v)
        }
    }

    /// Raw inner value. For testing + serialization.
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Decode from 8 little-endian bytes with range validation.
    ///
    /// ## Errors
    ///
    /// Returns [`OnChainError::PublicInputOutOfRange`] if the decoded
    /// value is `>= p` — consensus-critical so divergent inputs
    /// can't produce different field elements on different clients.
    pub fn from_bytes_le(bytes: &[u8; 8]) -> Result<Self, OnChainError> {
        let v = u64::from_le_bytes(*bytes);
        if v >= P {
            return Err(OnChainError::PublicInputOutOfRange);
        }
        Ok(Self(v))
    }

    /// Encode as 8 little-endian bytes (canonical).
    #[must_use]
    pub fn to_bytes_le(&self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Addition in Fp_Goldilocks.
    #[must_use]
    pub const fn add(self, other: Self) -> Self {
        // a + b may overflow u64 if a, b close to p; use u128 to be safe.
        let sum = (self.0 as u128) + (other.0 as u128);
        let p = P as u128;
        let r = if sum >= p { sum - p } else { sum };
        Self(r as u64)
    }

    /// Subtraction in Fp_Goldilocks.
    #[must_use]
    pub const fn sub(self, other: Self) -> Self {
        if self.0 >= other.0 {
            Self(self.0 - other.0)
        } else {
            // Wrap via modulus: (self + p) - other.
            Self(P - (other.0 - self.0))
        }
    }

    /// Additive inverse `-x = p − x`.
    #[must_use]
    pub const fn neg(self) -> Self {
        if self.0 == 0 {
            Self(0)
        } else {
            Self(P - self.0)
        }
    }

    /// Multiplication in Fp_Goldilocks via u128 expansion + modulo.
    #[must_use]
    pub fn mul(self, other: Self) -> Self {
        let prod = (self.0 as u128) * (other.0 as u128);
        let reduced = prod % (P as u128);
        Self(reduced as u64)
    }

    /// Modular inverse via Fermat's little theorem: `x^(p − 2)`.
    ///
    /// Returns `None` if `self == 0` (zero has no multiplicative
    /// inverse). Otherwise the returned value satisfies
    /// `self.mul(self.inverse().unwrap()) == Goldilocks::one()`.
    ///
    /// ## Performance note
    ///
    /// This uses square-and-multiply over `p − 2`, which requires up
    /// to 64 iterations each with one multiplication. Per-call cost
    /// is therefore `O(log p) ≈ 64 × cost(mul)`. For the FRI-layer
    /// fold inverses there's one per layer; session 11 may want to
    /// batch via Montgomery's trick if we see CU pressure.
    #[must_use]
    pub fn inverse(self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        // Exponent = p − 2. Compute via right-to-left square-and-multiply.
        let exponent = P - 2;
        let mut result = Self::one();
        let mut base = self;
        let mut exp = exponent;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_zero() {
        assert_eq!(Goldilocks::zero().as_u64(), 0);
    }

    #[test]
    fn one_is_one() {
        assert_eq!(Goldilocks::one().as_u64(), 1);
    }

    #[test]
    fn new_reduces_large_values() {
        // Value >= p should reduce by subtracting p once.
        let v = Goldilocks::new(P);
        assert_eq!(v.as_u64(), 0);
        let v = Goldilocks::new(P + 1);
        assert_eq!(v.as_u64(), 1);
    }

    #[test]
    fn from_bytes_le_round_trip() {
        for v in [0u64, 1, 2, 100, P - 1] {
            let bytes = v.to_le_bytes();
            let decoded = Goldilocks::from_bytes_le(&bytes).unwrap();
            assert_eq!(decoded.as_u64(), v);
            assert_eq!(decoded.to_bytes_le(), bytes);
        }
    }

    #[test]
    fn from_bytes_le_rejects_out_of_range() {
        // P is exactly out of range.
        let bytes = P.to_le_bytes();
        assert!(matches!(
            Goldilocks::from_bytes_le(&bytes),
            Err(OnChainError::PublicInputOutOfRange),
        ));
        // u64::MAX definitely is.
        let bytes = u64::MAX.to_le_bytes();
        assert!(matches!(
            Goldilocks::from_bytes_le(&bytes),
            Err(OnChainError::PublicInputOutOfRange),
        ));
    }

    #[test]
    fn add_wraps_at_modulus() {
        let a = Goldilocks::new(P - 1);
        let b = Goldilocks::one();
        // (p - 1) + 1 = p ≡ 0.
        assert_eq!(a.add(b), Goldilocks::zero());
    }

    #[test]
    fn add_commutes() {
        let a = Goldilocks::new(7);
        let b = Goldilocks::new(11);
        assert_eq!(a.add(b), b.add(a));
    }

    #[test]
    fn sub_wraps_at_zero() {
        // 0 - 1 = p - 1.
        let r = Goldilocks::zero().sub(Goldilocks::one());
        assert_eq!(r.as_u64(), P - 1);
    }

    #[test]
    fn sub_add_round_trip() {
        let a = Goldilocks::new(1234567);
        let b = Goldilocks::new(987654);
        let diff = a.sub(b);
        let recovered = diff.add(b);
        assert_eq!(recovered, a);
    }

    #[test]
    fn neg_is_additive_inverse() {
        for v in [0u64, 1, 42, 1_000_000, P - 1] {
            let a = Goldilocks::new(v);
            let neg_a = a.neg();
            assert_eq!(a.add(neg_a), Goldilocks::zero(), "v={v}");
        }
    }

    #[test]
    fn mul_commutes() {
        let a = Goldilocks::new(7);
        let b = Goldilocks::new(11);
        assert_eq!(a.mul(b), b.mul(a));
        assert_eq!(a.mul(b).as_u64(), 77);
    }

    #[test]
    fn mul_by_zero_is_zero() {
        let a = Goldilocks::new(123);
        assert_eq!(a.mul(Goldilocks::zero()), Goldilocks::zero());
    }

    #[test]
    fn mul_by_one_is_identity() {
        let a = Goldilocks::new(42);
        assert_eq!(a.mul(Goldilocks::one()), a);
    }

    #[test]
    fn mul_distributes_over_add() {
        let a = Goldilocks::new(3);
        let b = Goldilocks::new(5);
        let c = Goldilocks::new(7);
        // a * (b + c) == a*b + a*c.
        let lhs = a.mul(b.add(c));
        let rhs = a.mul(b).add(a.mul(c));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn mul_large_values_reduce() {
        // (p-1) * 2 = 2p - 2 ≡ p - 2 mod p.
        let a = Goldilocks::new(P - 1);
        let two = Goldilocks::new(2);
        let r = a.mul(two);
        assert_eq!(r.as_u64(), P - 2);
    }

    #[test]
    fn inverse_of_zero_is_none() {
        assert!(Goldilocks::zero().inverse().is_none());
    }

    #[test]
    fn inverse_of_one_is_one() {
        assert_eq!(Goldilocks::one().inverse().unwrap(), Goldilocks::one());
    }

    #[test]
    fn inverse_round_trip_small_values() {
        // x * x^(-1) == 1 for small x.
        for v in [2u64, 3, 5, 7, 11, 13, 17, 42, 1234] {
            let x = Goldilocks::new(v);
            let inv = x.inverse().unwrap();
            let product = x.mul(inv);
            assert_eq!(product, Goldilocks::one(), "v={v}");
        }
    }

    #[test]
    fn inverse_round_trip_large_values() {
        // x * x^(-1) == 1 for values near p.
        for v in [P - 1, P - 2, P - 100, P / 2, P / 3] {
            let x = Goldilocks::new(v);
            let inv = x.inverse().unwrap();
            let product = x.mul(inv);
            assert_eq!(product, Goldilocks::one(), "v={v}");
        }
    }

    #[test]
    fn inverse_of_neg_is_neg_of_inverse() {
        // (-x)^(-1) == -(x^(-1)) since (-1)^(-1) = -1.
        for v in [2u64, 13, 1000] {
            let x = Goldilocks::new(v);
            let inv = x.inverse().unwrap();
            let neg_inv = inv.neg();
            let neg_x_inv = x.neg().inverse().unwrap();
            assert_eq!(neg_x_inv, neg_inv, "v={v}");
        }
    }
}
