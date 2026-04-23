//! Fiat-Shamir transcript for PLONK challenge derivation.
//!
//! ## Scheme
//!
//! PLONK follows the "fresh transcript per round" pattern (as implemented
//! by snarkjs 0.7.x): each round creates a transcript, absorbs the
//! relevant preceding challenges and commitments, and squeezes a single
//! challenge. We keep a single [`Transcript`] struct and expose
//! [`Transcript::reset`] to start a new round.
//!
//! ## Keccak-256 backend
//!
//! Challenges derived as:
//!
//! ```text
//! digest = keccak256(accumulated_bytes)
//! challenge = digest mod r          // r = BN254 scalar field order
//! ```
//!
//! The accumulated byte buffer uses the canonical Mosaic wire layout:
//! big-endian G1 (64 B), big-endian Fr (32 B). No length prefixes, no
//! domain tags per absorb — the order of absorbs is the contract, not
//! a self-describing format. Order is enforced by the verifier's
//! round-by-round code path.
//!
//! ## Poseidon-BN254 backend
//!
//! Tracked in issue #1; not wired in session 1. Circom-compatible
//! PLONK proofs use Poseidon; switching between backends is a
//! `match self.kind` on squeeze.

use crate::fr::{self, BN254_FR_MODULUS_BE};
use alloc::vec::Vec;
use mosaic_core::{syscall::SyscallBackend, OnChainError};

/// Transcript hash choice. Pick per circuit family:
///
/// - `Keccak256`: gnark / arkworks default; snarkjs PLONK default as of
///   snarkjs 0.7.x.
/// - `PoseidonBn254X5`: Circom-compatible PLONK and Halo2-KZG.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Keccak-256.
    Keccak256 = 0x02,
    /// Poseidon over BN254 scalar field, x⁵ S-box.
    PoseidonBn254X5 = 0x01,
}

/// Fiat-Shamir transcript for PLONK rounds.
///
/// Constructed per round; `reset` clears the accumulator so the next
/// round starts fresh.
pub struct Transcript<'b, B: SyscallBackend + ?Sized> {
    kind: Kind,
    backend: &'b B,
    accumulated: Vec<u8>,
}

impl<'b, B: SyscallBackend + ?Sized> Transcript<'b, B> {
    /// Construct a fresh transcript.
    #[must_use]
    pub fn new(kind: Kind, backend: &'b B) -> Self {
        Self { kind, backend, accumulated: Vec::with_capacity(256) }
    }

    /// Reset the accumulator without changing the kind or backend. Use
    /// between rounds to start a fresh transcript.
    pub fn reset(&mut self) {
        self.accumulated.clear();
    }

    /// Absorb raw bytes. Caller is responsible for serializing field
    /// elements and points in the canonical Mosaic wire layout
    /// (big-endian G1 64 B, big-endian Fr 32 B) before calling.
    pub fn absorb(&mut self, data: &[u8]) {
        self.accumulated.extend_from_slice(data);
    }

    /// Convenience: absorb a G1 affine point's 64-byte canonical form.
    pub fn absorb_g1(&mut self, point: &[u8]) -> Result<(), OnChainError> {
        if point.len() != 64 {
            return Err(OnChainError::InvalidPointEncoding);
        }
        self.absorb(point);
        Ok(())
    }

    /// Convenience: absorb a 32-byte Fr element. Caller is responsible
    /// for ensuring it's actually in range.
    pub fn absorb_fr(&mut self, fr_be: &[u8]) -> Result<(), OnChainError> {
        if fr_be.len() != 32 {
            return Err(OnChainError::InvalidFieldEncoding);
        }
        self.absorb(fr_be);
        Ok(())
    }

    /// Squeeze a 32-byte big-endian Fr element from the accumulated bytes.
    ///
    /// Does **not** reset the accumulator — the challenge is derived from
    /// the full accumulator, and the caller decides whether to continue
    /// absorbing into the same transcript or start fresh.
    pub fn get_challenge(&self) -> Result<[u8; 32], OnChainError> {
        let raw = match self.kind {
            Kind::Keccak256 => self.backend.keccak256(&[&self.accumulated])?,
            Kind::PoseidonBn254X5 => {
                // TODO(mosaic-001): Poseidon absorb pattern differs —
                // needs per-field-element input, not raw byte stream.
                // Session 2 wires this properly with a length-prefixed
                // absorb path.
                return Err(OnChainError::UnimplementedProofSystem);
            },
        };
        let mut challenge = raw;
        fr::reduce_mod_r(&mut challenge);
        debug_assert!(fr::lt_r(&challenge));
        Ok(challenge)
    }
}

/// Well-known 32-byte zero-valued Fr (neutral element of Fr addition).
/// Useful when the verifier needs to absorb a "no prior challenge" slot.
pub const FR_ZERO: [u8; 32] = [0u8; 32];

/// Well-known 32-byte big-endian encoding of `r - 1` (largest Fr element).
/// Exposed for tests and Lagrange-basis edge cases.
pub const FR_MINUS_ONE: [u8; 32] = {
    let mut out = BN254_FR_MODULUS_BE;
    // Subtract 1. The last byte of r is 0x01; after subtraction it becomes 0x00.
    out[31] -= 1;
    out
};

/// Derive a BN254 `Fr` challenge via a single keccak-256 round over a
/// domain-separator prefix followed by caller-supplied byte slices.
///
/// This is the one-shot equivalent of building a fresh [`Transcript`]
/// and absorbing one message — useful for auxiliary challenges that
/// sit outside the main round-based transcript (e.g. Halo2's `v`/`u`
/// batching challenges, Nova's Spartan-batching `v` challenge). Each
/// caller gets its own domain separator string so the derived values
/// can't collide across protocols even if their input bytes do.
///
/// The keccak output is reduced into Fr via
/// [`crate::field::fr_from_be_bytes_reduced`] — any 32-byte input
/// maps to a well-defined Fr element without retries.
///
/// ## Errors
///
/// - Propagates any backend error from
///   [`SyscallBackend::keccak256`] (typically
///   [`OnChainError::Keccak256SyscallFailed`]).
pub fn derive_fr_challenge<B: SyscallBackend + ?Sized>(
    backend: &B,
    domain: &[u8],
    inputs: &[&[u8]],
) -> Result<ark_bn254::Fr, OnChainError> {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(inputs.len() + 1);
    parts.push(domain);
    parts.extend_from_slice(inputs);
    let bytes = backend.keccak256(&parts)?;
    Ok(crate::field::fr_from_be_bytes_reduced(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend;

    impl SyscallBackend for MockBackend {
        fn alt_bn128_group_op(
            &self,
            _op: mosaic_core::syscall::AltBn128Op,
            _endianness: mosaic_core::syscall::InputEndianness,
            _input: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, OnChainError> {
            Err(OnChainError::UnsupportedOperation)
        }
        fn alt_bn128_compression(
            &self,
            _op: mosaic_core::syscall::AltBn128Compress,
            _input: &[u8],
        ) -> Result<alloc::vec::Vec<u8>, OnChainError> {
            Err(OnChainError::UnsupportedOperation)
        }
        fn poseidon(
            &self,
            _params: mosaic_core::syscall::PoseidonParameters,
            _endianness: mosaic_core::syscall::InputEndianness,
            _inputs: &[&[u8]],
        ) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::UnimplementedProofSystem)
        }
        fn sha256(&self, _inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            Err(OnChainError::Sha256SyscallFailed)
        }
        fn keccak256(&self, inputs: &[&[u8]]) -> Result<[u8; 32], OnChainError> {
            // Use tiny-keccak under test feature to avoid depending on
            // `host-backend` (which is `std`-only). Tests run on the host
            // where std is available, so we can just use tiny-keccak
            // through its transitive `mosaic-core` dev-dep.
            use tiny_keccak::{Hasher, Keccak};
            let mut h = Keccak::v256();
            for i in inputs {
                h.update(i);
            }
            let mut out = [0u8; 32];
            h.finalize(&mut out);
            Ok(out)
        }
    }

    #[test]
    fn fr_minus_one_is_less_than_r() {
        assert!(fr::lt_r(&FR_MINUS_ONE));
    }

    #[test]
    fn absorb_then_challenge_is_deterministic() {
        let backend = MockBackend;
        let mut t = Transcript::new(Kind::Keccak256, &backend);
        t.absorb(b"mosaic-plonk");
        let c1 = t.get_challenge().unwrap();
        let c2 = t.get_challenge().unwrap();
        assert_eq!(c1, c2, "identical transcript state must yield identical challenges");
    }

    #[test]
    fn different_absorbs_yield_different_challenges() {
        let backend = MockBackend;
        let mut t1 = Transcript::new(Kind::Keccak256, &backend);
        t1.absorb(b"foo");
        let c_foo = t1.get_challenge().unwrap();

        let mut t2 = Transcript::new(Kind::Keccak256, &backend);
        t2.absorb(b"bar");
        let c_bar = t2.get_challenge().unwrap();
        assert_ne!(c_foo, c_bar);
    }

    #[test]
    fn reset_clears_accumulator() {
        let backend = MockBackend;
        let mut t = Transcript::new(Kind::Keccak256, &backend);
        t.absorb(b"round-1-data");
        let c_before = t.get_challenge().unwrap();
        t.reset();
        t.absorb(b"round-1-data"); // identical bytes → identical challenge
        let c_after = t.get_challenge().unwrap();
        assert_eq!(c_before, c_after);
    }

    #[test]
    fn challenge_is_always_in_fr_range() {
        let backend = MockBackend;
        // Try many different absorbed inputs and confirm the challenge
        // reduction lands us in [0, r).
        for seed in 0u64..50 {
            let mut t = Transcript::new(Kind::Keccak256, &backend);
            t.absorb(&seed.to_be_bytes());
            let c = t.get_challenge().unwrap();
            assert!(fr::lt_r(&c), "challenge >= r for seed {seed}");
        }
    }

    #[test]
    fn absorb_g1_length_check() {
        let backend = MockBackend;
        let mut t = Transcript::new(Kind::Keccak256, &backend);
        let bad = [0u8; 63];
        assert!(matches!(
            t.absorb_g1(&bad),
            Err(OnChainError::InvalidPointEncoding),
        ));
    }

    #[test]
    fn poseidon_kind_returns_unimplemented_session_1() {
        let backend = MockBackend;
        let mut t = Transcript::new(Kind::PoseidonBn254X5, &backend);
        t.absorb(b"whatever");
        assert!(matches!(
            t.get_challenge(),
            Err(OnChainError::UnimplementedProofSystem),
        ));
    }

    #[test]
    fn challenge_matches_direct_keccak_then_reduce() {
        // Oracle: compute the expected challenge via direct tiny-keccak
        // + manual reduce_mod_r, compare to transcript output.
        let backend = MockBackend;
        let data = b"mosaic-plonk-oracle-test";
        let mut t = Transcript::new(Kind::Keccak256, &backend);
        t.absorb(data);
        let got = t.get_challenge().unwrap();

        use tiny_keccak::{Hasher, Keccak};
        let mut h = Keccak::v256();
        h.update(data);
        let mut expected = [0u8; 32];
        h.finalize(&mut expected);
        fr::reduce_mod_r(&mut expected);
        assert_eq!(got, expected);
    }

    // ---- derive_fr_challenge ----

    #[test]
    fn derive_fr_challenge_is_deterministic() {
        let backend = MockBackend;
        let a = derive_fr_challenge(
            &backend,
            b"mosaic-test/v",
            &[b"seed-1", b"seed-2"],
        )
        .unwrap();
        let b = derive_fr_challenge(
            &backend,
            b"mosaic-test/v",
            &[b"seed-1", b"seed-2"],
        )
        .unwrap();
        assert_eq!(a, b, "same inputs must yield same challenge");
    }

    #[test]
    fn derive_fr_challenge_differs_on_different_domains() {
        // Domain-separation is the whole point of the prefix —
        // changing the domain must re-roll the challenge even when
        // the rest of the inputs are identical. Otherwise Halo2's
        // `v` and `u` could collide in pathological inputs.
        let backend = MockBackend;
        let v = derive_fr_challenge(&backend, b"halo2/v", &[b"same"]).unwrap();
        let u = derive_fr_challenge(&backend, b"halo2/u", &[b"same"]).unwrap();
        assert_ne!(
            v, u,
            "distinct domains must yield distinct challenges"
        );
    }

    #[test]
    fn derive_fr_challenge_differs_on_different_inputs() {
        let backend = MockBackend;
        let a = derive_fr_challenge(&backend, b"d", &[b"a"]).unwrap();
        let b = derive_fr_challenge(&backend, b"d", &[b"b"]).unwrap();
        assert_ne!(a, b, "different inputs must yield different challenges");
    }
}
