# ADR-0003 — Serialization strategy and canonical wire format

* **Status:** Accepted (2026-04-19)
* **Deciders:** Mosaic core team

## Context

Each upstream proving framework — `snarkjs`, `arkworks`, `gnark`,
`halo2-kzg`, `plonky3`, `risc0` — emits proofs and verifying keys in its
own native byte layout. Endianness, field-element packing, point
compression, and IC-vector framing all differ.

The on-chain verifier consumes a single canonical layout per proof system.
Doing the conversion on-chain would burn compute units linearly with
proof size; doing it client-side adds zero CU and is straightforward.

A separate question: should canonical layout be **big-endian** (matches the
current `sol_alt_bn128_group_op` syscall) or **little-endian** (matches
arkworks native + the future SIMD-0204 syscall)?

## Decision

### Conversion happens off-chain

All format conversion — snarkjs JSON, arkworks canonical, gnark binary,
etc. — happens in `mosaic-serde` on the client side. The on-chain
`mosaic-program` accepts only canonical bytes and rejects malformed input
with an `InvalidPointEncoding` error.

### Canonical layout is big-endian (today)

Canonical bytes are big-endian to match the current
`sol_alt_bn128_group_op` syscall convention. The verifier accepts a
`LE_INPUTS` const generic (`Groth16Verifier<B, LE_INPUTS>`); when SIMD-0204
activates and flips the syscall to little-endian, the dispatcher will swap
the const generic to `true` without changing call sites.

### Canonical Groth16 layout

| Artifact | Layout |
|---|---|
| `Groth16Proof` | `A (G1, 64B) ‖ B (G2, 128B) ‖ C (G1, 64B)` = 256 B |
| `Groth16VerifyingKey` | `α (G1, 64B) ‖ β (G2, 128B) ‖ γ (G2, 128B) ‖ δ (G2, 128B) ‖ IC[…]` |
| G1 point | `x (32B BE) ‖ y (32B BE)` |
| G2 point | `x.c1 (32B BE) ‖ x.c0 ‖ y.c1 ‖ y.c0` (Solana convention) |
| `Fr` element | `32B BE` (big-endian unsigned integer < `r`) |

The G2 `c1‖c0` ordering follows the Solana syscall, which differs from
arkworks (`c0‖c1`). Adapters perform the swap.

### Adapter trait

`mosaic_core::ProofCodec` is the contract:

```rust
pub trait ProofCodec {
    fn format(&self) -> FormatTag;
    fn decode_proof(&self, src: &[u8]) -> Result<Vec<u8>, OnChainError>;
    fn decode_vk(&self, src: &[u8]) -> Result<Vec<u8>, OnChainError>;
    fn decode_public_inputs(&self, src: &[u8]) -> Result<Vec<u8>, OnChainError>;
}
```

Adapters live in `mosaic-serde` (one module per format).

## Consequences

**Positive**:

- Zero on-chain CU spent on format translation.
- Canonical layout is wire-stable — versioned by `FormatTag::Canonical`
  rather than re-derived.
- Adding a framework adapter is a self-contained module with its own
  fixtures and tests; no core changes.
- The `LE_INPUTS` const generic is forward-compatible with SIMD-0204 — no
  breaking change when the syscall flips endianness.

**Negative**:

- Every framework added means another adapter to maintain and audit. Phase 1
  ships only `snarkjs` + `arkworks`; gnark/halo2/plonky3/risc0 are stubs.
- The G2 byte ordering differs from upstream arkworks output, which is a
  common source of confusion (and the canonical bug source of "my proof
  verifies in arkworks but not on-chain"). Adapters handle this; SDK
  `preflight()` catches it before paying for the failed transaction.

## Stability

`FormatTag` discriminants are wire-stable. Canonical Groth16 byte layout is
wire-stable until/unless a SIMD activation forces a change (e.g. SIMD-0204
LE inputs, SIMD-0233 native G2). Phase-1 canonical bytes are big-endian;
the eventual switch to LE will be coordinated with the syscall flip and
gated behind a `LE_INPUTS = true` dispatch path so existing on-chain VKs
remain verifiable during the transition.
