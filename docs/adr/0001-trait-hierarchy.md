# ADR-0001 — Trait hierarchy and dispatch model

* **Status:** Accepted (2026-04-19)
* **Deciders:** Mosaic core team
* **Consulted:** Solana ZK ecosystem maintainers (informal)

## Context

Mosaic must verify proofs from at least eight upstream proving systems
(Groth16, KZG-PLONK, HyperPlonk, Halo2-KZG, FRI-STARK, Risc0, Nova, ProtoStar).
On-chain code must dispatch from a single instruction handler to the right
verifier based on a wire-format selector byte. The library also needs to be
useful off-chain for SDK pre-flight, batch verifiers, and fuzz harnesses.

The two natural Rust patterns are:

1. **Monomorphized match**: hand-write a `match id { 1 => groth16::verify(..) }`
   in the dispatcher, with each verifier exposed as a free function. Maximum
   speed, smallest indirection, but every new system requires editing the
   dispatcher and every consumer must re-derive the match.
2. **`dyn ProofSystem`**: object-safe trait, dispatcher works against
   `&dyn ProofSystem` or a hash-keyed registry. New systems plug in without
   touching the dispatcher.

There is also a parametric variant — a `ProofSystem` trait with associated
types `Proof`, `VerifyingKey`, `PublicInputs` — but associated types break
object safety, which we want to retain for off-chain tooling.

## Decision

Mosaic adopts a **hybrid** model:

- The `mosaic_core::ProofSystem` trait is **object-safe**: methods take
  `&[u8]` byte slices, not associated types. Concrete verifier crates
  layer typed wrappers (`Groth16Proof<'a>`, `Groth16VerifyingKey`) on top
  of the byte API in their own modules.
- The on-chain dispatcher in `mosaic-program` uses a **monomorphized match**
  over `ProofSystemId` for minimal CU cost and an audit-friendly handler.
- Off-chain consumers (SDK, fuzz harnesses, batch verifiers) can store
  `Box<dyn ProofSystem>` in a registry and dispatch dynamically.

The trait surface is:

```rust
pub trait ProofSystem: Send + Sync {
    fn proof_system_id(&self) -> ProofSystemId;
    fn verify(&self, vk: &[u8], proof: &[u8], public_inputs: &[u8]) -> Result<(), OnChainError>;
    fn estimated_compute_units(&self, vk: &[u8], proof: &[u8]) -> Option<u32>;
    fn batch_verify(&self, vk: &[u8], proofs: &[&[u8]], public_inputs: &[&[u8]]) -> Result<(), OnChainError>;
}
```

The `SyscallBackend` abstraction (see `mosaic_core::syscall`) is **not**
part of this hierarchy — it lives one level lower so that verifier code
can be shared between host and SBF unmodified.

## Consequences

**Positive**:

- Adding a new proving system requires only: a new crate, a new
  `ProofSystemId` discriminant, and a new dispatcher arm. No core trait
  changes.
- Object safety lets us iterate `Box<dyn ProofSystem>` in tests and the SDK.
- Byte-slice API matches the wire format directly — fewer translation layers,
  fewer places for serialization bugs.

**Negative**:

- The dispatcher is monomorphized — adding a system requires editing
  `mosaic-program/src/lib.rs`. Tracked via this ADR rather than treated
  as a library defect.
- Typed `Proof`/`VerifyingKey` wrappers live in concrete crates and don't
  share a common trait. Users who want a strongly-typed API across systems
  must compose their own facade.
- Default `batch_verify` falls back to looped single verification.
  System-specific MSM amortization requires an override (see TODO(mosaic-005)).

## Stability

Breaking changes to the `ProofSystem` trait require an ADR amendment and a
major-version bump. Adding a `ProofSystemId` variant is **not** breaking —
the enum is `#[non_exhaustive]`.
