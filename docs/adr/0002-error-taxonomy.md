# ADR-0002 — Two-layer error taxonomy

* **Status:** Accepted (2026-04-19)
* **Deciders:** Mosaic core team
* **References:** [SIMD-0129](https://github.com/solana-foundation/solana-improvement-documents/pull/129) (consensus-failure incident from non-deterministic error returns)

## Context

Solana is a state machine: every validator independently re-executes every
transaction and must agree byte-for-byte on the result. If two validator
implementations (Agave, Firedancer, Jito-Solana) return different
`ProgramError` codes for the same input, the network forks. SIMD-0129
documents a real incident where this exact failure mode brought consensus
to a halt.

Off-chain consumers — SDKs, indexers, test harnesses — want richer
information than a bare numeric code: the byte buffer that failed to parse,
the expected vs actual length, the underlying arkworks error, the file path
of the fixture. None of that information can reach on-chain code.

## Decision

Mosaic implements a **two-layer error model**:

### Layer 1 — `OnChainError` (deterministic, on-chain)

A `#[repr(u32)]`, `#[non_exhaustive]` enum whose discriminants are part of
the public ABI. Maps to `ProgramError::Custom(code as u32)`.

- Discriminants are organized into ranges:
  - `0x0001..0x000F` input format errors
  - `0x0010..0x001F` proof-system selection
  - `0x0020..0x002F` verification failure
  - `0x0030..0x003F` chunked-upload protocol
  - `0x0040..0x004F` syscall surface
  - `0x0050..0x005F` resource limits
  - `0x00FF` catch-all `InternalInvariantViolation`
- Adding a variant appends at the next free discriminant; existing
  discriminants never change.
- Each variant has a **stable slug** for indexer parsing
  (`pairing_check_failed`, `chunk_overflow`, …).

### Layer 2 — `DiagnosticError` (off-chain, feature-gated)

A `thiserror::Error` enum behind the `std` feature. Carries free-form
context, expected/actual lengths, structured arkworks errors. Every variant
collapses to an `OnChainError` via `into_onchain()`, so the off-chain layer
can never violate the on-chain contract.

`MosaicError` is a type alias resolving to the diagnostic layer in `std`
builds and to the on-chain layer in `no_std`.

## Consequences

**Positive**:

- On-chain code paths are auditable: a small, finite enum of error codes,
  with no string formatting and no opaque error chains.
- Consensus determinism is enforced by the type system — you cannot
  accidentally surface a `DiagnosticError` from a `solana-program` entry
  point because the program's `ProgramResult` type rejects it.
- Off-chain consumers get rich errors without burdening on-chain code.
- Indexers can parse stable slugs without mapping numeric codes by hand.

**Negative**:

- Two error types means more boilerplate at the host/program boundary
  (every host-side error must be projected via `into_onchain()` before
  surfacing to a `ProgramResult`).
- Stability promise on discriminants forecloses future re-numbering for
  cleanliness.

## Stability

`OnChainError` discriminants follow the same stability rules as the wire
format: never change an existing value; only append. Renaming a variant or
removing one requires an ADR amendment, an `AUDIT.md` entry, and a
**protocol-version bump**.

## Validation

`mosaic_core::error::tests::discriminant_stability` pins the discriminants
of the four most load-bearing variants. Any change to those values fails
CI; adding new variants does not.
