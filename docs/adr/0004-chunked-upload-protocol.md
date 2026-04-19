# ADR-0004 — Chunked proof upload protocol

* **Status:** Accepted (2026-04-19)
* **Deciders:** Mosaic core team
* **Implementation:** `crates/mosaic-chunked` (data model + handler signatures only in Phase 1; logic tracked by TODO(mosaic-006))

## Context

A single Solana transaction caps instruction data at **1232 bytes**. Groth16
proofs (256 B) fit easily; verifying keys with many public inputs are the
edge case but still typically fit. The picture changes for larger systems:

| System | Typical proof size | Fits in 1232 B? |
|---|---|---|
| Groth16 BN254 | 256 B | yes |
| KZG-PLONK BN254 | 1.5–4 KB | no |
| Halo2-KZG | 2–8 KB | no |
| FRI-STARK (Plonky3) | 50–200 KB | no |
| Risc0 receipt | 200–500 KB | no |

For phase 2/3 systems we need a way to upload large proofs across multiple
transactions, then verify atomically.

## Decision

A **chunked-upload protocol** built on a session PDA with a **rolling-hash
commitment** binding chunk order and total length.

### Session PDA

Derived from `[b"mosaic-session", session_id]`. Stores:

```rust
pub struct ProofUploadSession {
    pub session_id: [u8; 32],
    pub total_len: u32,
    pub appended_len: u32,
    pub chunks_committed: u16,
    pub rolling_hash: [u8; 32],
    pub finalized: bool,
    pub proof_system_id: u8,
    pub assembled: Vec<u8>,
}
```

### Instruction set

| Tag | Name | Effect |
|---|---|---|
| `0x10` | `InitializeSession(session_id, total_len, proof_system_id, h_0)` | Create PDA, store seed `h_0 = SHA256(DOMAIN_TAG ‖ session_id ‖ total_len_le)`. |
| `0x11` | `AppendChunk(chunk_index, bytes)` | Append `bytes` (≤800 B), update `rolling_hash = SHA256(rolling_hash ‖ bytes)`. |
| `0x12` | `CommitAndVerify(vk, public_inputs, expected_final_hash)` | Mark finalized, dispatch verifier. |
| `0x13` | `CancelSession()` | Refund rent, drop session. |

### Rolling-hash binding

```text
h_0     = SHA256(DOMAIN_TAG ‖ session_id ‖ total_len_le)
h_{i+1} = SHA256(h_i ‖ chunk_i_bytes)
```

The client precommits the final `h_n` in `CommitAndVerify`. Mismatch yields
`ChunkCommitmentMismatch` and the session aborts.

### Determinism

Rolling-hash uses `solana_program::hash::hashv` (the SHA-256 syscall), which
is consensus-deterministic. The `DOMAIN_TAG = b"mosaic-chunked01"` is
versioned; bumping the tag invalidates all in-flight sessions and requires
an `AUDIT.md` entry.

## Consequences

**Positive**:

- Supports arbitrary-size proofs limited only by the requested heap frame
  (max 256 KiB) and the PDA storage budget.
- Adversarial reordering is detected by the rolling-hash mismatch.
- Session abandonment is cheap — `CancelSession` refunds rent.
- Domain-separated hash prevents cross-protocol replay.

**Negative**:

- Multi-transaction overhead: a 200 KB STARK proof requires ~250
  `AppendChunk` transactions. Each costs base transaction fee + rent.
  Acceptable for high-value verifications, painful for batched workloads.
- The PDA grows with the proof; storage rent scales with size. Long-running
  sessions accrue rent until `CommitAndVerify` or `CancelSession`.
- Phase-1 ships data model only; instruction handlers are TODO(mosaic-006).

## Alternatives considered

- **Address Lookup Tables (ALT)**: hold proof bytes in account data,
  reference via ALT. Rejected: ALT is for `AccountMeta` lists, not
  arbitrary data; would require a separate "data oracle" account model.
- **State compression / Merkle trees**: rejected as overkill — proofs are
  written-once / read-once, not log-shaped.
- **Direct upload via large transaction packs**: Solana's 1232 B limit is a
  validator policy, not a protocol limit, but raising it requires a SIMD.
  Out of scope.

## Stability

`ChunkedInstructionTag` discriminants are wire-stable. `DOMAIN_TAG` change
requires protocol-version bump. PDA seed prefix `b"mosaic-session"` is
wire-stable.
