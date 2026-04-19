# Design 0001 — Chunked Upload Instruction Handlers

* **Status:** Draft (2026-04-19)
* **Authors:** Mosaic core team
* **Implements:** [ADR-0004](../adr/0004-chunked-upload-protocol.md)
* **Tracking issue:** [#6](https://github.com/wienerlabs/mosaic/issues/6)
* **Audience:** Implementer, reviewers, audit firm

This document is the implementation contract for `mosaic-chunked` and the
chunked-session arms of `mosaic-program`. It locks the state machine, PDA
layout, wire format, rent model, DoS surface, and determinism audit before
any handler code is written.

If a question is not answered here, it is **out of scope** for the first
implementation pass. Open questions are listed at the bottom of the
document; they must be resolved (PR amendment to this doc) before the
ambiguity is encoded into runtime behaviour.

---

## 1. Scope and goals

### In scope
- On-chain instruction handlers for `InitializeSession`, `AppendChunk`,
  `CommitAndVerify`, `CancelSession`, and `CancelExpiredSession`.
- Session PDA account layout and rent model.
- Rolling-hash commitment protocol with explicit security reduction.
- DoS surface analysis with concrete mitigations.

### Out of scope
- Verifier integration internals (covered by per-system docs).
- SDK-side helpers for assembling chunked-upload transactions
  (covered by `mosaic-sdk` issue [#23](https://github.com/wienerlabs/mosaic/issues/23)).
- Cross-program-invocation (CPI) ergonomics from caller programs
  (covered by issue [#39](https://github.com/wienerlabs/mosaic/issues/39)
  singleton-vs-library discussion).

### Non-goals
- Streaming verification (chunks verified incrementally during upload).
  We commit fully before verifying. Streaming is a different protocol.
- Cross-session aggregation. Each session verifies one proof.

---

## 2. State machine

### 2.1 States

```
                        ┌──────────────┐
                        │ Uninitialized│
                        │ (no PDA)     │
                        └──────┬───────┘
                               │ InitializeSession
                               ▼
                        ┌──────────────┐
              ┌─────────│    Open      │◀────────┐
              │         │ accepting    │         │ AppendChunk
              │         │ chunks       │─────────┘ (chunks_committed < N)
              │         └──────┬───────┘
              │                │ CommitAndVerify
   CancelSession                ▼ (or rolling-hash mismatch)
              │         ┌──────────────┐
              │         │   Sealed     │
              │         │ rolling hash │
              │         │ matches      │
              │         └──────┬───────┘
              │                │
              │                │ verifier.verify(...)
              │                ▼
              │         ┌──────────────┐    ┌──────────────┐
              │   ┌─────│   Verified   │    │   Failed     │─────┐
              │   │     │ (closed,     │    │ (kept until  │     │ CancelSession
              │   │     │ rent refund) │    │ user cancels)│     │
              │   │     └──────────────┘    └──────────────┘     │
              │   │                                              │
              ▼   ▼                                              ▼
        ┌────────────────────────────────────────────────────────┐
        │                    Cancelled                           │
        │           (rent refunded, account closed)              │
        └────────────────────────────────────────────────────────┘
```

### 2.2 Transition table

| From | Instruction | To | Side effects |
|---|---|---|---|
| Uninitialized | `InitializeSession` | Open | PDA created; initial state stored; rent paid by signer. |
| Open | `AppendChunk` (next index, valid len) | Open | `assembled` extended; `rolling_hash` updated; counters incremented. |
| Open | `AppendChunk` (last chunk, fills to total_len) | Open (with `appended_len == total_len`) | Same as above; next valid call is `CommitAndVerify`. |
| Open | `CommitAndVerify` (all chunks present, hash matches) | Sealed → Verified | Verifier dispatched; on success, account closed and lamports returned to signer. |
| Open | `CommitAndVerify` (hash mismatch) | Open (handler returns `ChunkCommitmentMismatch`) | No state change; caller can `CancelSession`. |
| Sealed | (instantaneous) | Verified or Failed | Set by verifier outcome inside the same instruction. |
| Verified | (terminal) | — | Account already closed in same instruction. |
| Failed | `CancelSession` | Cancelled | Rent refunded. |
| Open | `CancelSession` | Cancelled | Rent refunded. |
| Any | `CancelExpiredSession` (after expiry slot) | Cancelled | Rent refunded to **session.payer** (not the canceller); permissionless. |

### 2.3 Invariants

These hold across every transition:

1. `appended_len ≤ total_len`. Violation → `ChunkOverflow`.
2. `chunks_committed * CHUNK_SIZE ≥ appended_len`.
3. `finalized == true` iff state is Sealed, Verified, or Failed.
4. `assembled.len() == appended_len` at all times.
5. PDA's lamports balance ≥ rent-exempt minimum until the terminating
   transition (Verified close, or CancelSession close).
6. `rolling_hash` reflects exactly the bytes appended so far, in order.

### 2.4 Sealed is an instantaneous state

In runtime there is no "sealed but not yet verified" account written to
chain. `CommitAndVerify` runs all of (rolling-hash check → verifier
dispatch → close-or-mark-failed) in a single instruction. The Sealed
state exists in the diagram only to make the transition logic explicit.

---

## 3. PDA seed scheme

### 3.1 Seeds

```rust
let seeds = &[
    b"mosaic-session",       // domain prefix
    session_id.as_ref(),     // 32-byte client nonce
    payer_pubkey.as_ref(),   // 32-byte signer pubkey
    &[bump],                 // canonical bump
];
```

The PDA address is derived via
`Pubkey::find_program_address(&seeds[..3], &PROGRAM_ID)`; the canonical
bump is stored in the session account so subsequent instructions can
reproduce the address without re-running the (expensive) `find_program_address`
search.

### 3.2 Why bind to payer?

Without `payer_pubkey` in the seeds:

- Adversary watches mempool for `InitializeSession(session_id=X)`.
- Submits their own `InitializeSession(X)` first with crafted parameters.
- Honest user's transaction reverts with "PDA already exists".
- Honest user picks a new `session_id`, retries — adversary repeats.

This is a classic **front-running griefing vector**. Binding the payer
pubkey into the seeds means each user's session-id namespace is private:
two users with the same `session_id` produce different PDAs and don't
collide.

### 3.3 Why include `session_id` if payer alone uniquifies?

A single payer may have many concurrent sessions (bulk uploads, retries
after `CancelSession`). The `session_id` differentiates them within the
payer's namespace.

### 3.4 Collision resistance

PDA derivation is SHA-256-based and assumes no preimage attack on
SHA-256. The output space is 2²⁵⁶ minus the rejection set (off-curve
points are rejected and re-rolled with the bump). For all practical
purposes, no two distinct `(session_id, payer)` pairs produce the same
PDA address.

---

## 4. Rolling-hash protocol

### 4.1 Construction

```text
DOMAIN_TAG = b"mosaic-chunked01"          // 16 bytes, version-locked

h_0     = SHA256( DOMAIN_TAG  ‖ session_id ‖ total_len_le ‖ proof_system_id )
h_{i+1} = SHA256( h_i         ‖ chunk_i_bytes )
```

The client precommits `h_n` (where `n = chunks_committed` after the
final chunk) in `CommitAndVerify`. The handler asserts
`computed_h_n == provided_h_n` and rejects with `ChunkCommitmentMismatch`
on inequality.

### 4.2 What this binds

- **Chunk content**: any altered byte changes `h_n`.
- **Chunk order**: swapping two chunks changes `h_n`.
- **Total length**: declared `total_len` is in `h_0`; mismatched declared
  vs. actual length changes `h_n`.
- **Session id**: prevents cross-session replay.
- **Proof system**: prevents bytes destined for one verifier being
  redirected to another.
- **Domain tag**: prevents cross-protocol replay (e.g. another protocol
  using SHA-256 over similar bytes).

### 4.3 Security reduction

**Claim.** Any adversary that produces a different chunk sequence
`(chunk'_0, …, chunk'_n)` whose rolling hash matches an honest
`h_n` either:

1. Found a SHA-256 second-preimage (assumed cryptographically intractable
   under standard hardness assumptions; equivalent to breaking the
   security of Bitcoin block headers and Solana's own state hash), or
2. Used identical bytes in identical order (which is not an attack — it's
   submitting the same proof).

**Game.** Adversary supplies `chunks'`, hash chain produces `h'_n`.
Adversary wins if `h'_n == h_n` and `chunks' != chunks`. Reduction
collapses to second-preimage at the first `i` where `chunk'_i != chunk_i`:
two distinct preimages of `SHA256(h_{i-1} ‖ chunk_i)` and
`SHA256(h_{i-1} ‖ chunk'_i)` collide, contradicting SHA-256 second-preimage
resistance.

### 4.4 DOMAIN_TAG versioning

Bumping `DOMAIN_TAG = b"mosaic-chunked01"` to `mosaic-chunked02`
invalidates all in-flight sessions: old `h_0` values won't match new
ones. This is the migration mechanism for any future change to the hash
construction (e.g. switching to Poseidon for cheaper on-chain transcript
operations).

Bump procedure documented in section 11.

---

## 5. Instruction wire format

All instructions are tagged with a single discriminator byte at offset 0.
Tags are wire-stable; see ADR-0002 for the stability contract.

### 5.1 `InitializeSession` (tag `0x10`)

```
Offset  Bytes  Field
0       1      tag (= 0x10)
1       32     session_id
33      4      total_len (u32 LE)
37      1      proof_system_id (ProofSystemId discriminant)
38      32     h_0 (precomputed by client)
```

**Accounts:**

| # | Pubkey | Writable | Signer | Notes |
|---|---|---|---|---|
| 0 | `payer` | Yes | Yes | Pays rent + tx fee. |
| 1 | `session_pda` | Yes | No | Will be initialized to size = base + total_len. |
| 2 | `system_program` | No | No | For account creation CPI. |

**Behaviour:**

1. Derive expected PDA from (session_id, payer); reject if account 1
   pubkey doesn't match.
2. Reject if `session_pda` already initialized
   (`SessionAlreadyInitialized`, code 0x35 — new variant).
3. Compute rent-exempt lamports for `BASE_SIZE + total_len`.
4. CPI `system_program::create_account` with payer paying.
5. Write `ProofUploadSession` initial state.

**Constraints:**

- `total_len ≥ 1` (zero-length proof rejected).
- `total_len ≤ MAX_PROOF_LEN` (currently `256 KiB - BASE_SIZE` ≈ 262 000).
- `proof_system_id` must be a known discriminant (validated via
  `ProofSystemId::from_byte`).

### 5.2 `AppendChunk` (tag `0x11`)

```
Offset  Bytes     Field
0       1         tag (= 0x11)
1       2         chunk_index (u16 LE) — for the handler to assert ordering
3       2         chunk_len (u16 LE) — bounded by CHUNK_SIZE
5       chunk_len chunk_bytes
```

**Accounts:**

| # | Pubkey | Writable | Signer | Notes |
|---|---|---|---|---|
| 0 | `payer` | No | Yes | Must equal `session.payer`. |
| 1 | `session_pda` | Yes | No | Existing initialized session. |

**Behaviour:**

1. Deserialize `session_pda` data.
2. Reject if `session.payer != accounts[0].key` (`SessionContextMismatch`).
3. Reject if `session.finalized` (`SessionAlreadyFinalized`).
4. Reject if `chunk_index != session.chunks_committed` (`ChunkOutOfOrder`).
5. Reject if `chunk_len > CHUNK_SIZE` (`ChunkOverflow`).
6. Reject if `session.appended_len + chunk_len > session.total_len`
   (`ChunkOverflow`).
7. Compute `next_hash = sol_sha256(session.rolling_hash ‖ chunk_bytes)`.
8. Append to `assembled`; update counters.
9. Write back.

### 5.3 `CommitAndVerify` (tag `0x12`)

```
Offset  Bytes  Field
0       1      tag (= 0x12)
1       32     expected_final_hash (precommitted h_n)
5       4      vk_account_offset (u32 LE) — index into accounts list
9       2      public_inputs_len (u16 LE)
11      pi_len public_inputs_bytes
```

**Accounts:**

| # | Pubkey | Writable | Signer | Notes |
|---|---|---|---|---|
| 0 | `payer` | Yes | Yes | Receives lamports refund on success. |
| 1 | `session_pda` | Yes | No | Existing session, must be Open. |
| N | `vk_account` | No | No | Account holding canonical-format VK bytes; index given by `vk_account_offset`. |

VK lives in a separate account because typical VKs are 1–4 KB —
embedding in the instruction data may not fit alongside chunks.

**Behaviour:**

1. Validate session ownership (as in `AppendChunk` step 2).
2. Reject if `session.appended_len != session.total_len`
   (`ChunkCommitmentMismatch`).
3. Reject if `session.rolling_hash != expected_final_hash`
   (`ChunkCommitmentMismatch`).
4. Mark `session.finalized = true`. (Defence-in-depth — even if verifier
   panics, the session can't be reused.)
5. Read VK bytes from `accounts[vk_account_offset]`.
6. Dispatch verifier on `(vk_bytes, session.assembled, public_inputs_bytes)`.
7. **On verifier success**: close session_pda, return all lamports to
   payer. Emit log `mosaic: chunked verify ok session=<id>`.
8. **On verifier failure**: write back with the verifier's error code
   stashed in a new field (`last_verify_error: u32`). Account remains
   open so user can `CancelSession` to recover rent. Log
   `mosaic: chunked verify failed session=<id> error=<code>`.

### 5.4 `CancelSession` (tag `0x13`)

```
Offset  Bytes  Field
0       1      tag (= 0x13)
```

**Accounts:**

| # | Pubkey | Writable | Signer | Notes |
|---|---|---|---|---|
| 0 | `payer` | Yes | Yes | Receives lamports refund. |
| 1 | `session_pda` | Yes | No | Existing session, any state. |

**Behaviour:**

1. Validate session ownership.
2. Close session_pda (zero data, transfer lamports to payer).

No state-machine restrictions: cancellable from Open or Failed. (Verified
sessions are already closed in step 5.3.7.)

### 5.5 `CancelExpiredSession` (tag `0x14`) — permissionless GC

```
Offset  Bytes  Field
0       1      tag (= 0x14)
```

**Accounts:**

| # | Pubkey | Writable | Signer | Notes |
|---|---|---|---|---|
| 0 | `caller` | No | Yes | Anyone. |
| 1 | `session_pda` | Yes | No | Existing session. |

**Behaviour:**

1. Read `session.expires_at_slot` (new field, see § 6).
2. Reject if `Clock::get()?.slot < session.expires_at_slot`
   (`SessionNotExpired` — new variant 0x36).
3. Close session_pda; **return lamports to `session.payer`**, not the
   caller. Caller pays only the transaction fee.

This makes garbage collection a public good: anyone can clean up
abandoned sessions without ability to redirect the rent.

---

## 6. Rent and storage cost model

### 6.1 Account layout

```rust
pub struct ProofUploadSession {
    pub session_id:        [u8; 32],   // 32
    pub payer:             Pubkey,     // 32
    pub bump:              u8,         //  1
    pub proof_system_id:   u8,         //  1
    pub total_len:         u32,        //  4
    pub appended_len:      u32,        //  4
    pub chunks_committed:  u16,        //  2
    pub finalized:         bool,       //  1
    pub last_verify_error: u32,        //  4 — 0 means none
    pub created_at_slot:   u64,        //  8
    pub expires_at_slot:   u64,        //  8 — created + EXPIRY_SLOTS
    pub rolling_hash:      [u8; 32],   // 32
    pub _reserved:         [u8; 39],   // 39 — future-compat padding
    // —— total: 168 bytes BASE_SIZE
    pub assembled:         Vec<u8>,    // total_len bytes (variable)
}
```

`BASE_SIZE = 168` bytes (with Borsh framing add ~8 bytes for the Vec
length prefix).

### 6.2 Rent

PDA must be rent-exempt for its full size. At Solana's current rent rate
(~6.96 SOL per MB-year), a 200 KB session costs ~0.0014 SOL =
~$0.014–0.42 depending on SOL price.

`InitializeSession` pays this; `CancelSession` / `CancelExpiredSession` /
successful `CommitAndVerify` refunds it.

### 6.3 Per-chunk transaction fees

Each `AppendChunk` is one transaction. At the current default fee of
5_000 lamports + priority fee (variable):

- 200 KB proof / 800 B per chunk = 250 chunks.
- 250 × 5_000 = 1_250_000 lamports = 0.00125 SOL minimum.
- Plus priority fees during congestion.

This is an acceptable cost for STARK / Risc0 use cases (single
verification per session). For workloads needing many small proofs,
Groth16 with single-tx upload is the right tool.

### 6.4 EXPIRY_SLOTS constant

Default `EXPIRY_SLOTS = 432_000` (≈ 48 hours at 400ms slots). Sessions
not finalized within this window become eligible for permissionless
cancellation. This bounds the worst-case rent that any single payer can
keep in flight.

The constant is compile-time. Changing it requires a protocol-version
bump (existing sessions retain their original `expires_at_slot`, so the
change is forward-compatible).

---

## 7. Concurrent session limits and DoS protection

### 7.1 Threat surface

| # | Attack | Mitigation |
|---|---|---|
| D-1 | Adversary creates many tiny sessions, exhausting their own SOL — but they want to grief the *payer*. | Sessions are bound to `payer`; only the adversary's own SOL is at risk. Not Mosaic's problem. |
| D-2 | Adversary creates session with `total_len = MAX`, never finalizes, locks rent. | `EXPIRY_SLOTS` bounds the lock to 48h. After expiry, anyone calls `CancelExpiredSession` and rent refunds to the payer. |
| D-3 | Adversary uploads max chunks then never `CommitAndVerify`. | Same as D-2. |
| D-4 | Adversary submits valid bytes with mismatched hash, forcing handler work. | One SHA-256 op per chunk (~2_000 CU). Adversary pays the tx fee for nothing. Rate-limited by their own SOL. |
| D-5 | Adversary fills assembled buffer with adversarial bytes that make the verifier hot path expensive. | Per-system CU budgets (ADR-0005). Verifier rejects with bounded CU regardless of input. |
| D-6 | Adversary creates millions of sessions to fill Solana validator state. | This is a Solana-wide concern; mitigated by Solana's account rent economics, not Mosaic. |
| D-7 | Adversary front-runs `InitializeSession` to grief honest user's chosen `session_id`. | Mitigated by binding payer to PDA seeds (§ 3.2). |
| D-8 | Adversary calls `CancelExpiredSession` *before* expiry to grief honest user. | Reject if `slot < expires_at_slot` (§ 5.5 step 2). |
| D-9 | Adversary submits chunks out of order to confuse handler state. | `chunk_index != session.chunks_committed` rejected (§ 5.2 step 4). |
| D-10 | Replay attack: adversary captures honest `CommitAndVerify` and submits again. | Solana's blockhash + nonce mechanism prevents transaction replay at the runtime level. Per-session: account is closed on success, so replay would fail "account does not exist". |

### 7.2 Per-payer concurrent session limit?

**Decision: no hard limit in Phase 1.** Rationale:

- Each session costs the payer rent up front. SOL economics naturally
  cap concurrent sessions per payer.
- A hard limit (say, max 16 concurrent) would require a separate
  per-payer counter PDA, doubling on-chain state per session.
- If we observe abuse in production, add the limit later via protocol
  bump.

This decision is revisited if the audit firm flags it as a concern.

---

## 8. Failure modes and error mapping

Every reachable error returns a deterministic `OnChainError`. The table
below is the complete enumeration; any reachable code path not in this
table is a bug.

| Where | Cause | `OnChainError` |
|---|---|---|
| `InitializeSession` | `total_len == 0` | `ProofLengthMismatch` |
| `InitializeSession` | `total_len > MAX_PROOF_LEN` | `ChunkOverflow` |
| `InitializeSession` | unknown `proof_system_id` | `UnknownProofSystem` |
| `InitializeSession` | PDA already initialized | `SessionAlreadyInitialized` (new, 0x35) |
| `AppendChunk` | wrong payer | `SessionContextMismatch` |
| `AppendChunk` | session finalized | `SessionAlreadyFinalized` |
| `AppendChunk` | wrong chunk_index | `ChunkOutOfOrder` |
| `AppendChunk` | chunk_len > CHUNK_SIZE | `ChunkOverflow` |
| `AppendChunk` | overflow against total_len | `ChunkOverflow` |
| `AppendChunk` | sha256 syscall fails | `Sha256SyscallFailed` |
| `CommitAndVerify` | wrong payer | `SessionContextMismatch` |
| `CommitAndVerify` | length mismatch | `ChunkCommitmentMismatch` |
| `CommitAndVerify` | hash mismatch | `ChunkCommitmentMismatch` |
| `CommitAndVerify` | unknown VK account | `InvalidPointEncoding` (re-uses code) |
| `CommitAndVerify` | verifier returns error | passes through verifier's error |
| `CancelSession` | wrong payer | `SessionContextMismatch` |
| `CancelExpiredSession` | not expired | `SessionNotExpired` (new, 0x36) |
| Any | malformed instruction data | `InternalInvariantViolation` (handler bug) |

### 8.1 New `OnChainError` variants required

These need to land in `mosaic-core::error::OnChainError` before
implementation:

```rust
SessionAlreadyInitialized = 0x35,
SessionNotExpired         = 0x36,
```

Adding these does not break ABI (they fall in the chunked-upload
0x30..0x3F range with previously-reserved space). `discriminant_stability`
test must be extended to pin them.

---

## 9. Determinism audit

Per ADR-0002, every reachable code path on-chain must be deterministic
across Agave / Firedancer / Jito-Solana validator implementations.

| Path | Sources of non-determinism | Mitigation |
|---|---|---|
| `InitializeSession` | `Clock::get()?` for `created_at_slot` | Clock is a sysvar; identical across validators. |
| `InitializeSession` | Rent-exempt calculation | Uses `Rent::get()?` sysvar; identical. |
| `AppendChunk` | `sol_sha256` syscall | Deterministic by spec. |
| `AppendChunk` | Vec growth allocation | Bounded by `total_len` declared at init; allocator is deterministic for fixed sizes. |
| `CommitAndVerify` | Verifier dispatch | Verifier crates carry their own determinism contract. |
| `CommitAndVerify` | Lamport refund math | `checked_sub` / `checked_add`; deterministic. |
| `CancelExpiredSession` | `Clock::get()?` for slot comparison | Same as init. |

**Validator-divergence test plan**: post-implementation, run the same
adversarial fixture suite against Agave and Firedancer (when Firedancer
ships local-test-validator). Any divergence in returned error codes is a
P0 bug.

---

## 10. CU budget targets

| Instruction | Target CU | Notes |
|---|---|---|
| `InitializeSession` | ≤ 25_000 | Account creation CPI dominates. |
| `AppendChunk` | ≤ 10_000 | One sha256 syscall + memcpy. |
| `CommitAndVerify` (Groth16) | ≤ 200_000 | 5_000 (chunked overhead) + 195_000 (verifier). |
| `CommitAndVerify` (PLONK) | ≤ 620_000 | 5_000 + 615_000. |
| `CommitAndVerify` (STARK) | ≤ 14_000_000 | Requires `set_compute_unit_limit(14M)` from caller. |
| `CancelSession` | ≤ 5_000 | Account close. |
| `CancelExpiredSession` | ≤ 7_000 | Account close + slot comparison. |

These targets land in `bpf-bench` thresholds (see issue
[#13](https://github.com/wienerlabs/mosaic/issues/13)).

---

## 11. Migration path: bumping `DOMAIN_TAG`

If we ever change the rolling-hash construction (e.g. switching SHA-256
to Poseidon for cheaper transcript operations once issue
[#8](https://github.com/wienerlabs/mosaic/issues/8) lands):

1. Bump `DOMAIN_TAG` from `mosaic-chunked01` to `mosaic-chunked02`.
2. New sessions use the new tag. Old in-flight sessions will fail
   verification (their `h_0` was computed against the old tag).
3. Notify dApp authors via `AUDIT.md` entry + breaking-change PR label.
4. Provide a 30-day grace window: handler accepts both tags, prefers
   new. After grace, remove old-tag support.

This procedure is explicit so we don't accidentally hard-fork in-flight
proofs without warning.

---

## 12. Open questions (must be resolved before implementation)

### Q1. Should `InitializeSession` reserve `total_len` bytes upfront, or grow `assembled` per-chunk?

**Trade-off**: upfront is simpler and avoids realloc cost; grow-as-needed
allows partial cancellation refund (less rent locked if user gives up
mid-upload). The protocol locks `total_len` at init either way (it's in
`h_0`), so the first option is cleaner.

**Proposed answer**: reserve upfront. Rent is the cost of using the
protocol; if a user cancels early, full refund happens at `CancelSession`.

### Q2. Should `last_verify_error` field exist?

If we close on success and keep on failure, the failed session needs
*some* way to communicate which verifier error fired. We can either:
- Store it in the account (proposed above).
- Emit it only via instruction log (transient).

**Proposed answer**: log + account field. Logs are transient, dApps may
need to read failure state asynchronously.

### Q3. Should there be a `MAX_CONCURRENT_SESSIONS_PER_PAYER` enforced on-chain?

See § 7.2.

**Proposed answer**: no, in Phase 1. Revisit if abuse observed.

### Q4. Does `CommitAndVerify` need to support multiple proofs in one transaction (batch)?

**Proposed answer**: no, in Phase 1. One session, one proof. Batching
multiple proofs that share a VK is the `batch_verify` use case (issue
[#5](https://github.com/wienerlabs/mosaic/issues/5)) and uses a different
instruction (`VerifyProofBatch`, not chunked).

### Q5. Should we support resumable sessions across program upgrades?

If `mosaic-program` is upgraded mid-session, will old sessions still
finalize correctly?

**Proposed answer**: account layout is part of ABI. Any change requires
the migration procedure in § 11. The handler must reject sessions whose
account layout version (introduce `version: u8` field?) doesn't match
the running program.

**Open**: should the layout carry a version byte?

### Q6. Permissionless garbage collection bounty?

`CancelExpiredSession` costs the caller a transaction fee with no
refund. In practice this means abandoned sessions accumulate until
someone has selfish reason to clean up.

Options:
1. **Status quo**: caller pays, no incentive. Practical for whoever
   wants the address space cleaned (e.g., the program itself via a
   keeper).
2. **Small bounty**: caller receives a fixed % of the rent (e.g. 1%).
   Other 99% to payer. Incentivises GC.
3. **Configurable bounty** via instruction param.

**Proposed answer**: option 1 in Phase 1. Add option 2 only if cleanup
lag becomes a real problem.

---

## 13. Implementation checklist (when this design is approved)

- [ ] Add `OnChainError` variants 0x35 and 0x36; extend
      `discriminant_stability` test.
- [ ] Add fields `payer`, `bump`, `created_at_slot`, `expires_at_slot`,
      `last_verify_error`, `_reserved` to `ProofUploadSession`.
- [ ] Implement `InitializeSession` handler in `mosaic-program`.
- [ ] Implement `AppendChunk` handler.
- [ ] Implement `CommitAndVerify` handler (with verifier dispatch).
- [ ] Implement `CancelSession` handler.
- [ ] Implement `CancelExpiredSession` handler.
- [ ] Integration test: 50 KB upload in 65 chunks, verify, refund.
- [ ] Integration test: cancellation flow.
- [ ] Integration test: expired session GC.
- [ ] Integration test (security): out-of-order chunk rejected.
- [ ] Integration test (security): hash mismatch rejected.
- [ ] Integration test (security): wrong-payer rejected.
- [ ] Integration test (security): permissionless GC before expiry rejected.
- [ ] CU benchmark: each instruction within target.
- [ ] `docs/threat-model.md` cross-reference for D-1..D-10.
- [ ] README update: chunked-upload subsection.

---

## Sign-off

This document becomes binding once merged. Subsequent changes to the
design require a PR amendment to this file with the rationale; runtime
implementation must not deviate without an amendment.

Reviewers expected:
- @0raclus (project lead)
- (Audit firm — once engaged)
EOF
)