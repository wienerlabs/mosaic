# Mosaic — Threat Model

> *Living document.* Last reviewed 2026-04-19. Re-review on every audit.

## Scope

Threats covered:

- Adversarial proof, VK, and public-input bytes submitted on-chain.
- Adversarial chunked-upload sequences targeting the session PDA.
- Validator-divergence attacks targeting consensus determinism.
- Memory-safety and arithmetic-overflow attacks within library code.
- Timing side-channels reachable from on-chain (limited — see below).

Threats **not** covered:

- Compromise of the proving trust setup (out of scope; verifier assumes
  trusted setup integrity).
- Compromise of the upstream framework (snarkjs, arkworks, gnark, …).
- Solana validator infrastructure compromise.
- DoS via legitimate-but-expensive proofs (mitigated by CU budgets, not
  full prevention).
- Client-side key management (the SDK is not a wallet).

## Trust boundaries

```
┌────────────────────────────────────────────────────────────────────┐
│ Untrusted: arbitrary bytes from any caller                         │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Mosaic adapters (mosaic-serde) — convert to canonical bytes        │
│   Input: framework-specific format. Output: canonical bytes.       │
│   Failure mode: returns Err; never panics.                         │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ On-chain dispatcher (mosaic-program)                                │
│   Input: canonical bytes. Output: ProgramResult.                    │
│   Trust: assumes byte format only; no semantic trust.              │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ Verifier (mosaic-groth16, …)                                        │
│   Input: canonical bytes. Output: Result<(), OnChainError>.        │
│   Trust: trusts SyscallBackend to be deterministic and correct.    │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────────┐
│ SyscallBackend (mosaic-core::syscall)                               │
│   Solana SBF: trusts validator implementation of alt_bn128/SHA-256. │
│   Host: trusts arkworks + sha2 + tiny-keccak.                       │
└────────────────────────────────────────────────────────────────────┘
```

## Threats and mitigations

### T-1 Adversarial proof bytes — pairing accept on invalid proof

**Risk**: Crafted bytes pass length checks but cause the pairing syscall to
return `1` for an invalid proof.

**Mitigation**: We delegate cryptographic correctness to the
`alt_bn128_pairing` syscall. The Solana validator implementations are the
authoritative oracle. We do not re-implement pairing in `forbid(unsafe_code)`
Rust.

**Residual risk**: Soundness errors in the validator implementations would
break Mosaic. We mirror with the host backend (arkworks) for differential
testing, which would surface a divergence between the two implementations.

### T-2 Adversarial public inputs — values ≥ scalar field order `r`

**Risk**: Bypasses Groth16 soundness if accepted with `pi >= r`.

**Mitigation**: `Groth16Verifier::verify` bounds-checks every public input
against `BN254_FR_MODULUS_BE` *before* invoking the syscall. Violations
return `OnChainError::PublicInputOutOfRange`.

**Validation**: Unit test in `crates/mosaic-groth16/src/canonical.rs::tests::fr_modulus_bound`.

### T-3 Off-curve / wrong-subgroup G1 / G2 inputs

**Risk**: Crafted "points" that aren't on the curve.

**Mitigation**: The `alt_bn128_pairing` syscall rejects off-curve inputs with
non-success status, surfacing as `OnChainError::AltBn128SyscallFailed`.
Host backend explicitly calls `is_on_curve` and `is_in_correct_subgroup_assuming_on_curve`.

**Residual risk**: A subtle bug in the syscall's subgroup check (cf. the
2022 BN254 subgroup-check bug in geth) would propagate. Differential testing
against arkworks catches divergence; cannot catch *both* impls being wrong
in the same way.

### T-4 Length-mismatch crash via crafted byte slices

**Risk**: A crafted proof / VK byte slice causes a panic via slice indexing.

**Mitigation**: Every byte-level access uses `split_at`, `chunks_exact`, or
explicit `.get()` with `?`. Library-wide `clippy::indexing_slicing = "warn"`
catches regressions.

**Validation**: `cargo-fuzz` harnesses in `mosaic-fuzz/` (proof bytes, VK
bytes, public inputs).

### T-5 Validator divergence on error codes (consensus failure)

**Risk**: Two validator implementations (Agave, Firedancer, Jito-Solana)
return different `ProgramError` codes on the same input, forking the network.
Cf. SIMD-0129.

**Mitigation**: `OnChainError` is a small `repr(u32)` enum; every reachable
code path maps to a stable discriminant. Off-chain `DiagnosticError` cannot
reach on-chain entry points (compile-time enforced). All length / format
checks return concrete variants, never wildcards. `mosaic-core::error::tests::discriminant_stability` pins the most load-bearing discriminants.

### T-6 Chunked-upload reordering / commitment forgery

**Risk**: Adversary uploads a different proof than the one whose hash they
precommitted to in `InitializeSession`.

**Mitigation**: Rolling SHA-256 binds each chunk's content and order;
`CommitAndVerify` checks the running hash against the precommitted final
hash. Mismatch yields `ChunkCommitmentMismatch`.

**Residual risk**: SHA-256 second-preimage attack. Considered
cryptographically intractable; if SHA-256 falls, the entire Solana state
hash falls with it.

### T-7 PDA squatting / cross-session aliasing

**Risk**: Adversary pre-creates a session PDA with a chosen `session_id`.

**Mitigation**: `session_id` is a 32-byte client-supplied value; if two
clients pick the same value, the second `InitializeSession` will fail
because the PDA is already initialized. Clients are expected to use
cryptographic randomness (the SDK does this via `rand::thread_rng`).

### T-8 Timing side-channels

**Risk**: Pairing or MSM timing leaks witness data.

**Mitigation**: On-chain code runs on validators, not in an environment where
timing is observable to the prover. The `subtle` crate's constant-time
primitives are used for length-equal comparisons in non-host paths.

**Out of scope**: Host-side prover timing. Provers should use
constant-time crypto themselves; Mosaic verifies, it does not prove.

### T-9 Memory unsafety

**Risk**: Use-after-free, buffer overflow, etc.

**Mitigation**: Every library crate has `#![forbid(unsafe_code)]`. Any future
use of `unsafe` requires an `allow` exception list in `deny.toml` and a
`SAFETY:` block.

### T-10 Arithmetic overflow

**Risk**: Silent wrapping in length / index arithmetic causes incorrect
behavior on hostile input.

**Mitigation**: `clippy::arithmetic_side_effects = "warn"`. All chunk-size
and offset calculations use `checked_add` / `try_from`. `dev` profile has
`overflow-checks = true`; `release` has it off but the patterns are
checked-arithmetic regardless.

### T-11 Compression-syscall round-trip divergence (sessions 103-114)

**Risk**: alt_bn128 compression / decompression diverges between the
host arkworks `serialize_compressed` / `deserialize_with_mode` path and
the Solana SBF `sol_alt_bn128_compression` syscall. A divergence would
silently corrupt off-chain transport: a prover-emitted compressed
proof that round-trips correctly on the prover's host could fail to
verify on chain after decompression, or — worse — decompress to a
*different* curve point than the prover intended.

**Mitigation**:

1. **Surface compression APIs are wire-format only.** The on-chain
   `verify` path never invokes compression / decompression. A proof
   uploaded as canonical bytes verifies identically on host and SBF;
   compression is opt-in at the SDK / chunked-upload layer.
2. **Round-trip tests on real BN254 generators across all five
   BN254-curve verifiers** (Halo2, Groth16, KZG-PLONK, HyperPlonk,
   Nova). 59 lib tests exercise:
   - happy path (compress → decompress → equal canonical bytes);
   - non-curve byte pass-through preservation;
   - off-curve rejection;
   - length / shape-counter rejection;
   - proptest sweep of non-curve fields under random fill.
3. **Fuzz coverage on the decompression entry points** (10 harnesses).
   The panic-free invariant catches any byte-sequence-induced panic
   that would diverge between host and SBF behavior.
4. **STARK family is excluded by design** — Plonky3 STARK proofs
   carry no BN254 curve points; alt_bn128 is N/A. Bandwidth
   optimization there stays on the field-element-packing track.

Residual risk: until the on-chain `verify_compressed_proof` instruction
lands (planned session 116) and bpf-bench measures the SBF syscall side
directly, the host-vs-SBF cost ratio for compression is inferred from
arkworks wall-clock, not measured directly. Any drift in the syscall's
per-op CU schedule (Solana protocol upgrade) would not surface in our
host bench until SBF measurements land.

### T-12 Chunked-STARK CU exhaustion / single-tx infeasibility

**Risk**: A FRI-STARK proof at production shape (8 queries × 4 FRI
layers × `log_h = 10`, the `bpf-bench` reference) consumes ~7.8 M CU
per the verifier's `estimated_compute_units` shape-aware estimate.
Solana's per-transaction cap is `MAX_COMPUTE_UNIT_LIMIT = 1_400_000`
CU. A naïve client submitting a STARK proof as a single
`VerifyProof` transaction will hit this cap and the program will
abort with `ProgramError::ComputationalBudgetExceeded` — burning the
caller's prioritization fee and leaving them confused about whether
the proof was malformed.

**Mitigation**:

1. **Chunked execution (implemented, #76).** The verifier exposes a
   resumable API — `FriStark::verify_setup` (once-per-proof shape +
   PoW + OOD gate) and `verify_query_range(start, end)` (per-query
   batch) — because each query's checks (trace + constraint Merkle
   paths, FRI fold-chain, per-layer auth) are independent. The
   `mosaic-program` `BeginStarkVerify` (0x15) + `StarkVerifyStep`
   (0x16) instructions drive this across separate transactions, with
   a `StarkVerifyProgress` cursor in the session PDA enforcing that
   `[0, num_queries)` is covered contiguously exactly once and that
   the setup gate ran first. Each step processes a `queries_per_step`
   batch sized to stay under the 1.4M cap. STARK callers MUST use this
   path (never single-shot `VerifyProof`); the SDK's
   `build_chunked_stark_plan` assembles the full instruction sequence.
   End-to-end tested on the VM in `chunked_stark.rs` (verify across
   three transactions, cursor `0 → 2 → 4`, session closes on
   completion).
2. **SBF integration test caveat.** Session 113's
   `sbf_dispatches_fri_stark_scaffold` uses the smallest passing
   shape (`num_q=4, num_fri=0, log_h=0, log_blowup=0`) — depth-zero
   Merkle, ~150 K CU — explicitly to fit in a single tx for
   regression-tracking purposes. This is documented in the test
   file as the "chunking constraint" audit note. Production STARK
   verification uses the chunked path.
3. **bpf-bench scaffold sizing intentional.** The bench targets
   the production shape (~7.8 M CU) so regression alarms surface
   before the chunked-path runtime cost drifts.

Residual risk: a caller submitting a STARK proof via the single-tx
`VerifyProof` instruction (rather than the chunked path) will not
get a *user-friendly* error today — they'll get
`ComputationalBudgetExceeded` from the runtime, not a Mosaic-level
"use chunked execution" hint. The SDK guards against this; direct
on-chain callers might not.

## Scope boundaries and application responsibilities

The T-N threats above cover adversarial inputs to Mosaic's byte-level
interface. Four further axes describe the boundary between what Mosaic
owns and what consuming applications own. Auditors typically probe these
within the first hour of an engagement; the sections below pre-answer
the standard questions.

### Axis 1 — Under-constrained circuit attacks

**What is Mosaic's scope?** Mosaic verifies that *a* proof is
well-formed and that the stated public inputs satisfy the verification
equation. It does **not** verify that the underlying circuit correctly
captures the application's intent. A Circom / arkworks / gnark author
who forgets a constraint produces a circuit that accepts invalid
witnesses; Mosaic then correctly verifies proofs of those invalid
witnesses — the flaw is upstream of our code.

**Concrete failure mode.** The 0xPARC under-constrained Circom audit
catalogue (<https://github.com/0xPARC/zk-bug-tracker>) documents dozens
of real-world cases: range checks elided, selector bits unconstrained,
lookup tables with permutation gaps. A Groth16 proof against a circuit
with any of these flaws will verify successfully in Mosaic *and on
Light Protocol's reference verifier* — the algebra is still satisfied.

**Where to look instead.** Circuit-level correctness tooling:

- [Picus](https://github.com/Veridise/Picus) — automated soundness
  checking for arithmetic circuits.
- [Ecne](https://github.com/franklynwang/EcneProject) — constraint-gap
  finder for Circom.
- [ZK-NavigatOR](https://eprint.iacr.org/2023/1278) — taint-tracking
  analysis framework.
- Manual review by a cryptographer familiar with the target system.

**Mosaic's commitment.** The adapter documentation and SECURITY.md
state this scope boundary explicitly. If a user reports "my proof
verified but the underlying claim was false", we help them trace it to
the circuit flaw but do not treat it as a Mosaic vulnerability.

**What an auditor can still check on our side.** That the verifier does
not *introduce* new soundness flaws on top of a correctly-constrained
circuit — i.e. that every T-1..T-10 attack vector is mitigated.

### Axis 2 — Malleable proof vectors

**What the SNARK algebra guarantees.** Groth16 proofs are
non-malleable in the cryptographic sense: an adversary who observes a
valid `(A, B, C)` for public input `x` cannot produce a distinct
`(A', B', C')` for the *same* `x` without knowing the witness. This is
a consequence of the knowledge-of-exponent assumption underlying
Groth16.

**What that guarantee does not cover.** Two proofs `(A, B, C)` and
`(A', B', C')` may both be valid for the *same* public inputs and the
same statement — because the prover is allowed to inject fresh
randomness. Application replay protection cannot rely on
"the second proof must equal the first". It must bind each proof to an
external anti-replay nonce.

**The correct application pattern.**

1. Include a **nonce** or **commitment hash** in the circuit's public
   inputs.
2. Maintain on-chain a set of spent nonces (hash set PDA, or a
   compressed sparse merkle tree for scale).
3. `verify_proof` reaches success only if the nonce is fresh; then
   insert it into the spent set atomically.

Mosaic's chunked-upload protocol is a worked example: the
`session_id` is a 32-byte client-chosen nonce that binds every
`AppendChunk` and the final `CommitAndVerify` to that specific
session (design doc § 3.3).

**What Mosaic does not do.** There is no global "spent proof" set
inside `mosaic-program`. Applications maintain their own.

### Axis 3 — Validator determinism (extends T-5)

T-5 covers error-code divergence. Three additional determinism
surfaces auditors should probe:

**Arithmetic determinism.** No floating-point operations anywhere in
library code. All integer arithmetic uses `checked_add` / `try_from`
on paths reachable from hostile input; the `dev` profile has
`overflow-checks = true` to catch silent wrapping in tests. Release
profile disables overflow checks by policy (CU cost) but every reachable
arithmetic site has been manually audited for overflow-free operation
within the input domain.

**Iteration order determinism.** No `HashMap` or `HashSet` in hot
paths (they iterate in random order by default in Rust). Where
associative lookup is needed, we use `BTreeMap` (deterministic order) or
`ArrayVec` + linear scan (deterministic by construction).

**Allocator determinism.** SBF uses a bump allocator whose layout is
fixed per `requested_heap_frame`. `forbid(unsafe_code)` rules out any
allocator behavior that could vary across validator implementations.
Post-issue-#58 migration to `deny(unsafe_code)` + `unsafe-arena`
feature requires Miri CI as the lockstep gate specifically to rule
out allocator non-determinism in that future path.

**Reference incident.** [SIMD-0129][simd-0129] documents the consensus
failure incident that motivated this axis. We treat every new error
code, every new allocator use, and every new iteration as a
divergence candidate during code review.

[simd-0129]: https://github.com/solana-foundation/solana-improvement-documents/pull/129

**What an auditor can check.** That no addition of future code paths
can violate the above. The Miri CI job on the unsafe-arena feature is
the mechanical backstop; the review discipline in CONTRIBUTING.md is
the human layer.

### Axis 4 — Replay safety and instruction binding

**What Mosaic does.** The verifier returns `Ok(())` for any valid
proof matching a VK. It does not track which proofs have been seen
before. Submitting the same proof + VK + public inputs twice in two
transactions produces two `Ok(())` returns.

**Why this is correct.** Replay protection is inherently application-
specific: "the same proof for the same claim" is legitimate in one
protocol (e.g. optimistic rollup proofs where multiple provers may
submit the same valid state transition) and illegitimate in another
(single-use attestation, one-time access token).

**The correct application pattern.**

```rust
// Pseudocode for an attestation-minting program:
pub fn mint_if_proof_valid(ctx: Context<MintIfValid>, proof: Proof) -> Result<()> {
    // 1. Derive the nullifier from the proof's public inputs.
    let nullifier = derive_nullifier(&proof.public_inputs);

    // 2. Check and insert into the spent set atomically.
    if ctx.accounts.spent_nullifiers.contains(&nullifier) {
        return Err(Error::ProofAlreadyUsed);
    }
    ctx.accounts.spent_nullifiers.insert(nullifier);

    // 3. NOW call Mosaic's verifier.
    mosaic_sdk::invoke_verify(&ctx.accounts.mosaic, &proof, &ctx.accounts.vk)?;

    // 4. Issue the token.
    mint_attestation_token(&ctx.accounts)
}
```

**Instruction binding.** Each `VerifyProof` call is a single
transaction; chunked-upload sessions are bound to a payer pubkey via
PDA seeds (design doc § 3.2) so an adversary cannot redirect someone
else's upload to attest to a claim they did not intend. The chunked
protocol also binds `proof_system_id` into the rolling-hash seed `h_0`,
so bytes destined for a Groth16 verify cannot be redirected to a
hypothetical future Plonk verify.

**What Mosaic does not do.** There is no `verify_once` variant that
records the proof digest on-chain. Adding one would either (a) require
a global "seen proofs" PDA (large state) or (b) require the application
to supply a commit account (which pushes the problem back to the
application anyway). We deliberately do neither; applications that
want single-use semantics implement them at the nullifier layer.

**Reference incidents.** Classical replay bug in early ZK-rollup
systems where a valid proof for state `S` could be re-submitted to
finalize the same transition twice. Our guidance explicitly avoids
that class of bug at the application/protocol layer.

## Audit history

See [`AUDIT.md`](../AUDIT.md).
