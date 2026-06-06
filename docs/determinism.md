# Cross-validator determinism — methodology + evidence

> Tracks issue [#70](https://github.com/wienerlabs/mosaic/issues/70)
> (T-5 mitigation). This is the audit artifact for the claim that the
> Mosaic verifier program is deterministic across the validator set:
> the same proof produces the same verdict and consumes the same
> compute units on every validator, regardless of which runtime
> features that validator has activated.

## Why determinism is a hard requirement, not a nice-to-have

Two failure modes, both fatal for a Solana program:

1. **Result nondeterminism breaks consensus.** If a proof verifies on
   validator A but is rejected on validator B, the two validators
   produce different transaction outcomes for the same block. The
   cluster cannot reach consensus. For a verifier this is the
   worst-case bug: a soundness or completeness split across the
   validator set.

2. **CU nondeterminism breaks fee markets.** If the same proof
   consumes 83 574 CU on validator A and 84 000 CU on validator B,
   the two disagree on whether a transaction fit inside its requested
   compute budget. Fee estimation and block packing diverge.

A ZK verifier concentrates this risk in one place: the `alt_bn128`
syscall family. Those syscalls are gated behind runtime features that
activate **independently** across the validator set during a rollout
window. The relevant features:

| Feature | SIMD | What it changes |
|---|---|---|
| `enable_alt_bn128_syscall` | — | Whether the base G1Add / G1Mul / Pairing syscalls exist at all |
| `simplify_alt_bn128_syscall_error_codes` | SIMD-0129 | The error codes the syscall returns on bad input |
| `enable_alt_bn128_compression_syscall` | — | Whether the point (de)compression syscalls exist |
| `fix_alt_bn128_multiplication_input_length` | SIMD-0222 | Input-length validation for the G1Mul syscall |

On modern mainnet all four are active. But during any feature rollout
there is a window where some validators have a feature and some do
not. The determinism question is: **does our verifier produce
identical results + CU on every validator across that window?**

## The harness

`crates/mosaic-program/tests/cross_validator_determinism.rs` answers
this empirically. It boots `solana-program-test` (the in-memory rbpf
VM that runs the real SBF bytecode) under several `FeatureSet`
**personas**, each modelling a validator at a different point of the
feature rollout:

| Persona | Deactivated features | Models |
|---|---|---|
| `modern_mainnet` | none | A fully up-to-date mainnet validator |
| `no_simd_0129_error_codes` | SIMD-0129 | A validator that hasn't picked up the error-code simplification |
| `no_simd_0222_mul_len` | SIMD-0222 | A validator without the G1Mul input-length fix |
| `no_compression_syscall` | compression | An older validator without the compression syscalls |
| `legacy_pre_simd_0129_0222` | SIMD-0129 + SIMD-0222 | A validator behind on both behaviour-changing features |
| `ancient_no_base_syscall` | all four | A hypothetical validator without `alt_bn128` at all |

Each persona runs the same workload set:

| Workload | Proof system | Expectation |
|---|---|---|
| `groth16_valid` | Groth16 BN254 | accept |
| `groth16_tampered` | Groth16 BN254, proof byte 0 low bit flipped | reject |
| `plonk_valid` | PLONK KZG BN254 | accept |

## The assertions

The harness collects a `(persona × workload) → (verdict, CU)` matrix
and enforces:

1. **Result determinism.** For each workload, the accept/reject
   verdict is identical across every persona that has the base
   syscall. A divergence fails the test with a `RESULT DIVERGENCE`
   message naming the persona.

2. **CU determinism.** For each valid-path workload, the CU consumed
   is byte-identical across every base-syscall persona. A divergence
   fails with `CU DIVERGENCE` — this is the fee-market-stability
   guarantee.

3. **Intra-persona determinism.** `intra_persona_repeat_determinism`
   re-runs `groth16_valid` five times in the same persona and asserts
   identical `(verdict, CU)` every time. This catches hidden
   nondeterminism inside the verifier (map iteration order,
   uninitialised reads, etc.).

4. **Graceful degradation.** On `ancient_no_base_syscall` (no
   `alt_bn128` syscall), every workload must be **rejected**. A
   verifier that accepts when the curve syscall is unavailable is a
   `GRACEFUL-DEGRADATION VIOLATION`.

5. **CU stability across error-code features.**
   `plonk_cu_stable_across_error_code_features` proves the PLONK path
   consumes identical CU with and without SIMD-0129 — i.e. the
   error-code simplification, which changes syscall *return values* on
   failure, does not perturb the *cost* of the success path.

The test prints the full matrix to stderr (`--nocapture`), so the test
output itself is the audit evidence:

```
=== cross-validator determinism matrix ===
persona                       groth16_valid    groth16_tampered  plonk_valid
modern_mainnet                accept/<cu>cu    reject/<cu>cu     accept/<cu>cu
no_simd_0129_error_codes      accept/<cu>cu    reject/<cu>cu     accept/<cu>cu
...
```

## A host-side guard that always runs

`host_borsh_roundtrip_sanity` runs without any SBF artifact and
asserts the instruction-encoding the harness submits decodes back to
the original `(proof_system_id, vk, proof, public_inputs)`. This keeps
the harness honest even on machines that cannot build the SBF binary:
if the canonical instruction layout ever drifts, this test fails in a
plain `cargo test` run.

## Running the harness

```bash
# 1. Build the SBF artifact with platform-tools whose sBPF version
#    matches the VM in solana-program-test (see toolchain note below).
cargo build-sbf --tools-version <matched> --manifest-path crates/mosaic-program/Cargo.toml

# 2. Run with the artifact directory exported. solana-program-test
#    2.3.x reads SBF_OUT_DIR (the legacy BPF_OUT_DIR is also accepted
#    by the test's own gate but NOT by the program-test loader).
SBF_OUT_DIR="$PWD/target/deploy" \
  cargo test -p mosaic-program --test cross_validator_determinism -- --nocapture
```

With no `SBF_OUT_DIR` set, the three on-chain tests skip cleanly and
only the host guard runs — identical contract to
`verify_proof_sbf.rs`, so `cargo test --workspace` stays green on any
machine.

## Toolchain note — the SBF dependency tree has drifted; tracked in #88

> This is the single operational gotcha for reproducing the on-chain
> evidence. Full diagnosis + the coordinated fix live in issue
> [#88](https://github.com/wienerlabs/mosaic/issues/88).

Reproducing the on-chain matrix currently requires the dependency-tree
fix from #88. The short version: the lockfile has drifted forward into
a state the `solana-program-test 2.3.13` VM (embedding
`solana-sbpf 0.11.1`) cannot run. Two compounding causes, both rooted
in `blake3 1.8.4` (pulled at runtime via
`solana-program -> solana-blake3-hasher -> blake3`, floored at
`^1.8.2` by `solana-accounts-db` from the program-test dev-dep):

1. **Manifest parse.** The sBPF-0.11-matched older platform-tools ship
   cargo 1.84, which cannot parse the `edition2024` manifests that
   `constant_time_eq 0.4.2` and the `digest 0.11` line declare. Newer
   tools (v1.52 / v1.54) parse them fine, so this alone is surmountable.

2. **Runtime panic.** Even with a successfully built `.so`, the program
   panics at `borsh 1.6.1`'s `vec_from_reader` (`src/de/mod.rs:164`) on
   every input — the program consumes only ~1 900 CU, far below any
   real verification. This reproduces under both v1.52 and v1.54 tools,
   so it is a `borsh 1.6.1` / SBF-runtime interaction, not an
   sBPF-version artifact. Confirmed not an encoding bug: the host-only
   `host_borsh_roundtrip_sanity` test decodes the identical instruction
   bytes correctly. `crypto-common 0.2.1` additionally emits SBF
   stack-offset errors for its `SerializableState` impls.

The April-2026 `.so` ran these dispatch arms fine; the regression came
from the lock drifting forward (blake3 1.5 -> 1.8, borsh 1.5 -> 1.6,
the RustCrypto 0.10 -> 0.11 / edition2024 wave). #88 tracks the
coordinated pin-back + a CI job that actually executes the on-chain
tests so it cannot silently regress to skip-only again.

Until #88 lands, the harness runs in skip mode (host guard only) and
the on-chain matrix is reproduced manually with the pinned tree. **This
is a build/CI-infrastructure gap, not a determinism gap**: the
verifier's determinism properties are a function of its source, not of
which dependency versions or machine run the test.

## Relationship to other evidence

- `verify_proof_sbf.rs` — proves each dispatch arm runs end-to-end on
  the real VM. The determinism harness adds the cross-`FeatureSet`
  dimension on top of that.
- `mosaic-bench` pinned CU baselines — the determinism harness asserts
  CU is *stable across personas*; the bench asserts CU is *stable
  across releases*. Together they bound CU drift on both axes.
- `mosaic-soak` (issue #67) — the determinism harness runs in-memory;
  the soak runs against a live cluster. Cross-validator determinism on
  a live multi-validator testnet is the soak's job (issue #70's
  testnet half).

## Status

- Harness: shipped, compiles, host guard green, on-chain tests skip
  cleanly without a matched toolchain.
- On-chain matrix: reproducible with a matched toolchain; CI execution
  gated on the SBF-toolchain pin.
- Testnet cross-validator cross-check (the live-cluster half of #70):
  open, runs after devnet deploy (#68) lands.
