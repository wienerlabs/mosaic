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
output itself is the audit evidence. Captured 2026-06-06 against a real
SBF build (`cargo build-sbf --tools-version v1.52`, borsh 1.5.7) on the
`solana-program-test` VM:

```
=== cross-validator determinism matrix ===
persona                       groth16_valid    groth16_tampered  plonk_valid
modern_mainnet                accept/84027cu   reject/83855cu    accept/973388cu
no_simd_0129_error_codes      accept/84027cu   reject/83855cu    accept/973388cu
no_simd_0222_mul_len          accept/84027cu   reject/83855cu    accept/973388cu
no_compression_syscall        accept/84027cu   reject/83855cu    accept/973388cu
legacy_pre_simd_0129_0222     accept/84027cu   reject/83855cu    accept/973388cu
ancient_no_base_syscall       reject/3310cu    reject/3310cu     reject/577289cu
cross-validator determinism OK: 3 workloads × 5 base personas, all
results + CU identical; ancient persona degraded gracefully.
```

Read the matrix top to bottom: every base-syscall persona reports the
**byte-identical** verdict and CU for each workload. groth16 verifies
at 84 027 CU and rejects a tampered proof at 83 855 CU on every
persona; PLONK verifies at 973 388 CU on every persona. The
`ancient_no_base_syscall` row rejects all three (3 310 CU for the
Groth16 attempts where the syscall is reached and fails, 577 289 for
PLONK) — graceful degradation, never a silent accept. This is the
determinism claim, demonstrated rather than asserted.

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

## Toolchain note — reproducing the on-chain build (resolved; see #88)

> Full diagnosis + the remaining CI-wiring work live in issue
> [#88](https://github.com/wienerlabs/mosaic/issues/88).

The matrix above is reproduced with two pins:

1. **borsh pinned to 1.5.7.** borsh 1.6.x's `vec_from_reader`
   (`src/de/mod.rs:164`) panics on the SBF runtime, so the program died
   at ~1 900 CU before any verification regardless of platform-tools
   version. Pinning borsh back to 1.5.7 (within the workspace's
   declared `borsh = "1.5.1"` range) fixes it. With the pin, all 17
   `verify_proof_sbf` tests and all 4 determinism tests pass.

2. **Platform-tools v1.52 for the build.** `cargo build-sbf
   --tools-version v1.52` ships a cargo new enough to parse the
   `edition2024` manifests in the tree (`constant_time_eq 0.4.2`, the
   `digest 0.11` line — both dragged in by `blake3 1.8.4`) while
   emitting sBPF the `solana-program-test 2.3.13` VM (sBPF 0.11.1)
   executes correctly.

`crypto-common 0.2.1` still emits SBF stack-offset *warnings* for its
`[u128; N] SerializableState` impls; that code is unreachable in the
verifier (we never hash with blake3's digest trait), the build still
finishes, and the program runs correctly — confirmed by the green
matrix above. #88 tracks tidying the residual `blake3 1.8.4` /
RustCrypto-0.11 drift and wiring `SBF_OUT_DIR=... cargo test
-p mosaic-program` into CI so the on-chain path runs on every push
rather than skip-only.

Without `SBF_OUT_DIR` set, the three on-chain tests skip cleanly and
only the host guard runs, so `cargo test --workspace` stays green on
any machine. **Determinism is a property of the verifier source, not of
the toolchain**: these pins are about *running the demonstration*, not
about *making the verifier deterministic*.

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

- Harness: shipped, compiles, host guard green.
- On-chain matrix: **green** — 4/4 determinism tests + 17/17
  `verify_proof_sbf` tests pass against a real SBF build (borsh 1.5.7,
  platform-tools v1.52). Matrix captured above.
- CI execution of the on-chain path on every push: gated on the #88
  wiring (matched-toolchain build + `SBF_OUT_DIR` in the workflow).
- Testnet cross-validator cross-check (the live-cluster half of #70):
  open, runs after devnet deploy (#68) lands.
