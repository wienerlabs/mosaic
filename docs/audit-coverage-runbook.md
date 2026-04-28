# Audit-coverage runbook

This file is the entry point for an external review firm that wants
to reproduce the Mosaic audit-coverage matrix locally and extend it
with their own tests. It complements [`AUDIT.md`](../AUDIT.md)
(milestone log), the per-session CHANGELOG entries (work
provenance), and [ADR-0006](adr/0006-verifier-audit-gate-pattern.md)
(audit-gate extraction pattern that all Phase-3 verifiers follow).

## Coverage matrix at v0.8.11-hyperplonk-audit-gate

| Surface | Coverage | Source |
|---|---|---|
| Property tests | 609 lib tests across 16 crates | sessions 36-91 |
| BPF CU bench | 7 systems via `solana-program-test` | sessions 47, 49 |
| Host criterion bench | 5 systems with statistical noise floor | session 51 |
| Fuzz harnesses | 23 targets across 6 production verifiers | sessions 54-59 |
| Shared primitives | 11 audit-grade helpers in `mosaic-zk-primitives` | sessions 21-83 |
| **Phase-3 audit gates** | **4 named `verify_*` functions, one per Phase-3 verifier** | **sessions 86-91** |
| CI activation | All harnesses wired into GitHub Actions | session 61 |

## Phase-3 audit gate quick-reference

| Verifier | Audit gate | Test count | Tag |
|---|---|---|---|
| Nova | [`verify_folding_consistency`](../crates/mosaic-nova/src/folding.rs) | 5 unit + 4 proptest | v0.8.6 |
| Halo2 lookup | [`verify_multi_column_lookup_identity`](../crates/mosaic-halo2/src/circuit.rs) | 4 unit + 3 proptest | v0.8.8 |
| STARK FRI | [`verify_fri_query`](../crates/mosaic-stark/src/fri.rs) | 5 unit + 1 proptest | v0.8.10 |
| HyperPlonk | [`verify_sumcheck_claim_reduction`](../crates/mosaic-hyperplonk/src/verifier.rs) | 4 unit + 2 proptest | v0.8.11 |

Each gate is a `pub fn` callable with hand-constructed inputs.
External auditors should focus reproduction work here — these are
the soundness boundaries of the workspace.

### Reproduce: run all four audit-gate test suites

```bash
cargo test -p mosaic-nova       --lib folding::tests
cargo test -p mosaic-halo2      --lib circuit::tests
cargo test -p mosaic-stark      --lib fri::tests
cargo test -p mosaic-hyperplonk --lib verifier::tests
```

Expected: every gate's full test suite passes (28+ tests across 4
gates). See ADR-0006 for the gate contract and recipe.

## How to reproduce locally

### Property tests

```bash
# Per-crate (fast, targeted)
cargo test -p mosaic-halo2 --features std --lib
cargo test -p mosaic-hyperplonk --features std --lib
# ... repeat for each crate

# Full workspace sweep (~30 sec on a stock laptop after warm cache)
cargo test --workspace --all-features --lib
```

Expected output: `test result: ok` for every crate. The reported
counts in this runbook (e.g. "75 passed" for mosaic-halo2) are
authoritative as of v0.8.3.

### BPF CU regression bench

```bash
# 1. Build the SBF program (one-time per change to mosaic-program/).
cargo build-sbf --tools-version v1.52 \
  --manifest-path crates/mosaic-program/Cargo.toml

# 2. Set the artifact path (cargo-build-sbf default).
export BPF_OUT_DIR="$PWD/target/deploy"
export SBF_OUT_DIR="$PWD/target/deploy"

# 3. Run the bench. Fails on ADR-0005 hard-cap breach (exit 1).
cargo run --release -p mosaic-bench --bin bpf-bench
```

The bench prints a per-system table:

```
SYSTEM                                  MEASURED  CAP      BASELINE    STATUS
groth16_bn254_mul_circuit_1pi             83574   180000      83574       OK
groth16_batch_n5_mul_circuit_1pi         258397   300000     258397       OK
plonk_bn254_mul_circuit_1pi              968457  1100000     968457       OK
hyperplonk_kzg_bn254_scaffold            <new>    660000          0       OK
halo2_kzg_bn254_scaffold                 <new>    760000          0       OK
nova_folding_bn254_scaffold              <new>   1150000          0       OK
fri_stark_goldilocks_scaffold            <new>   7800000          0       OK
```

Hard caps come from ADR-0005 (Phase-1/2) and verifier
`estimated_compute_units` × 1.30 (Phase-3, sessions 47, 49). New
Phase-3 baselines start at `0` because the WARN-on-drift logic
needs an established baseline; the first successful run records the
baseline for future regression tracking (see
`crates/mosaic-bench/src/bin/bpf_bench.rs`).

### Host criterion bench

```bash
# Two bench files; the matrix runs both.
cargo bench -p mosaic-bench --bench groth16_host
cargo bench -p mosaic-bench --bench phase3_host
```

Criterion writes statistical reports under `target/criterion/`.
A real algorithmic regression surfaces as a measurable shift
distinct from JIT/codegen drift.

### Fuzz harnesses

```bash
# One-time setup
cargo install cargo-fuzz --locked

# Run any of the 23 harnesses (5-min budget, expand for serious
# corpus development).
cargo +nightly fuzz run --fuzz-dir crates/mosaic-fuzz \
  fuzz_halo2_combined -- -max_total_time=300
```

Full inventory:

| Surface | Targets |
|---|---|
| Phase-1 Groth16 | `fuzz_groth16_proof_bytes`, `fuzz_vk_bytes`, `fuzz_public_inputs` |
| Phase-2 PLONK | `fuzz_plonk_{proof_bytes, vk_bytes, public_inputs, combined}` |
| Phase-3 HyperPlonk | `fuzz_hyperplonk_{proof_bytes, vk_bytes, public_inputs, combined}` |
| Phase-3 Halo2 | `fuzz_halo2_{proof_bytes, vk_bytes, public_inputs, combined}` |
| Phase-3 Nova | `fuzz_nova_{proof_bytes, vk_bytes, public_inputs, combined}` |
| Phase-3 STARK | `fuzz_stark_{proof_bytes, vk_bytes, public_inputs, combined}` |

The combined-slot fuzzers split the libfuzzer input into three
length-prefixed sub-buffers (vk, proof, public_inputs) and explore
cross-slot interaction surface — bugs that only surface when two
slots lie about the same shape parameter in a coordinated way.
Halo2 and STARK have the richest cross-check fingerprints; PLONK
the narrowest.

## How to extend the coverage

### Add a new property test

1. Pick a soundness-critical invariant (e.g. "every byte flip in
   the commit region must reject").
2. Write the test in the relevant crate's `src/<module>.rs`
   `#[cfg(test)] mod tests {}` block, prefixed with `proptest_*`.
3. Add a docstring explaining what the property pins and why an
   external auditor cares. The session-37-52 commits are the
   canonical examples; they document false positives inline.
4. Run locally with `cargo test -p <crate> --features std --lib`.

### Add a new fuzz harness

1. Pick a parser surface not already covered (e.g. a new adapter
   format).
2. Write the harness as `crates/mosaic-fuzz/fuzz_targets/<name>.rs`
   following the session-54-59 template (single-slot variant) or
   session-56's `split_three_slots` (combined variant).
3. Add a `[[bin]]` entry to `crates/mosaic-fuzz/Cargo.toml`.
4. Add the target to both PR-mode and nightly-mode matrices in
   `.github/workflows/fuzz.yml`.

### Add a new bench

1. For a host-side bench: add a new `[[bench]]` to
   `crates/mosaic-bench/Cargo.toml` and a corresponding
   `benches/<name>.rs` following the session-51 `phase3_host`
   template.
2. For an on-chain CU bench: add a `SystemTarget` entry to the
   `TARGETS` const in `crates/mosaic-bench/src/bin/bpf_bench.rs`,
   plus an inline `build_*_scaffold_fixture` builder, plus a
   dispatch arm in `main`. Sessions 47 + 49 are the canonical
   examples.
3. Add the harness to the matrix in `.github/workflows/bench.yml`.

### Add a new shared primitive

1. Add the function to the relevant `mosaic-zk-primitives::*`
   module with a `# Errors` docstring section.
2. Write at least one proptest pinning the soundness invariant
   (the canonical example is session 63's
   `prop_horner_matches_naive_eval` against a naive
   sum-of-products implementation).
3. Migrate the first in-tree consumer in a follow-up commit so
   the primitive has a real production user from session-1.
4. Track remaining consumers in the commit message; future
   sessions migrate them in commit-sized batches.

## What this coverage does NOT pin

**Important for the auditor's threat model.** The coverage above
exercises every byte-format, Fiat-Shamir, state-machine, and
cross-slot invariant the verifier surface is supposed to enforce.
It does NOT exercise:

1. **Real prover output.** All bench + fuzz fixtures are
   scaffold-acceptance bytes (uniformly zero or structurally
   valid but cryptographically vacuous). A successful BPF run on
   the scaffold fixture means "the verifier completes the
   pipeline and accepts" — NOT "the verifier rejects every
   forged real proof". Closing this gap is the
   "fixture-driven differential testing" item in the planned-beyond
   block of CHANGELOG.md.

2. **Full cryptographic soundness of Phase-3 reductions.**
   HyperPlonk's multi-point-to-univariate reduction
   (Zeromorph / PST / Gemini), Halo2's full lookup argument,
   Nova's complete folding consistency, FRI-STARK's per-layer
   fold + low-degree test — each is implemented as a "scaffold"
   that exercises the full syscall chain but stops short of the
   complete soundness check. Per-crate rustdoc spells out the
   scaffold caveat in detail.

3. **External `solana-program-test` integration for the chunked
   upload protocol.** `mosaic-program::chunked::dispatch` has
   property tests on its data shape but no integration test
   driving the full PDA + AccountInfo lifecycle. Tracked in the
   planned-beyond block.

The auditor should treat the coverage matrix as a guarantee that
the verifier surface fails closed on hostile bytes, not as a
guarantee that every reachable code path is cryptographically
sound. The latter requires fixture-driven differential testing
against external prover implementations.

## Where to file issues

| Type | Channel |
|---|---|
| Soundness bug found by fuzzer | GitHub Issues, label `security` |
| Property-test false positive | GitHub Issues, label `audit-coverage` |
| Bench baseline drift | GitHub Issues, label `cu-regression` |
| Vulnerability disclosure | See [SECURITY.md](../SECURITY.md) — DO NOT use GitHub Issues for unreported vulnerabilities |
