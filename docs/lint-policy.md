# Lint Policy

> Audit-facing document. Every clippy and rustc `allow` in the codebase
> is justified here. Any new suppression requires an entry in the
> [Suppression registry](#suppression-registry) below with the reason and
> an issue link if it is expected to be lifted later.

## Rust compiler lints

Defined in `[workspace.lints.rust]` and inherited by every crate.

| Lint | Level | Why |
|---|---|---|
| `unsafe_code` | **forbid** | The single most important line for auditors. `forbid` (not `deny`) means no `#[allow(unsafe_code)]` escape hatch can re-enable it anywhere in the tree — the workspace contains **zero** lines of `unsafe`. Reinforced by an explicit `#![forbid(unsafe_code)]` at the root of all 16 library crates so the guarantee survives even if a crate is extracted from the workspace. A bump-allocator variant that would need `unsafe` is gated behind a separate future `unsafe-arena` feature (issue #58) precisely so the default build stays `forbid`. |
| `rust_2018_idioms` | warn | Idiom hygiene (path clarity, elided lifetimes). |
| `rust_2024_compatibility` | warn | Forward-compat with the 2024 edition migration. |
| `unreachable_pub` | warn | Flags `pub` items not actually reachable from the crate root — keeps the public API surface honest, which matters for an audited library. |
| `unused_lifetimes` | warn | Dead lifetime parameters. |
| `unused_qualifications` | warn | Redundant path qualifiers. |
| `missing_docs` | warn | Every public item is documented; the warn keeps new gaps visible at PR review. |

`unsafe_code = "forbid"` is the load-bearing one. For a ZK verifier that
runs on-chain, freedom from memory-unsafety bugs is a precondition, not a
nice-to-have — `forbid` makes it unbypassable rather than merely
discouraged.

## Layered enforcement (clippy)

Mosaic uses a four-layer clippy policy, defined in workspace `Cargo.toml`:

| Layer | Lint groups | Severity | CI behaviour |
|---|---|---|---|
| 1 | `correctness`, `suspicious` | `deny` | Hard error |
| 2 | `pedantic`, `nursery`, `cargo` | `warn` | Visible in log; CI demotes back via `-W` so build passes |
| 3 | Explicit denies (`todo`, `unimplemented`) | `deny` | Hard error |
| 4 | Soft allows (see below) | `allow` | Silent |

CI invocation:

```bash
cargo clippy --workspace --all-features --all-targets -- \
  -D warnings \
  -W clippy::pedantic \
  -W clippy::nursery \
  -W clippy::cargo
```

The blanket `-D warnings` promotes everything to error; the three `-W`
flags demote pedantic / nursery / cargo back to warn. Result: correctness
issues fail the build; style noise is visible but non-blocking.

## Hard-deny lints (Layer 1 + 3)

| Lint | Why it's denied |
|---|---|
| `clippy::correctness` (group) | Real bugs. No exceptions. |
| `clippy::suspicious` (group) | Patterns that are almost always wrong. No exceptions. |
| `clippy::todo` | A `todo!()` on a reachable on-chain path is a guaranteed validator panic — and a consensus failure if returns differ between Agave and Firedancer. |
| `clippy::unimplemented` | Same as `todo!`. Stub verifiers must return `Err(OnChainError::UnimplementedProofSystem)` instead. |

## Soft allows (Layer 4)

Each entry justifies the `allow` and links to an issue if planned to be lifted.

### `clippy::unwrap_used` — allow

Fires on every test module's `.unwrap()`. Library code is expected to
avoid `unwrap()`, but enforcement is via code review, not lint, until
issue [#32](https://github.com/wienerlabs/mosaic/issues/32) ratchets up
crate-by-crate.

### `clippy::expect_used` — allow

Same rationale as `unwrap_used`.

### `clippy::panic` — allow

Library code never directly panics (verified: `grep -r "panic!" crates/`
returns zero hits in non-test paths). Tests panic on assertion failures —
that's correct behaviour.

### `clippy::arithmetic_side_effects` — allow

Cryptographic code does extensive integer arithmetic where bounds are
proven by prior length / range checks. Treating every `+ 1` as a lint
finding generates noise that drowns the actually-interesting findings.

We rely on:

- `dev` profile `overflow-checks = true` to catch wrapping in tests.
- Explicit `checked_add` / `try_from` in chunked-upload session arithmetic
  where overflow is reachable from hostile input.

### `clippy::indexing_slicing` — allow

Same false-positive pattern as `arithmetic_side_effects`. After a
`if bytes.len() != EXPECTED { return Err(...) }` guard, a subsequent
`bytes[..32]` is provably safe but clippy can't see through the check.

Decode functions in `mosaic-core::syscall::host` and
`mosaic-groth16::canonical` follow this pattern consistently.

### `clippy::missing_panics_doc` — allow

Library code does not panic, so the lint never fires meaningfully on us;
when it does, it's noise on test code.

### `clippy::disallowed_macros` — allow

`mosaic-bench` and `mosaic-sdk` legitimately use `eprintln!` /
`println!` for host-side tooling output. The on-chain crates have no
macro use that would benefit from a deny list.

### `clippy::pedantic`, `clippy::nursery`, `clippy::cargo` — warn (visible)

Phase 1 expedient. These groups generate ~100+ findings on a fresh
workspace, most of them stylistic. We want them visible (not silent
allow) so reviewers and auditors can see the noise floor and confirm
nothing security-critical is hiding inside.

Issue [#32](https://github.com/wienerlabs/mosaic/issues/32) tracks the
crate-by-crate ratchet from `warn` to `deny`.

## Suppression registry

Every `#[allow(...)]` / `#![allow(...)]` in `crates/` (excluding `#[cfg(test)]`
modules, whose `unwrap`/`expect`/`panic` are covered by the Layer-4 soft
allows above). Generated by:

```bash
grep -rnE '#!?\[allow\(' crates/*/src --include='*.rs'
```

Last reconciled: 2026-06-06 (16 library crates + 3 host binaries).

### On-chain library crates

| Site | Lint | Scope | Justification |
|---|---|---|---|
| `mosaic-core/src/proof_system.rs:168` | `dead_code` | fn | `assert_object_safe` — compile-time `dyn ProofSystem` object-safety probe; never called at runtime. |
| `mosaic-groth16/src/verifier.rs:185` | `clippy::too_many_arguments` | fn | `verify_groth16_pairing_identity` takes flat `&[u8]` proof / VK slices that mirror the on-chain instruction ABI byte-for-byte; bundling them into a struct would obscure the wire layout the auditor checks against. |
| `mosaic-halo2/src/kzg.rs:147,265` | `clippy::too_many_arguments` | fn | KZG batched-opening helpers; same flat-slice ABI rationale. |
| `mosaic-halo2/src/circuit.rs:454,511` | `clippy::too_many_arguments` | fn | Circuit gadget constructors taking each column/selector slice explicitly. |
| `mosaic-halo2/src/verifier.rs:831` | `dead_code` | item | Layout-assertion constant, shape-dependent. |
| `mosaic-hyperplonk/src/kzg.rs:84` | `clippy::too_many_lines` | fn | `verify_batched_opening` is one coherent verification routine (transcript → challenges → pairing); splitting it would scatter a security-critical sequence across helpers. |
| `mosaic-hyperplonk/src/verifier.rs:344` | `clippy::too_many_arguments` | fn | Verification entry; flat-slice ABI. |
| `mosaic-hyperplonk/src/verifier.rs:376,663` | `dead_code` | const | `_SUMCHECK_POLY_LEN` etc. — compile-time layout assertions that fail the build if a canonical size constant drifts. |
| `mosaic-nova/src/verifier.rs:652` | `dead_code` | item | Layout-assertion constant. |
| `mosaic-nova/src/folding.rs:245` | `clippy::too_many_arguments` | fn | Folding-step helper; each commitment passed explicitly. |
| `mosaic-plonk/src/linearization.rs:516` | `dead_code` | const fn | `const _: fn() = ...` trait-bound compile assertion (verifies `Field`/`One` re-exports stay in scope). |
| `mosaic-plonk/src/verifier.rs:233` | `dead_code` | item | Layout-assertion constant. |
| `mosaic-stark/src/verifier.rs:784` | `dead_code` | item | Layout-assertion constant (FRI/trace size invariant). |
| `mosaic-serde/src/snarkjs.rs:200,249` | `non_snake_case` | struct | `SnarkjsPlonkProof` / VK fields are `A`, `B`, `C`, `Z`, `T1`… — the exact PascalCase keys snarkjs emits in its proof JSON. The `#[serde(rename)]` mirrors the external format; renaming the Rust fields would desync the deserializer from the upstream artifact. |
| `mosaic-program/src/lib.rs:33` | `unexpected_cfgs` | crate | `solana-program`'s `#[cfg(target_os = "solana")]` and custom-heap cfgs are not in the workspace's known-cfg list; the lint is noise, not a real unknown-cfg. |
| `mosaic-program/src/chunked.rs:14` | `deprecated` | module | `solana-program` 2.x deprecates several re-exports the chunked-upload handler still uses; migration tracked in issue #52. |

### Host-side binaries (never compiled to SBF)

| Site | Lint | Scope | Justification |
|---|---|---|---|
| `mosaic-bench/src/bin/bpf_bench.rs:23` | `clippy::unwrap_used`, `expect_used`, `print_stdout`, `print_stderr`, `indexing_slicing` | crate | Host-side CU regression tool. `unwrap` on a bench fixture is the correct fail-fast; `println!` is the report. None of this is in the on-chain `.so`. |
| `mosaic-soak/src/bin/soak.rs:27` | `clippy::print_stdout`, `print_stderr` | crate | Host-side soak runner CLI; stdout is the operator-facing progress + report. |
| `mosaic-demo-sudoku/src/bin/generate_fixtures.rs:21` | `clippy::print_stdout`, `print_stderr` | crate | Host-side fixture generator CLI. |

**Invariant for auditors**: no `#[allow]` in the registry suppresses a
*correctness* or *suspicious* clippy lint, and none touches `unsafe_code`
(impossible by `forbid`). Every entry is either (a) a compile-time
assertion marked `dead_code`, (b) an ABI-shaped signature flagged
`too_many_arguments`/`too_many_lines`, (c) an external-format field name
(`non_snake_case`), or (d) host-tooling stdout — none affects on-chain
verification behaviour.

## How to add a suppression

1. **Don't, if you can help it.** Most clippy findings are real signals.
2. If you must, add `#[allow(clippy::lint_name)]` at the narrowest scope
   that compiles.
3. Add a one-line `// SAFETY-style` comment immediately above explaining
   why the lint is wrong here.
4. Add an entry to this file under the appropriate section.
5. If the suppression is expected to be temporary, link to an issue
   tracking the lift.

## How to lift a suppression

1. Open a PR against this file removing the entry.
2. Either fix the underlying issue or escalate the lint to a hard deny.
3. Reference the relevant tracking issue and close it.

## Audit hand-off

When this codebase enters audit:

- This file is part of the audit scope.
- Every `#[allow]` annotation in `crates/` and `tests/` should
  cross-reference an entry here.
- The audit firm is invited to challenge any entry; updates land via PR
  with their concurrence.
