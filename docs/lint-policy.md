# Lint Policy

> Audit-facing document. Every clippy `allow` in the codebase is justified
> here. Any new suppression requires an entry in this file with the
> reason and an issue link if it is expected to be lifted later.

## Layered enforcement

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
