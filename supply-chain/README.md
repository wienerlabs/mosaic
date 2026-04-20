# Supply-chain attestation

Mosaic uses [`cargo-vet`](https://mozilla.github.io/cargo-vet/) to maintain
a peer-reviewed attestation chain for every crate in the dependency graph.

## Status

**Phase 1 bootstrap.** Configuration files exist
([`config.toml`](config.toml), [`audits.toml`](audits.toml)) and point at
imports from Mozilla, Google, Bytecode Alliance, and Embark Studios, but
the full import chain has not been run and CI gating is not yet enforced.
Full setup tracked by
[issue #59](https://github.com/wienerlabs/mosaic/issues/59).

## Why this matters to auditors

A working `cargo-vet` setup lets an auditor verify:

- Every dependency in our transitive graph has been reviewed by *someone*
  we trust (Mozilla, Google, BCA, Embark, or Wiener Labs).
- Policy-level constraints (`safe-to-deploy` vs `safe-to-run`) are enforced
  via `[policy.<crate>]` blocks in [`config.toml`](config.toml).
- New dependencies cannot land without an explicit `audits.toml` entry or
  an exemption with a written justification.

## Running locally

```bash
cargo install cargo-vet --locked
cargo vet check
```

First run may report unaudited crates — these will become explicit
exemptions or receive audit entries as issue #59 progresses.

## Policy

| Crate | Criteria | Rationale |
|---|---|---|
| `mosaic-core`, `mosaic-groth16`, `mosaic-plonk`, `mosaic-stark`, `mosaic-nova`, `mosaic-serde`, `mosaic-chunked`, `mosaic-program` | `safe-to-deploy` | Ship as on-chain or library code consumed by on-chain code. |
| `mosaic-sdk`, `mosaic-bench`, `mosaic-fuzz` | `safe-to-run` | Host-only tooling; compromise doesn't affect on-chain security. |

## Adding a new dependency

1. Make the dep change in the relevant `Cargo.toml`.
2. Run `cargo vet check`.
3. For each new unaudited version, either:
   - Import an existing audit (bump the relevant `[imports.<author>]`).
   - Add a `[[audits.<crate>]]` entry in [`audits.toml`](audits.toml)
     with your review notes.
   - Add an `[[exemptions.<crate>]]` entry with a written justification
     (rare; flagged in PR review).
4. Commit the updated attestation files in the same PR as the dep change.
