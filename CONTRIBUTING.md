# Contributing to Mosaic

Thanks for your interest in Mosaic! This document covers how to set up your
development environment, the conventions we follow, and how to land a PR.

## Getting started

### Prerequisites

- Rust **1.85.0** stable (host).
- Solana CLI **3.0.x** with `cargo-build-sbf` (for SBF target builds).
- `cargo-deny`, `cargo-audit`, `cargo-fuzz` (install on demand for the
  workflows you touch).

### Clone and build

```bash
git clone https://github.com/wienerlabs/mosaic
cd mosaic
cargo check --workspace                          # host check
cargo test  --workspace --all-features           # host tests
cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml   # SBF
```

The `--tools-version v1.52` flag is mandatory: the default v1.51
platform-tools ships rustc 1.84 which cannot parse `edition2024` in some
transitive deps (`constant_time_eq` via `blake3`). v1.52 ships rustc 1.89
which works.

## Conventions

### Code style

- `cargo fmt --all` before every commit (CI enforces).
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`
  must pass. We run `pedantic` + `nursery` lints; allows are documented in
  workspace `Cargo.toml`.
- Every public item has a `///` rustdoc.
- Every crate has a crate-level `//!` block.
- `#![forbid(unsafe_code)]` is mandatory in library crates.

### Commit messages

Use the [Conventional Commits][cc] format:

```
feat(groth16): add LE_INPUTS const generic for SIMD-0204
fix(serde): handle snarkjs c0/c1 G2 ordering correctly
docs(adr): amend ADR-0001 to clarify object-safety rationale
```

[cc]: https://www.conventionalcommits.org/

### Branch and PR flow

1. Branch from `main`.
2. Make focused commits — one logical change per commit.
3. Open a PR with:
   - A summary of the change and the motivating context.
   - A test plan (unit / fuzz / on-chain coverage).
   - Links to any ADRs you amended or created.
4. CI must be green before merge: `fmt`, `clippy`, host tests, SBF build,
   docs, MSRV check.
5. PRs that touch:
   - the `mosaic-core` trait hierarchy require an ADR amendment.
   - the `OnChainError` discriminants require updating the
     `discriminant_stability` test and an entry in `AUDIT.md`.
   - per-system CU budgets require updating ADR-0005 and bench thresholds.

## Testing

### Unit tests

```bash
cargo test -p <crate-name>
```

### Differential tests

```bash
cargo test --test differential --all-features
```

These run the host backend against arkworks and assert byte-for-byte
identical results.

### Fuzzing

```bash
cd crates/mosaic-fuzz
cargo +nightly fuzz run fuzz_groth16_proof_bytes -- -max_total_time=600
```

### On-chain CU regression

```bash
cargo build-sbf --manifest-path crates/mosaic-program/Cargo.toml
cargo run --release -p mosaic-bench --bin bpf-bench
```

## Where to start (good first issues)

- **Adapter implementations**: pick gnark / halo2-kzg / plonky3 / risc0 and
  write the codec module mirroring `mosaic-serde::snarkjs`.
- **Fixtures**: contribute representative proof + VK fixtures from real
  circuits (Circom, gnark, halo2). Place under `tests/fixtures/<format>/`
  with a brief README.
- **CU optimization**: improve the Groth16 pairing input layout, batch
  MSM amortization, or shave deserialization overhead. Always paired with
  a `bpf-bench` measurement.
- **Documentation**: tutorials, recipes, ADR amendments.

## Code of conduct

Be kind. Disagree about technical merits, never about people. We follow the
[Rust Code of Conduct][rust-coc].

[rust-coc]: https://www.rust-lang.org/policies/code-of-conduct

## License

Contributions are dual-licensed under [Apache-2.0](LICENSE-APACHE) and
[MIT](LICENSE-MIT) at the contributor's option, matching the repository's
license.
