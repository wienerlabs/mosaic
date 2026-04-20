# Supply-chain attestation

Mosaic uses [`cargo-vet`](https://mozilla.github.io/cargo-vet/) to maintain
a peer-reviewed attestation chain for every crate in the dependency graph.

## Baseline (as of v0.1.0-phase1)

`cargo vet` against \`main\`:

```
Vetting Succeeded (74 fully audited, 2 partially audited, 689 exempted)
```

- **74 fully audited**: covered by imported audit feeds (Mozilla + Embark
  Studios + Bytecode Alliance).
- **2 partially audited**: partial coverage from import chain.
- **689 exempted**: phase-1 baseline. Every crate exempted here was in the
  dependency graph at the time of `cargo vet init`. Exemptions shrink over
  time as we import more audit feeds or perform our own audits — net-new
  unaudited dependencies require an explicit PR review.

## Running locally

```bash
cargo install cargo-vet --locked
cargo vet          # check current state
cargo vet suggest  # list crates that would benefit from audits
```

CI runs `cargo vet check` on every PR (see `.github/workflows/audit.yml`).

## Policy per crate

| Crate | Criteria | Rationale |
|---|---|---|
| `mosaic-core`, `mosaic-groth16`, `mosaic-plonk`, `mosaic-stark`, `mosaic-nova`, `mosaic-serde`, `mosaic-chunked`, `mosaic-program` | `safe-to-deploy` | Ship as on-chain or library code consumed by on-chain code. |
| `mosaic-sdk`, `mosaic-bench`, `mosaic-fuzz` | `safe-to-run` | Host-only tooling; compromise doesn't affect on-chain security. |

## Adding a new dependency

1. Make the dep change in the relevant `Cargo.toml`.
2. Run `cargo vet`.
3. If the command reports unaudited crates, either:
   - Run `cargo vet import <source> <url>` to add a new audit feed that
     covers the crate.
   - Add a `[[audits.<crate>]]` entry in [`audits.toml`](audits.toml) with
     your review notes.
   - Add a `[[exemptions.<crate>]]` entry with a written justification in
     PR description (rare; flagged in PR review).
4. Commit the updated attestation files in the same PR as the dep change.

## Running your own audit

```bash
cargo vet certify <crate> <version>
```

follow the prompts. The resulting entry lands in [`audits.toml`](audits.toml)
and is referenced by the `[policy.<crate>]` block in
[`config.toml`](config.toml).

## Audit feed imports

Listed in [`config.toml § imports`](config.toml). Currently:

- **mozilla** — Mozilla's Rust audit feed from mozilla-central.
- **bytecode-alliance** — Wasmtime / BCA maintainers.
- **embark-studios** — Embark Studios' ecosystem audits.

Google's audit feed was considered but the URL format change (2024)
requires a tracking cleanup; tracked as a follow-up.
