# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in Mosaic, please **do not open a
public GitHub issue**. Instead, email <security@wienerlabs.com> with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof-of-concept exploit.
- Your suggested mitigation, if you have one.
- Whether you would like public credit in the eventual disclosure.

We aim to:

- **Acknowledge receipt within 48 hours.**
- Provide an initial assessment within 5 business days.
- Coordinate a disclosure timeline with you, typically 90 days from
  acknowledgement to public disclosure (shorter if the vulnerability is
  being actively exploited).

## In scope

This policy covers all crates in this repository:

- `mosaic-core`
- `mosaic-groth16`
- `mosaic-plonk` *(Phase 2 — currently stub)*
- `mosaic-stark` *(Phase 3 — currently stub)*
- `mosaic-nova` *(Phase 3 — currently stub)*
- `mosaic-serde`
- `mosaic-chunked`
- `mosaic-program`
- `mosaic-sdk`

And the published artifacts on crates.io once releases begin.

## Out of scope

- Vulnerabilities in upstream dependencies (`arkworks`, `solana-program`,
  `light-poseidon`, `sha2`, `tiny-keccak`, etc.) — please report those to
  the respective projects. We will track downstream impact in this repo.
- Vulnerabilities in proving systems themselves (Groth16 trust setup,
  Halo2 implementation, etc.).
- DoS via legitimate-but-expensive proofs that fit within the declared CU
  budget. CU exhaustion is an accepted attack and mitigated by client-side
  budgeting, not in-protocol.
- Issues in client-side key management — Mosaic is not a wallet.
- Issues in our test fixtures or benchmark harnesses.

## Known unaudited components

| Component | Status |
|---|---|
| `mosaic-core` traits / error taxonomy / syscall surface | **Unaudited**. Phase 1 bootstrap. |
| `mosaic-groth16` BN254 verifier | **Unaudited**. Mirrors Light Protocol `groth16-solana` algorithmically but is a cleanroom implementation. |
| `mosaic-serde` snarkjs adapter | **Unaudited**. Decimal-string parsing path is a fuzzing target. |
| `mosaic-chunked` data model | **Unaudited**. Instruction handlers not yet implemented. |
| `mosaic-program` reference dispatcher | **Unaudited**. |

We do not recommend using Mosaic for production value-bearing transactions
until at least one independent audit has landed. See [AUDIT.md](AUDIT.md)
for current status.

## Our security posture

- **Memory safety:** every library crate has `#![forbid(unsafe_code)]`. Any
  future relaxation requires an `allow` exception in `deny.toml` and a
  written `SAFETY:` block.
- **No hand-rolled cryptography:** see [README.md § Design principles](README.md#design-principles).
- **Consensus determinism:** see [docs/threat-model.md § T-5](docs/threat-model.md#t-5-validator-divergence-on-error-codes-consensus-failure).
- **Strict CI:** `cargo clippy -- -D warnings` with `pedantic` + `nursery`,
  `cargo deny check`, `cargo audit`, scheduled fuzzing — see
  [.github/workflows/](.github/workflows/).

## Coordinated disclosure with Solana ecosystem

If a vulnerability potentially affects other Solana ZK projects (Light
Protocol, Bonsol, ZK Compression, etc.) we will coordinate disclosure with
the Solana Foundation security team and the respective project maintainers
under the standard [Solana security disclosure policy][solana-sdp].

[solana-sdp]: https://solana.com/docs/security-disclosure
