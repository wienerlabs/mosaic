# Security Policy

## Status

**Phase 1 scope is frozen at tag
[`v0.1.0-phase1`](https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1).**
This file documents the policy for reporting vulnerabilities in that scope.

---

## Reporting a vulnerability

If you discover a security vulnerability in Mosaic, please **do not open a
public GitHub issue**. Instead, email <security@wienerlabs.com> (PGP key
coming soon) with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof-of-concept exploit.
- Your suggested mitigation, if you have one.
- Whether you would like public credit in the eventual disclosure.

Our response SLA and timeline is documented in
[`docs/responsible-disclosure-timeline.md`](docs/responsible-disclosure-timeline.md).

## In scope

Every crate inside this repository (workspace members under `crates/`) plus
the reference Solana program binary produced by
`cargo-build-sbf --manifest-path crates/mosaic-program/Cargo.toml`:

- `mosaic-core`
- `mosaic-groth16`
- `mosaic-plonk` *(Phase 2 — currently stub; scope covers the stub's return
  path only)*
- `mosaic-stark` *(Phase 3 — currently stub; same)*
- `mosaic-nova` *(Phase 3 — currently stub; same)*
- `mosaic-serde`
- `mosaic-chunked`
- `mosaic-program`
- `mosaic-sdk`

And published artifacts on crates.io once releases begin.

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

## Threat model and mitigations

For each of the following attack surfaces, the linked section of
[`docs/threat-model.md`](docs/threat-model.md) documents current mitigations
and residual risk.

| # | Threat | Mitigation reference |
|---|---|---|
| T-1 | Pairing accepts an invalid proof | [docs/threat-model.md § T-1](docs/threat-model.md#t-1-adversarial-proof-bytes--pairing-accept-on-invalid-proof) |
| T-2 | Public inputs ≥ BN254 scalar field order | [§ T-2](docs/threat-model.md#t-2-adversarial-public-inputs--values--scalar-field-order-r) |
| T-3 | Off-curve / wrong-subgroup points | [§ T-3](docs/threat-model.md#t-3-off-curve--wrong-subgroup-g1--g2-inputs) |
| T-4 | Length-mismatch panic via crafted bytes | [§ T-4](docs/threat-model.md#t-4-length-mismatch-crash-via-crafted-byte-slices) |
| T-5 | Validator divergence on error codes (consensus failure) | [§ T-5](docs/threat-model.md#t-5-validator-divergence-on-error-codes-consensus-failure) |
| T-6 | Chunked-upload reordering / commitment forgery | [§ T-6](docs/threat-model.md#t-6-chunked-upload-reordering--commitment-forgery) |
| T-7 | PDA squatting / cross-session aliasing | [§ T-7](docs/threat-model.md#t-7-pda-squatting--cross-session-aliasing) |
| T-8 | Timing side-channels | [§ T-8](docs/threat-model.md#t-8-timing-side-channels) |
| T-9 | Memory unsafety | [§ T-9](docs/threat-model.md#t-9-memory-unsafety) |
| T-10 | Arithmetic overflow | [§ T-10](docs/threat-model.md#t-10-arithmetic-overflow) |

Axes tracked for Phase-2 expansion (issue
[#63](https://github.com/wienerlabs/mosaic/issues/63)):

- Under-constrained circuit attacks — *scope boundary: out-of-scope; we
  verify proofs, not circuits.*
- Malleable proof vectors — *application responsibility; documented
  patterns.*
- Replay safety — *application responsibility; documented patterns.*

## Known unaudited components

| Component | Status |
|---|---|
| `mosaic-core` traits / error taxonomy / syscall surface | **Unaudited**. Phase 1 pre-release. |
| `mosaic-groth16` BN254 verifier | **Unaudited**. Algorithm parity with Light Protocol's `groth16-solana` cross-checked via 36-test suite; not formally reviewed. |
| `mosaic-serde` snarkjs adapter | **Unaudited**. Decimal-string parsing is a fuzzing target. |
| `mosaic-serde` arkworks adapter | **Unaudited**. Round-trip byte equality with snarkjs verified; not formally reviewed. |
| `mosaic-chunked` protocol + handlers | **Unaudited**. Design doc has explicit DoS enumeration (§ 7); implementation integration-tested. |
| `mosaic-program` reference dispatcher | **Unaudited**. |

External audit commission is tracked in issue
[#19](https://github.com/wienerlabs/mosaic/issues/19); pre-audit outreach
for slot reservation in issue
[#61](https://github.com/wienerlabs/mosaic/issues/61).

**We do not recommend using Mosaic for production value-bearing transactions
until at least one independent audit has landed.** See
[AUDIT.md](AUDIT.md) for current status.

## Our security posture

- **Memory safety:** every library crate has `#![forbid(unsafe_code)]`. Any
  future relaxation (e.g. the `unsafe-arena` feature, issue
  [#58](https://github.com/wienerlabs/mosaic/issues/58)) requires an
  `allow` exception in `deny.toml`, a written `SAFETY:` block, and a Miri
  CI job as the lockstep quality gate.
- **No hand-rolled cryptography:** see [README.md § Design principles](README.md#design-principles).
- **Consensus determinism:** see
  [`docs/threat-model.md` § T-5](docs/threat-model.md#t-5-validator-divergence-on-error-codes-consensus-failure).
- **Strict CI:** `cargo clippy` with hard-deny on
  `clippy::correctness + suspicious + todo + unimplemented`; pedantic /
  nursery visible as warnings. See
  [`docs/lint-policy.md`](docs/lint-policy.md) for the audit-facing
  suppression registry.
- **Supply chain:** `cargo-deny` for license + banned-crate checks;
  `cargo-audit` for CVE matching. `cargo-vet` attestation bootstrap in
  progress (issue [#59](https://github.com/wienerlabs/mosaic/issues/59)).
- **Fuzzing:** three `libfuzzer-sys` harnesses run on every PR (10 min)
  and nightly (4 h per harness).

## CVE assignment

For vulnerabilities we confirm and publish:

1. Wiener Labs is a CVE Numbering Authority applicant (as of 2026-04-20);
   pending approval we request CVEs through [MITRE's public form][mitre].
2. Affected versions documented in [`AUDIT.md`](AUDIT.md) with fix commit
   SHA and downstream advisory links.
3. GitHub Security Advisory created and linked from the CVE record.
4. RustSec advisory filed so `cargo-audit` flags it for dependents.

Reporters are credited by name (or handle) in the CVE record and
advisory unless they prefer anonymity.

[mitre]: https://cveform.mitre.org/

## Coordinated disclosure with Solana ecosystem

If a vulnerability potentially affects other Solana ZK projects (Light
Protocol, Bonsol, ZK Compression, etc.) we will coordinate disclosure with
the Solana Foundation security team and the respective project maintainers
under the standard [Solana security disclosure policy][solana-sdp].

[solana-sdp]: https://solana.com/docs/security-disclosure
