# Security Policy

## Status

**Pre-mainnet review window — v0.9.13-phase3-compression (2026-05-02).**
The audit-prep sprint that ran from sessions 86 to 114 (v0.9.0 → v0.9.13)
delivered:

- All six BN254-curve verifiers implemented (Groth16, KZG-PLONK,
  HyperPlonk, Halo2, Nova/HyperNova/ProtoStar) plus FRI-STARK
  (Plonky3 family).
- alt_bn128 compression infrastructure across all five BN254-curve
  verifiers (proof + VK round-trips, fuzz coverage, criterion benches).
- 712 lib tests + 37 fuzz harnesses + 14 criterion benches +
  10 SBF integration tests.
- Audit-coverage runbook + per-gate isolation benches +
  bpf-bench dispatch byte-fix (s113).

External audit commission is the next gate. See
[`AUDIT-CHECKLIST.md`](AUDIT-CHECKLIST.md) for the full crate-by-crate
scope / non-scope / known-limitations matrix that audit firms should
review before sending a quote.

---

## Reporting a vulnerability

If you discover a security vulnerability in Mosaic, please **do not open a
public GitHub issue**. Instead, email <baturalp@wienerlabs.com> (PGP key
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

- `mosaic-core` — verifier trait + error taxonomy + syscall abstraction
- `mosaic-zk-primitives` — shared cryptographic primitives (12+ helpers)
- `mosaic-groth16` — single + Bowe-Gabizon batched verifier
- `mosaic-plonk` — KZG-PLONK BN254 verifier
- `mosaic-hyperplonk` — HyperPlonk KZG BN254 verifier
- `mosaic-halo2` — Halo2 KZG BN254 verifier (PSE fork-compatible)
- `mosaic-stark` — FRI-STARK Goldilocks/BabyBear/Mersenne31
- `mosaic-nova` — Nova / HyperNova / ProtoStar folding verifier
- `mosaic-serde` — snarkjs + arkworks adapters (gnark stub)
- `mosaic-chunked` — chunked-upload protocol + handlers
- `mosaic-program` — reference Solana on-chain dispatcher (cdylib)
- `mosaic-sdk` — off-chain transaction builder helpers

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
| T-11 | Compression-syscall round-trip divergence | [§ T-11](docs/threat-model.md#t-11-compression-syscall-round-trip-divergence-sessions-103-114) |
| T-12 | Chunked-STARK CU exhaustion / single-tx infeasibility | [§ T-12](docs/threat-model.md#t-12-chunked-stark-cu-exhaustion--single-tx-infeasibility) |

Scope-boundary axes documented in [`docs/threat-model.md`](docs/threat-model.md#scope-boundaries-and-application-responsibilities):

| # | Axis | Where Mosaic draws the line |
|---|---|---|
| Axis 1 | Under-constrained circuit attacks | *Out-of-scope by design*; tooling references (Picus, Ecne, ZK-NavigatOR) provided. |
| Axis 2 | Malleable proof vectors | Application responsibility via nullifier / nonce set; chunked-upload's `session_id` is a worked example. |
| Axis 3 | Validator determinism | Extends T-5; covers arithmetic, iteration order, allocator. |
| Axis 4 | Replay safety + instruction binding | Application responsibility; guidance patterns documented. |

## Known unaudited components

| Component | Status (v0.9.13) |
|---|---|
| `mosaic-core` traits / error taxonomy / syscall surface | **Unaudited.** Trait + error code stability frozen since v0.5.0; `#[non_exhaustive]` enums for forward-compat. |
| `mosaic-zk-primitives` shared cryptographic helpers | **Unaudited.** Internal extraction (sessions 90-95); 9 primitives lifted from per-verifier duplicates. |
| `mosaic-groth16` BN254 verifier (single + batched) | **Unaudited.** Algorithm parity with Light Protocol's `groth16-solana` cross-checked via 36+ tests + arkworks differential harness. |
| `mosaic-plonk` KZG-PLONK BN254 verifier | **Unaudited.** snarkjs PLONK 0.7.6 differential test landed at v0.6.0; SBF integration test landed at v0.9.12. |
| `mosaic-hyperplonk` KZG BN254 verifier | **Unaudited; Phase-3 scaffold.** Espresso-reference fixture differential test pending session 118. Compression API at v0.9.13. |
| `mosaic-halo2` KZG BN254 verifier (PSE fork) | **Unaudited; Phase-3 scaffold.** Multi-column lookup wired at v0.9.1; multi-lookup at v0.9.6; compression at v0.9.5/.7/.8. |
| `mosaic-stark` FRI-STARK | **Unaudited; Phase-3 scaffold.** Plonky3-reference fixture pending; alt_bn128 compression N/A (field-only). **Chunked-only on chain:** a production-shaped proof (~7.8M CU) exceeds the 1.4M per-transaction cap, so STARK MUST be verified via the chunked path (`verify_setup` + `verify_query_range`, driven by `BeginStarkVerify` / `StarkVerifyStep`), never single-shot `VerifyProof`. This mitigates T-12. SDK: `build_chunked_stark_plan`. |
| `mosaic-nova` Nova/HyperNova/ProtoStar | **Unaudited; Phase-3 scaffold.** sonobe-reference fixture pending session 118. Compression at v0.9.13. |
| `mosaic-serde` snarkjs adapter | **Unaudited.** Decimal-string parsing is fuzzed (4 harnesses). |
| `mosaic-serde` arkworks adapter | **Unaudited.** Round-trip byte equality with snarkjs verified. |
| `mosaic-chunked` protocol + handlers | **Unaudited.** Design doc § 7 enumerates DoS surface; integration-tested via `chunked_handlers.rs`. Session layout v2 adds the `StarkVerifyProgress` resumable-verification cursor (chunked STARK, #76), end-to-end tested in `chunked_stark.rs`. |
| `mosaic-program` reference dispatcher | **Unaudited.** SBF integration tests at v0.9.12 cover all 8 declared bytes + 2 negative paths (10 tests). |
| **alt_bn128 compression infra (s103-114)** | **Unaudited.** Round-trip + fuzz coverage across all 5 BN254 verifiers. Wire format only — never on the verify path. |

External audit commission is tracked in issue
[#19](https://github.com/wienerlabs/mosaic/issues/19); pre-audit outreach
for slot reservation in issue
[#61](https://github.com/wienerlabs/mosaic/issues/61). The
[`AUDIT-CHECKLIST.md`](AUDIT-CHECKLIST.md) document is the
crate-by-crate scope handoff — audit firms should grep that for
deliverable boundaries.

**We do not recommend using Mosaic for production value-bearing transactions
until at least one independent audit has landed.** See
[AUDIT.md](AUDIT.md) for the per-release audit log.

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
- **Fuzzing:** **37 `libfuzzer-sys` harnesses** at v0.9.13 (was 3 at
  v0.1.0). PR matrix runs 22 representative harnesses for 5 min each
  (~110 min wall-clock); nightly runs the full 37-target sweep for
  60 min per harness (~37 hours, in 2 parallel batches under
  GitHub's 20-concurrent-runner cap). See
  [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml) for
  the matrix.
- **Compression round-trip safety:** every BN254-curve verifier has
  fuzzed compression APIs (4 harnesses for Phase-3 + 6 for Phase-2 =
  10 total). Round-trip tests on real BN254 generators confirm
  bit-for-bit reproduction; pass-through invariants confirm non-curve
  fields survive compression unmodified.
- **SBF runtime evidence:** session 113 added 10 SBF integration
  tests covering every declared `ProofSystemId` discriminant byte
  (8 known + 1 alias + 1 unknown-byte negative) against the real
  `solana-program-test` runtime (rbpf VM, not the host arkworks
  mock).

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
under the standard [Solana security disclosure policy][solana-sdp]. The
trigger conditions, ecosystem contact tree, embargo timeline, and shared
advisory format are specified in
[`docs/coordinated-disclosure.md`](docs/coordinated-disclosure.md).

[solana-sdp]: https://solana.com/docs/security-disclosure
