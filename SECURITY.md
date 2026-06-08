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
public GitHub issue**. Instead, email <security@wienerlabs.com> (PGP key
coming soon) with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof-of-concept exploit.
- Your suggested mitigation, if you have one.

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

## Risk Mitigation

To mitigate the identified risks, we have implemented the following strategies:

1. **Multisig Escrow Configuration**: We have configured the multisig escrow to follow a 2-of-3 Squads V4 design, ensuring robust control and security.
2. **Regular Audits and Testing**: The solution is continuously audited by an external audit commission and rigorously tested for vulnerabilities.
3. **Secure Development Practices**: Adherence to secure coding practices and the use of proven cryptographic libraries are enforced throughout the development process.

## Conclusion

We are committed to maintaining the highest standards of security in Mosaic and appreciate your cooperation in responsibly reporting any potential vulnerabilities.