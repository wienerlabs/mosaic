# Mosaic — Audit Request For Quote

**Status:** Draft, pending maintainer review. Not yet sent to firms.

## At a glance

| | |
|---|---|
| **Project** | Mosaic — multi-proving-system on-chain verifier library for Solana |
| **Organization** | Wiener Labs |
| **Language / runtime** | Rust (host + Solana SBF), `#![forbid(unsafe_code)]` |
| **Repository** | <https://github.com/wienerlabs/mosaic> |
| **Audit artifact** | [`v0.1.0-phase1`](https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1) — scope frozen, documentation audit-facing |
| **Scope (LoC)** | ~2 400 LoC in-scope library/program code + ~1 300 LoC test scaffolding |
| **Requested audit window** | *[TBD — suggest 2026-Q3]* |
| **Budget range** | *[TBD per firm's proposal — typical Solana + ZK engagements $30–80 K USD]* |
| **Primary contact** | *[@0raclus / security@wienerlabs.com]* |

## Why an audit now

Solana's ecosystem has exactly one production-grade on-chain ZK verifier
today (Light Protocol's `groth16-solana`). Every other proving system —
PLONK, Halo2-KZG, FRI-STARK, Risc0, Nova — requires awkward Groth16
wrapping on L1 or cannot be verified at all. Mosaic's Phase-1 ships a
proof-system-agnostic trait + first concrete implementation for BN254
Groth16 that matches Light Protocol's CU envelope and introduces a
chunked-upload protocol for proofs that exceed Solana's 1 232-byte
instruction limit.

The Phase-1 runtime surface is now **scope-frozen at
[`v0.1.0-phase1`](https://github.com/wienerlabs/mosaic/releases/tag/v0.1.0-phase1).**
Phase 2 adds KZG-PLONK + Halo2-KZG; Phase 3 adds FRI-STARK + folding
schemes. An independent external audit of Phase 1 before we ship Phase 2
is the gate we've committed to.

## Scope

### In scope

- `crates/mosaic-core/` — trait hierarchy, two-layer error taxonomy
  (29 on-chain error codes pinned at stable discriminants),
  `SyscallBackend` abstraction.
- `crates/mosaic-groth16/` — BN254 Groth16 verifier. Dual-endian via
  `LE_INPUTS` const generic (SIMD-0204 forward-compat). Host backend
  via `ark-bn254`, SBF backend via `solana-bn254` syscalls.
- `crates/mosaic-serde/` — **snarkjs + arkworks format adapters only**.
  Round-trip byte equality with `ArkworksCodec` / `SnarkjsCodec` is
  test-pinned.
- `crates/mosaic-chunked/` — session PDA layout, rolling-SHA-256
  protocol, instruction set (5 instructions).
- `crates/mosaic-program/` — reference Solana program dispatcher
  producing a 112 KB SBF ELF. Includes chunked-upload handler
  integration.
- `docs/adr/` (5 documents) — binding architectural decisions.
- `docs/design/0001-chunked-upload-handlers.md` — implementation
  contract with state machine, security reduction, DoS enumeration.
- `docs/threat-model.md` — T-1..T-10 adversarial input vectors.

### Out of scope

- `crates/mosaic-plonk/`, `mosaic-stark/`, `mosaic-nova/` — Phase 2/3
  stubs. They return `UnimplementedProofSystem`; only that return-path
  is in scope.
- `crates/mosaic-serde/src/{gnark,halo2,plonky3,risc0}.rs` — stubs.
- `crates/mosaic-sdk/` — host-only client library.
- `crates/mosaic-bench/`, `mosaic-fuzz/` — tooling crates.
- Upstream dependencies — audited by their own projects.

### What makes this audit interesting

- **Two-layer error taxonomy** (`OnChainError` vs `DiagnosticError`) as
  a structural defence against consensus failure — we want you to find
  any path where an off-chain diagnostic error can leak into the
  on-chain entry point. SIMD-0129 is the reference incident.
- **Rolling-hash chunked-upload protocol** — domain-separated SHA-256
  chain with PDA seeds bound to `(session_id, payer)`. The design doc
  provides the security reduction; we want you to break it.
- **LE / BE forward-compatibility** — the `LE_INPUTS` const generic
  exists for SIMD-0204 activation. We'd like validation that the
  endianness-swap surface is clean.
- **G2 byte-ordering (c0/c1 swap)** — Solana syscall convention differs
  from arkworks. Adapter layer does the swap; round-trip test pins it.
  Classic source of undetected bugs in Groth16-on-Solana
  implementations.

## Self-review artifacts

The repository intentionally maintains the review trail itself, so the
audit team can audit our audit discipline:

| Artifact | Role |
|---|---|
| [`AUDIT.md`](../../AUDIT.md) | Explicit in/out of scope; 12-item self-review checklist |
| [`SECURITY.md`](../../SECURITY.md) | Threat list T-1..T-10 with mitigation cross-links |
| [`docs/threat-model.md`](../threat-model.md) | Full adversarial-input analysis |
| [`docs/adr/`](../adr) | Binding architectural decisions |
| [`docs/design/0001-chunked-upload-handlers.md`](../design/0001-chunked-upload-handlers.md) | Chunked-upload implementation contract |
| [`docs/compute-unit-budget.md`](../compute-unit-budget.md) | Per-system CU caps + measured baselines |
| [`docs/lint-policy.md`](../lint-policy.md) | Clippy suppressions audited one-by-one |
| [`docs/responsible-disclosure-timeline.md`](../responsible-disclosure-timeline.md) | Disclosure SLA |
| [`supply-chain/`](../../supply-chain) | `cargo-vet` attestation bootstrap |
| [`CHANGELOG.md`](../../CHANGELOG.md) | Keep-a-Changelog / SemVer discipline |

## Testing posture

- **36 tests passing** in the tagged release: unit + on-chain
  integration (via `solana-program-test`) + round-trip + proptest
  differential against arkworks reference.
- **`bpf-bench`** measures real on-chain CU against ADR-0005 hard caps
  and blocks PRs that breach them (current Groth16 baseline:
  **80 296 CU** vs 180 000 CU cap).
- **`libfuzzer-sys`** harnesses for proof bytes, VK bytes, public
  inputs. PR-gated 10-minute runs, nightly 4-hour runs.
- **`cargo-deny`** + **`cargo-audit`** in CI for license, banned-crate,
  and advisory checks.

## Known unaudited components

Listed in [SECURITY.md § Known unaudited components](../../SECURITY.md#known-unaudited-components).
Summary: the entire Phase-1 scope is unaudited. No external audits
have been commissioned prior to this RFQ.

## Deliverables we expect

1. **Kick-off call** — 1 hour, shared vocabulary + scope confirmation.
2. **Weekly sync** — async summary + optional live call during audit.
3. **Findings document** — machine-readable (SARIF or markdown table)
   classifying by CVSS 3.1, with reproductions.
4. **Mitigation review** — one round where you re-verify our fixes.
5. **Public summary** — once findings are closed or mitigated, a public
   report we can link from [`AUDIT.md`](../../AUDIT.md).

## Timeline

- **Week 0** (RFQ sent) — this document reaches firms.
- **Week 0–2** — discovery calls with 2–4 firms.
- **Week 2–4** — quotes received, engagement signed.
- **Week 4–6** — audit firm ramp-up (context + environment).
- **Week 6–10** — active audit (exact duration per firm scoping).
- **Week 10–12** — mitigation round.
- **Week 12** — public report + `AUDIT.md` entry + 1.0-track release
  candidate preparation.

Timeline is flexible; the above is our default cadence to inform your
own scheduling.

## Commercial engagement details

### Payment

We pay via bank transfer in USD or EUR; USDC on Solana accepted.
Milestones: 30% on engagement signature, 40% on findings delivery, 30%
on mitigation verification.

### Confidentiality

Mutual NDA covering pre-disclosure vulnerability details. We commit to
the [disclosure timeline SLA](../responsible-disclosure-timeline.md);
firms are expected to reciprocate.

### Liability cap

Standard cap at 1× engagement fee. Not negotiating above this unless
engagement triggers extraordinary scope expansion.

## How to respond

Please reply to `security@wienerlabs.com` with:

1. **Confirmation of interest** and availability window.
2. **Quote** (fixed-fee preferred; T&M acceptable if scoped).
3. **Team composition** for the engagement (lead + reviewers).
4. **Similar-engagement references** (other BN254 / Groth16 / Solana
   ZK audits you have published).
5. **Any pre-audit questions** we can address before the discovery
   call.

Target turnaround for this RFQ: **10 business days** from the date
listed on the cover email.

---

*Wiener Labs, 2026-04. Prepared by @0raclus. This RFQ supersedes any
prior verbal scope discussion.*
