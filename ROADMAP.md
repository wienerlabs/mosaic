# Mosaic Roadmap

> Forward-looking plan. What's shipped lives in [`CHANGELOG.md`](CHANGELOG.md);
> what's been audited lives in [`AUDIT.md`](AUDIT.md). This doc is updated
> roughly weekly via PR — re-read it after each release tag.

Three horizons. Anything past the third horizon is not a commitment, it's
research direction.

---

## Now — this month

**Theme**: ship v1.0.0 mainnet-ready.

The audit-prep sprint produced v0.9.16-multi-system-demo. The remaining
delta from here to v1.0.0 is documented as the [mainnet-readiness
epic (#66)](https://github.com/wienerlabs/mosaic/issues/66).

| Status | Item | Tracked |
|---|---|---|
| 🟡 In progress | External audit commissioning — IronNode and Halborn conversations active | [#71](https://github.com/wienerlabs/mosaic/issues/71), [#72](https://github.com/wienerlabs/mosaic/issues/72) |
| 🟡 In progress | Devnet deployment + soak harness (24 h) | [#67](https://github.com/wienerlabs/mosaic/issues/67) |
| 🔴 Blocked on devnet | Mainnet `PROGRAM_ID` + deploy script | [#68](https://github.com/wienerlabs/mosaic/issues/68) |
| 🔴 Blocked on audit | Mainnet deployment | [#66](https://github.com/wienerlabs/mosaic/issues/66) |
| 🟢 Design done | Mainnet rollback + incident response playbook | [#69](https://github.com/wienerlabs/mosaic/issues/69) |
| 🟡 In progress | Multi-sig upgrade authority policy | [#86](https://github.com/wienerlabs/mosaic/issues/86) |

---

## Next — this quarter

**Theme**: close every Phase-3 scaffold gap so the full multi-system claim is
production-real, not lab-demo-real.

| Item | Tracked |
|---|---|
| HyperPlonk: Espresso reference fixture + integration | [#73](https://github.com/wienerlabs/mosaic/issues/73) |
| Halo2: full two-point batched opening | [#74](https://github.com/wienerlabs/mosaic/issues/74) |
| Nova: Spartan-wrapped multi-opening | [#75](https://github.com/wienerlabs/mosaic/issues/75) |
| FRI-STARK: Plonky3 reference + chunked execution (T-12) | [#76](https://github.com/wienerlabs/mosaic/issues/76) |
| HyperPlonk: Zeromorph partial reduction | [#77](https://github.com/wienerlabs/mosaic/issues/77) |
| `VerifyCompressedProof` SBF CU baselines in `bpf-bench` | [#84](https://github.com/wienerlabs/mosaic/issues/84) |
| Bug bounty program live (post-audit) | [#79](https://github.com/wienerlabs/mosaic/issues/79) |
| Reference dapp (private voting) deployed to mainnet | [#82](https://github.com/wienerlabs/mosaic/issues/82) |
| Cross-validator determinism cross-check on testnet | [#70](https://github.com/wienerlabs/mosaic/issues/70) |
| Coordinated disclosure protocol with Solana Foundation | [#87](https://github.com/wienerlabs/mosaic/issues/87) |

---

## Later — this year

**Theme**: ecosystem position. Close the Bonsol Groth16-wrap gap, ship the
SDK off Rust-only, stand up the hosted prover service that funds ongoing
development.

| Item | Tracked |
|---|---|
| Risc0Stark (`0x06`) dispatch arm — close the Bonsol CIRCOM-wrap | [#78](https://github.com/wienerlabs/mosaic/issues/78) |
| TypeScript SDK via wasm-bindgen | [#22](https://github.com/wienerlabs/mosaic/issues/22), [#45](https://github.com/wienerlabs/mosaic/issues/45) |
| Hosted prover service (production) | [#80](https://github.com/wienerlabs/mosaic/issues/80) |
| Tokenomics decision (commit or drop) | [#81](https://github.com/wienerlabs/mosaic/issues/81) |
| Documentation site at `docs.mosaic.wienerlabs.com` | [#36](https://github.com/wienerlabs/mosaic/issues/36) |
| Solana 3.0 program SDK migration | [#52](https://github.com/wienerlabs/mosaic/issues/52) |

---

## Beyond — research direction (not commitment)

- Recursive proof aggregation on chain (Nova-style folding deployed at scale)
- GPU-accelerated prover for the hosted service
- Multi-chain extension (Sei / Sui — same verifier core, different syscall stub)
- ZK-friendly hash function adoption when Solana ships SIMD-0233 (Poseidon
  inside alt_bn128 precompile)

---

## How to read this

- 🟢 = work designed, ready to start
- 🟡 = work in progress
- 🔴 = blocked on something else (named)
- ✅ = shipped; moved to CHANGELOG/AUDIT

This file is a snapshot. If you need the live view, the GitHub Project
board at <https://github.com/wienerlabs/mosaic/projects> is the source of
truth (track-by-track).

For the audit-firm scope handoff, the canonical document is
[`AUDIT-CHECKLIST.md`](AUDIT-CHECKLIST.md). For the threat model and
responsible-disclosure timeline, see [`SECURITY.md`](SECURITY.md) and
[`docs/threat-model.md`](docs/threat-model.md).
