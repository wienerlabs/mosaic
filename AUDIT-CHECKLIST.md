# Audit Checklist

> **For external review firms.** This document is the crate-by-crate
> scope handoff for an external audit of Mosaic at tag
> `v0.9.14-audit-checklist`. Read it end-to-end before sending a
> quote — every section is a deliverable boundary, every "Out of
> scope" is a deliberate non-goal.

For session-by-session implementation history see
[`AUDIT.md`](AUDIT.md). For the responsible-disclosure policy and
threat model see [`SECURITY.md`](SECURITY.md) and
[`docs/threat-model.md`](docs/threat-model.md).

---

## Repository at a glance

| Field | Value |
|---|---|
| Languages | Rust (workspace), no_std-compatible library crates, stdlib-only test infra |
| Targets | x86_64-unknown-linux-gnu (host), sbf-solana-solana (on-chain) |
| MSRV | 1.85.0 |
| Lib tests | 712 |
| Fuzz harnesses | 37 (`libfuzzer-sys`) |
| Criterion benches | 14 |
| SBF integration tests | 10 |
| Differential test fixtures | snarkjs CIRCOM (Groth16), snarkjs PLONK 0.7.6 (PLONK), arkworks (Groth16) |
| External audit | Not yet commissioned |
| Reproducible build | `cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml` |

---

## Crate inventory

### `mosaic-core` — verifier trait + error taxonomy + syscall abstraction

**In scope.**
- `ProofSystem` object-safe trait (returns `Result<(), OnChainError>`).
- `OnChainError` enum (deterministic, `#[non_exhaustive]`, stable
  discriminants documented in `error.rs`).
- `SyscallBackend` abstraction: trait with `alt_bn128_*`, `keccak256`,
  `sha256`, `poseidon` methods; two implementations
  (`SolanaSyscallBackend` for on-chain, `HostBackend` for host-side
  testing via arkworks).
- `ProofSystemId` enum + on-chain dispatcher byte mapping (`0x01`
  through `0x08`).

**Out of scope.**
- Arkworks correctness (we depend on `ark-bn254 = "0.5.0"`; defer to
  upstream).
- Solana program runtime correctness (`solana-program = "2.1.0"`).

**Known limitations.**
- `Risc0Stark` (`0x06`) returns `UnimplementedProofSystem` —
  intentional reservation, not a bug.
- The `host-backend` and `solana` features can be simultaneously
  active in test builds (dev-deps of downstream crates do this); both
  are additive but the dual-active path isn't exercised in
  production.

**Reproduce.**
```text
cargo test -p mosaic-core --lib
```

---

### `mosaic-zk-primitives` — shared cryptographic primitives

**In scope.**
- 12+ primitives extracted from per-verifier duplicates (sessions
  90-95): `field::*`, `g1_consts::*`, `compression::*`, `kzg::*`,
  `transcript::*`, `msm::*`.
- BN254 generator constants (`g1_generator_bytes`,
  `g2_generator_bytes`).
- alt_bn128 compression helpers (`compress_g1`, `compress_g2`,
  `decompress_g1`, `decompress_g2`).

**Out of scope.**
- The arkworks scalar / field arithmetic (we wrap, we don't
  reimplement).
- Subgroup-check correctness when the underlying syscall is the
  authority (the host backend's mock implements arkworks
  `is_in_correct_subgroup_assuming_on_curve` directly; SBF defers to
  the syscall — see T-3 in `docs/threat-model.md`).

**Known limitations.**
- `light-poseidon` is depended on for host-side Poseidon; the SBF
  backend uses Solana's `solana-poseidon = "2.3"` syscall. Behavior
  parity is asserted via differential tests in `mosaic-zk-primitives`'s
  `kzg.rs` module but the parity is *configuration-dependent*
  (Poseidon parameter sets must match exactly).

**Reproduce.**
```text
cargo test -p mosaic-zk-primitives --lib
```

---

### `mosaic-groth16` — single + Bowe-Gabizon batched verifier

**In scope.**
- Single-proof verification via `ProofSystem::verify`.
- Bowe-Gabizon aggregation: N proofs sharing one VK fold into a
  single `alt_bn128_pairing` syscall (8 pairs).
- Compressed proof + VK round-trip (sessions 108-109).

**Out of scope.**
- Trusted-setup ceremony correctness (a snarkjs-emitted VK is
  trusted-as-input; circuit-level constraint correctness is the
  prover's responsibility — see Axis 1 in `docs/threat-model.md`).
- Risc0-in-Circom Groth16 wrapping (Bonsol's responsibility).

**Known limitations.**
- Algorithm parity with Light Protocol's `groth16-solana` is
  cross-checked via 36+ tests + arkworks differential harness.
  *No formal audit has confirmed the parity beyond test coverage.*
- Batch verification scales linearly in CU above N=5 — past that the
  Σ r_i scalar multiplication dominates.

**Reproduce.**
```text
cargo test -p mosaic-groth16 --lib
cargo run -p tests-differential --bin groth16_diff_arkworks
cargo run -p tests-differential --bin groth16_diff_snarkjs
```

**SBF runtime evidence.** Tests
`sbf_verify_proof_succeeds_on_valid_groth16` and
`sbf_rejects_tampered_groth16_proof` in
`crates/mosaic-program/tests/verify_proof_sbf.rs`.

---

### `mosaic-plonk` — KZG-PLONK BN254 verifier

**In scope.**
- Full PLONK pipeline: linearization MSM + KZG batched opening +
  pairing.
- snarkjs PLONK 0.7.6 differential test (real-world prover output).
- Compressed proof + VK round-trip (session 110).

**Out of scope.**
- Halo2-style accumulation / IPA commitments (separate verifier).
- snarkjs versions other than 0.7.6 (forward-compat tracked in
  issue #50).

**Known limitations.**
- CU baseline at 968 457 (re-measured 2026-04-23 under
  opt-level="z" profile). Hard cap raised to 1.1 M for 13%
  regression headroom.
- Linearization-polynomial MSM is the dominant CU consumer; tighter
  packing tracked by issue #37.

**Reproduce.**
```text
cargo test -p mosaic-plonk --lib
cargo run -p tests-differential --bin plonk_diff_snarkjs
```

**SBF runtime evidence.**
`sbf_verify_proof_succeeds_on_valid_plonk` in
`verify_proof_sbf.rs`.

---

### `mosaic-hyperplonk` — HyperPlonk KZG BN254 verifier

**In scope.**
- Sumcheck pipeline (parse → challenges → claim reduction → KZG).
- `HyperPlonkVerifyingKey` (8 G1 + 1 G2 + 3 Fr cosets).
- Compressed proof + VK round-trip (session 114).

**Out of scope (Phase-3 scaffold caveats).**
- Full Zeromorph / PST / Gemini reduction (canonical layout
  breaking change, planned post-audit).
- Espresso-reference fixture differential test (session 118).

**Known limitations.**
- The current verifier accepts a scaffold-shaped proof of
  `(num_variables=10, n_public=1, all-zero commits)` — see test
  `full_pipeline_zero_proof_accepts`. **This is not a soundness
  bug** — it's the documented scaffold acceptance shape until
  prover-emitted fixtures land. A real Espresso-emitted proof will
  fail the current pipeline at the claim-reduction permutation step
  because that step is approximated, not exact. Tightening tracked
  by session 117.
- Multi-lookup support (n_lookups ≥ 2) is wired in `mosaic-halo2`
  but not yet in `mosaic-hyperplonk`.

**Reproduce.**
```text
cargo test -p mosaic-hyperplonk --lib
```

**SBF runtime evidence.**
`sbf_dispatches_hyperplonk_kzg_scaffold` in `verify_proof_sbf.rs`.

---

### `mosaic-halo2` — Halo2 KZG BN254 verifier (PSE fork-compatible)

**In scope.**
- Full Halo2 pipeline: parse → challenges (θ, β, γ, y, ξ) → KZG
  multi-poly batched opening.
- Multi-column lookup (arity ≥ 2) end-to-end + KZG-bound (v0.9.1).
- Multi-lookup (n_lookups ≥ 2) with distinct y-power weighting for
  soundness (v0.9.6).
- Compressed proof + VK round-trip (sessions 105-108).

**Out of scope.**
- PSE Halo2 IPA / accumulation (we implement KZG variant only).
- Custom-gate flexibility — Mosaic targets the standard PSE fork's
  fixed gate set + dynamic lookup width.

**Known limitations.**
- Phase-3 scaffold caveats apply: the current pipeline accepts the
  PSE-style "5 advice + 0 lookup + 3 quotient + 19 evals" scaffold
  but real-world circuits with custom gate compositions outside
  this shape are tracked by sessions 117-119.
- VK fixed-commit ordering is opinionated to PSE's selector layout
  (q_M / q_L / q_R / q_O / q_C); other forks need an adapter.

**Reproduce.**
```text
cargo test -p mosaic-halo2 --lib
```

**SBF runtime evidence.**
`sbf_dispatches_halo2_kzg_scaffold` in `verify_proof_sbf.rs`.

---

### `mosaic-stark` — FRI-STARK Goldilocks/BabyBear/Mersenne31

**In scope.**
- Structural FRI-STARK pipeline: parse → challenges (α, z,
  query_seed) → per-query index derivation → dual-Merkle path
  verification → FRI fold-chain check.
- Three field tower variants (Goldilocks 64-bit, BabyBear 31-bit,
  Mersenne31 31-bit).

**Out of scope.**
- alt_bn128 compression (STARK proofs carry no BN254 curve points).
- Risc0 zkVM-specific STARK proofs (`Risc0Stark = 0x06`
  → `UnimplementedProofSystem`).
- Plonky3 prover-side details — we are pure verifier.

**Known limitations.**
- **Single-tx infeasibility for production STARK shapes.** See T-12
  in `docs/threat-model.md`. Production callers MUST use the
  chunked-upload path; the SBF integration test uses the smallest
  passing depth-zero shape that fits in 1.4 M CU.
- Plonky3-reference fixture differential test pending session 118.
- AIR-hash binding to circuit identity is a `[u8; 32]` opaque
  digest in the VK — the digest's collision-resistance is the
  prover's setup-time responsibility.

**Reproduce.**
```text
cargo test -p mosaic-stark --lib
```

**SBF runtime evidence.**
`sbf_dispatches_fri_stark_scaffold` in `verify_proof_sbf.rs`
(depth-zero Merkle, fits in single tx).

---

### `mosaic-nova` — Nova / HyperNova / ProtoStar folding verifier

**In scope.**
- Folded-instance verifier: parse → challenges → Hadamard-relation
  check → folded-commitment reconstruction → KZG opening.
- Three folding variants (Nova `0x00`, HyperNova `0x01`, ProtoStar
  `0x02`) — ProtoStarFolding (`ProofSystemId = 0x08`) shares the
  Nova verifier per dispatcher.
- Compressed proof + VK round-trip (session 114).

**Out of scope (Phase-3 scaffold caveats).**
- Spartan / Hyrax inner verification (currently scaffolded).
- sonobe-reference fixture differential test (session 118).
- HyperNova higher-degree gate flexibility beyond the
  `num_aux_commits ≤ 16` cap.

**Known limitations.**
- Compressed VK depends on `cs_digest` for circuit identity; the
  prover-side ceremony is responsible for digest collision-resistance.
- Hadamard-relation check accepts the trivial all-zero proof under
  the scaffold-acceptance fixture — same caveat as HyperPlonk.

**Reproduce.**
```text
cargo test -p mosaic-nova --lib
```

**SBF runtime evidence.**
- `sbf_dispatches_nova_folding_scaffold` (canonical `0x07`).
- `sbf_dispatches_protostar_via_nova_verifier` (alias `0x08`).

---

### `mosaic-serde` — snarkjs + arkworks adapters

**In scope.**
- snarkjs JSON → canonical bytes (Groth16, PLONK).
- arkworks `CanonicalSerialize` → canonical bytes (Groth16).
- Decimal-string parsing for PLONK 0.7.6 (`uint256` decimal text).

**Out of scope.**
- gnark / halo2 / plonky3 / risc0 adapters (stubs in workspace).
- snarkjs versions other than the pinned reference set.

**Known limitations.**
- snarkjs JSON is parsed via `serde_json` with `alloc` only —
  large file safety is gated by the SDK's chunked-upload caller.
- The decimal-string parser surface is fuzzed (4 harnesses).

**Reproduce.**
```text
cargo test -p mosaic-serde --lib
cargo +nightly fuzz run fuzz_serde_snarkjs_decimal -- -max_total_time=300
```

---

### `mosaic-chunked` — chunked-upload protocol + handlers

**In scope.**
- Session-bound multi-tx upload: `session_id: [u8;32] ‖ total_len:
  u32 LE ‖ proof_system_id: u8 ‖ h_0: [u8;32]`.
- Per-chunk Merkle-extending append digest (`h_{i+1} = H(h_i ‖
  chunk_bytes)`).
- Final commit-and-verify: dispatcher routes to the per-system
  verifier on the assembled buffer.

**Out of scope.**
- PDA scheme correctness for application-layer session-id encoding
  (SDK's responsibility; see Axis 4 in `docs/threat-model.md`).
- Reorg-handling for chunk-tx ordering (Solana runtime guarantees
  same-slot atomicity within a transaction; cross-tx sequencing is
  the caller's responsibility).

**Known limitations.**
- DoS surface enumerated in design doc § 7. Mitigation is per-tx
  CU budget, not in-protocol.
- Currently each VerifyProof is a single instruction; chunked-tx
  invocations are wrapped by the application layer's PDA strategy.

**Reproduce.**
```text
cargo test -p mosaic-chunked --lib
cargo test -p mosaic-program --test chunked_handlers
```

---

### `mosaic-program` — reference Solana on-chain dispatcher

**In scope.**
- `cdylib` SBF entrypoint at PROGRAM_ID
  `MosA1cVer1f1er11111111111111111111111111111`.
- `VerifyProof` (instruction tag `0x01`): dispatches by
  `ProofSystemId` byte to per-system verifier.
- `VerifyProofBatch` (instruction tag `0x02`): only Groth16 has
  true amortization; other systems return `UnsupportedOperation`.
- Chunked-upload handlers (init / append / commit-and-verify).

**Out of scope.**
- Account-data persistence for application state — Mosaic doesn't
  manage user accounts; PDAs are caller-driven.
- Risc0Stark dispatch arm returns `UnimplementedProofSystem` (0x11).

**Known limitations.**
- Borsh-decode → discriminant-parse → SBF VM execution path now
  has 10 SBF integration tests covering every declared byte +
  unknown-byte rejection (session 113). `bpf-bench` runs these
  bytes against the cu-baseline ceiling per ADR-0005.
- Pre-mainnet CU drift fixed in session 113: the bpf-bench
  harness's previously-swapped Nova/FriStark byte mapping
  (a pre-audit `MEDIUM` finding) is corrected with audit trail.

**Reproduce.**
```text
cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml
BPF_OUT_DIR=target/deploy cargo test -p mosaic-program --test verify_proof_sbf
cargo run --release -p mosaic-bench --bin bpf-bench
```

---

### `mosaic-sdk` — off-chain transaction builder helpers

**In scope.**
- TS-friendly Rust API surface: builders for `VerifyProof`,
  `VerifyProofBatch`, chunked-upload sessions.
- Helpers for the snarkjs adapter pre-canonicalization.

**Out of scope.**
- Wallet interaction (key management is the consuming
  application's responsibility — Mosaic is not a wallet).
- TS bindings (the `solana-web3.js`-level SDK is a separate
  workstream; the Rust SDK serves Rust callers + downstream
  tooling).

---

## Cross-cutting deliverables

### Compression infrastructure (sessions 103-114)

**Surfaces under audit.**

| Verifier | Proof API | VK API | Saving (proof) | Saving (VK) |
|---|---|---|---|---|
| Groth16 | ✓ | ✓ | 50 % | 50 % |
| KZG-PLONK | ✓ | ✓ | 37.5 % | 43 % |
| Halo2 | ✓ | ✓ | variable | 43 % |
| HyperPlonk | ✓ | ✓ | 160 B constant | 43 % |
| Nova | ✓ | ✓ | (9 + num_aux)·32 B | 45 % |
| FRI-STARK | N/A | N/A | — | — |

**Audit boundaries.**

- The `compress_*` / `decompress_*` APIs are wire-format only —
  they are NEVER invoked by the on-chain verify path. A divergence
  between host arkworks and SBF syscall would NOT cause an on-chain
  verify to accept an invalid proof; it would corrupt off-chain
  transport and surface as a *parse error* on the on-chain side
  (the byte format would no longer match the canonical layout).
- 4 fuzz harnesses per Phase-2 verifier (Groth16, PLONK, Halo2) +
  4 for Phase-3 (HyperPlonk, Nova) = 10 total fuzz harnesses
  asserting the panic-free invariant.
- 14 criterion benches measuring host-side wall-clock cost
  characteristics (regression detection + cost-ratio
  characterization).

### SBF integration tests (session 113)

10 tests in
[`crates/mosaic-program/tests/verify_proof_sbf.rs`](crates/mosaic-program/tests/verify_proof_sbf.rs)
covering every dispatch byte `0x01..=0x08` + `0xFE` (unknown). See
the discriminant table in
[`CHANGELOG.md` v0.9.12 entry](CHANGELOG.md#0912-sbf-coverage--2026-05-02).

### Lint policy (audit-prep relevant)

Every workspace crate inherits `[workspace.lints]`:

- **Layer 1 — hard-deny everywhere**: `clippy::correctness`,
  `clippy::suspicious`, `todo`, `unimplemented`. CI uses
  `-D warnings` so these always fail the build.
- **Layer 2 — warn**: `clippy::pedantic`, `clippy::nursery`,
  `clippy::cargo`. Visible in `cargo clippy` output but doesn't
  fail PR CI; deliberate suppressions registered in
  [`docs/lint-policy.md`](docs/lint-policy.md).
- **Layer 3 — `#![forbid(unsafe_code)]`** at every library crate
  root. The single permitted exception (the `unsafe-arena`
  feature) is gated by an explicit allow-list in `deny.toml`.

### Differential testing

- `tests/differential` workspace member runs:
  - `groth16_diff_arkworks` (mul-circuit, single fixture)
  - `groth16_diff_snarkjs` (mul-circuit, single fixture)
  - `plonk_diff_snarkjs` (mul-circuit, single fixture)
- Phase-3 differential coverage is gated on prover-side fixtures
  landing (session 118).

---

## Reproducibility recipe (for audit firms)

```text
# 1. Clone at the audit-locked tag.
git clone https://github.com/wienerlabs/mosaic
cd mosaic
git checkout v0.9.14-audit-checklist

# 2. Run the lib test suite.
cargo test --workspace --lib

# 3. Run the SBF artifact build + integration tests.
cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml
BPF_OUT_DIR=target/deploy cargo test -p mosaic-program --test verify_proof_sbf

# 4. Run the on-chain CU regression bench.
cargo run --release -p mosaic-bench --bin bpf-bench

# 5. Run the host-side criterion benches.
cargo bench -p mosaic-bench --bench compression_host
cargo bench -p mosaic-bench --bench groth16_host
cargo bench -p mosaic-bench --bench phase3_host
cargo bench -p mosaic-bench --bench audit_gates_host

# 6. Run the differential test harness.
cargo test -p tests-differential

# 7. (Optional) Fuzz any harness for 5 minutes.
cd crates/mosaic-fuzz
cargo +nightly fuzz run fuzz_groth16_proof_bytes -- -max_total_time=300
```

---

## Open questions deferred to external audit

1. **Subgroup-check assumption coverage** — T-3 mitigation cites the
   alt_bn128 syscall as authority for subgroup checks on SBF. Audit
   should review the host-side mock's subgroup check parity (it
   uses arkworks' `is_in_correct_subgroup_assuming_on_curve`).
2. **Phase-3 scaffold soundness** — every Phase-3 verifier accepts
   a documented scaffold-acceptance fixture under the trivial-zero
   wire bundle. Audit should review whether the in-pipeline
   accept-on-zero behavior is *only* exposed under the scaffold
   shape and *cannot* be reproduced under non-trivial real-world
   prover output (the session 118 differential tests will close
   this gap pre-commission).
3. **bpf-bench Nova/FriStark byte swap (s47/s49 → s113 fix)** —
   audit should verify the fix is complete and the corrected
   constants match the canonical `ProofSystemId` enum byte-for-byte.
4. **Compression round-trip vs SBF syscall** — until session 116
   adds `verify_compressed_proof` on chain, the host-vs-SBF parity
   for the syscall is asserted via cost-ratio analysis only, not
   measured directly.
5. **PoseidonParameters parity** — host `light-poseidon = "0.3.0"`
   vs SBF `solana-poseidon = "2.3"`. Differential tests in
   `mosaic-zk-primitives::kzg` assert byte-equality but the parity
   is configuration-dependent.
6. **Risc0 dispatch arm** — currently returns
   `UnimplementedProofSystem`. Audit should confirm the rejection
   is deterministic and doesn't leak side-channel info.

---

## Audit-firm contact

- **Email**: <baturalp@wienerlabs.com>
- **PGP key**: coming soon (issue
  [#19](https://github.com/wienerlabs/mosaic/issues/19))
- **Pre-audit outreach**: issue
  [#61](https://github.com/wienerlabs/mosaic/issues/61)

For NDA / SOW templates, mention this checklist as the scope
reference and we'll pre-fill the deliverable matrix.
