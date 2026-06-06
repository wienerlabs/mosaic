# Compute-Unit Budget Reference

> Authoritative numbers come from `mosaic-bench/bin/bpf-bench`. The targets
> below are the *hard caps* enforced in CI (see ADR-0005).

## Full BPF measurement sweep — 2026-06-06 (borsh 1.5.7 / platform-tools v1.52)

The first sweep where **every** dispatch arm was measured end-to-end on
the real `solana-program-test` VM, after the borsh-1.5.7 pin (#88) made
the on-chain program runnable. Reproduce with:

```bash
cargo build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml
SBF_OUT_DIR=$PWD/target/deploy cargo run --release -p mosaic-bench --bin bpf-bench
```

| Target | Measured CU | Hard cap | Headroom | Status |
|---|---|---|---|---|
| `groth16_bn254_mul_circuit_1pi` | **84,027** | 180,000 | 53% | ✅ |
| `groth16_batch_n5_mul_circuit_1pi` | **259,772** | 300,000 | 13% | ✅ |
| `plonk_bn254_mul_circuit_1pi` | **973,388** | 1,100,000 | 12% | ✅ |
| `hyperplonk_kzg_bn254_scaffold` | **900,750** | 1,050,000 | 14% | ✅ ¹ |
| `halo2_kzg_bn254_scaffold` | **824,074** | 950,000 | 13% | ✅ ¹ |
| `nova_folding_bn254_scaffold` | **289,899** | 360,000 | 19% | ✅ ² |
| `groth16_compressed_mul_circuit_1pi` | **146,620** | 190,000 | 23% | ✅ |
| `plonk_compressed_mul_circuit_1pi` | **1,005,100** | 1,200,000 | 16% | ✅ |
| `hyperplonk_kzg_compressed_scaffold` | **928,039** | 1,100,000 | 16% | ✅ ¹ |
| `halo2_kzg_compressed_scaffold` | **857,503** | 960,000 | 11% | ✅ |
| `nova_folding_compressed_scaffold` | **316,580** | 400,000 | 21% | ✅ ² |
| `fri_stark_goldilocks_scaffold` | — | 7,800,000 | — | ⚠ ³ |

¹ The host-side `estimated_compute_units` shape estimate **under-counted**
HyperPlonk (~505K est vs 900K real, +78%) and Halo2 (~580K est vs 824K
real, +42%). Caps re-set to measured × ~1.15. These are worst-case
zero-wire scaffold shapes; real proofs share the same pairing/MSM counts.

² The Nova estimate **over-counted** by ~3× (~885K est vs 290K real); the
Hadamard identity check is far cheaper on-chain than the host estimate
assumed. Caps tightened 1.15M → 360K so the bench actually catches
regressions instead of allowing 4× silent drift.

³ The large-shape FRI-STARK scaffold currently fails verification on-chain
with `Custom(0x2F)` `VerificationFailed` — `build_stark_scaffold_fixture()`
does not construct Merkle paths the verifier accepts at this shape. The
depth-zero STARK shape in `verify_proof_sbf.rs` passes, so the dispatch is
sound; this is a bench-fixture-builder gap tracked with the FRI-STARK body
work ([#76](https://github.com/wienerlabs/mosaic/issues/76)).

**Key takeaway for auditors**: the three production verifiers (Groth16,
Groth16-batch, KZG-PLONK) re-measured within **0.6%** of their prior
pinned baselines — the verifier arithmetic is stable. The Phase-3
scaffold numbers are first real measurements that corrected three
estimate-derived caps.

## Per-system targets (post-2026-06-06 sweep)

| Proof system | Hard cap | Last-measured | `request_heap_frame` | Status |
|---|---|---|---|---|
| Groth16 BN254 | ≤180,000 | **84,027** | 32 KiB | Production ✅ |
| Groth16 batch N=5 | ≤300,000 | **259,772** | 32 KiB | Production ✅ |
| KZG-PLONK BN254 | ≤1,100,000 | **973,388** | 32 KiB | Production ✅ |
| HyperPlonk-KZG | ≤1,050,000 | **900,750** | 64 KiB | Phase-3 body (scaffold) |
| Halo2-KZG | ≤950,000 | **824,074** | 64 KiB | Phase-3 body (scaffold) |
| Nova folding | ≤360,000 | **289,899** | 64 KiB | Phase-3 body (scaffold) |
| ProtoStar folding | ≤360,000 | via Nova arm | 64 KiB | Phase-3 body (shared) |
| FRI-STARK (Plonky3) | ≤7.8M (chunked) | fixture pending ³ | 256 KiB | Phase-3 body (scaffold) |
| Risc0 receipt | ≤14M (chunked) | — | 256 KiB | Stub (Phase 3) |

## Groth16 BN254 — cost breakdown

For a VK with `n` public inputs:

| Operation | Count | CU each | Subtotal |
|---|---|---|---|
| Deserialization + bounds checks | 1 | ~5,000 | 5,000 |
| `G1Mul` (`pi[i] · IC[i+1]`) | `n` | ~3,200 | `3,200 · n` |
| `G1Add` (`L += prod`) | `n` | ~100 | `100 · n` |
| `Pairing` (4 pairs) | 1 | ~36,000 | 36,000 |
| **Total** | | | `41,000 + 3,300 · n` |

Concrete examples:

| `n` (public inputs) | Algorithmic CU | Measured CU (actual) |
|---|---|---|
| 1 | 44,300 | **80,296** (see below) |
| 5 | 57,500 | — |
| 10 | 74,000 | — |
| 25 | 123,500 | — |
| 42 | 179,600 (right at the cap) | — |

`Groth16Verifier::estimated_compute_units` returns the *algorithmic*
estimate; actual on-chain CU is higher because of Borsh deserialization
of the `VerifyProofData` payload, instruction dispatch, `msg!` logging,
and the `solana-bn254` syscall wrapper allocations.

### Phase 1 / 2 measured baselines (2026-04-23, opt-level="z")

| System | Fixture | Measured | Cap | Headroom |
|---|---|---|---|---|
| Groth16 BN254 | `mul-circuit` (1 PI) | **83,574 CU** | 180,000 | 53.6 % |
| Groth16 BN254 batch N=5 | same proof × 5 | **258,397 CU** (51,680/proof) | 300,000 | 13.8 % |
| KZG-PLONK BN254 | `mul-circuit` (1 PI) | **968,457 CU** | 1,100,000 | 11.4 % |

**Batch savings**: 5 × 83,574 loop CU = 417,870 baseline; batched 258,397
= **38.2 % reduction**. Per-proof CU drops from 84K to 52K. Break-even
at N=2; savings grow with N (projected ~45 % at N=10 once measured).

Sources: `mosaic-bench/src/bin/bpf_bench.rs` against canonical fixtures.
Baselines pinned in `TARGETS[i].baseline_cu`; bench warns on >5 % drift.

**Opt-level="z" re-measurement drift (v0.4.1 → v0.5.0).** The SBF
binary size optimization adopted in v0.4.1 reshuffled inlining
decisions during the v0.5.0 STARK body + `mosaic-zk-primitives`
extraction:

| System | v0.4.1 baseline | v0.5.0 measured | Drift |
|---|---|---|---|
| Groth16 single | 80,296 | 83,574 | +4.1 % |
| Groth16 batch N=5 | 230,626 | 258,397 | +12.0 % |
| KZG-PLONK | 747,666 | 968,457 | +29.5 % |

PLONK's polynomial-heavy path (linearization 5-term MSM, transcript
Fr arithmetic, three KZG openings) absorbs the size-optimizer tradeoff
disproportionately. Root causes of the PLONK gap vs algorithmic estimate:

- Arkworks `Fr` arithmetic on SBF costs ~2 000 CU per `*` (Montgomery
  limb-by-limb + reduce). PLONK does ~30 Fr multiplications.
- Each `alt_bn128_group_op` syscall has ~400 CU fixed overhead on top
  of the operation; PLONK makes ~20 calls vs Groth16's ~6.
- `scalar_mul_g1` allocates `Vec<u8>` per call (~200 CU/call).
- Under `opt-level = "z"`, these per-call costs compound because
  previously-inlined Fr helpers now go through shared tail-call
  destinations.

The 600K algorithmic target remains on the roadmap as optimization goal;
1,100K is the current enforceable cap. Path to reduction:

- Issue [#37](https://github.com/wienerlabs/mosaic/issues/37) —
  Pippenger MSM for the linearization 5-term MSM (saves ~50K).
- Issue [#38](https://github.com/wienerlabs/mosaic/issues/38) — Fr
  in-place mutation to reduce Montgomery round-trip (saves ~80K).
- Future: cache evaluation decodes across `compute_d*` helpers to avoid
  re-decoding proof evaluations 3× (saves ~20K).

## Client transaction overhead

A `VerifyProof` transaction also pays for:

| Component | Approx CU |
|---|---|
| Transaction signature verification | 2,000 |
| Account loads | 1,500 per account |
| `set_compute_unit_limit` instruction | 150 |
| `request_heap_frame` instruction | 150 |
| Borsh deserialization of `VerifyProofData` | 1,000 + 1.0 per byte |

For a typical Groth16 transaction with 5 public inputs:
57,500 (verifier) + ~5,000 (overhead) ≈ **62,500 CU**.

Recommend `set_compute_unit_limit(80,000)` for headroom.

## SDK helpers

`mosaic-sdk` adds the appropriate `ComputeBudgetInstruction` calls
automatically based on the request:

```rust
let req = VerifyRequest { /* ... */ };
let cu = mosaic_groth16::Groth16Verifier::<HostBackend, false>::new(&hb)
    .estimated_compute_units(&req.vk, &req.proof);
let cu_with_overhead = cu.unwrap_or(180_000).saturating_add(20_000);
let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(cu_with_overhead);
```

## Regression policy

Any PR that increases a target by more than 5% requires:

1. Updated target in `ADR-0005`.
2. Updated `bpf-bench` threshold in `mosaic-bench`.
3. PR description with the algorithmic justification.
4. `AUDIT.md` entry if the change touches a syscall surface.

Reductions are always welcome and pass CI silently.
