# Compute-Unit Budget Reference

> Authoritative numbers come from `mosaic-bench/bin/bpf-bench`. The targets
> below are the *hard caps* enforced in CI (see ADR-0005).

## Per-system targets

| Proof system | Hard cap | Last-measured | `request_heap_frame` | Status |
|---|---|---|---|---|
| Groth16 BN254 | ≤180,000 | **83,574** | 32 KiB | Production ✅ |
| Groth16 batch N=5 | ≤300,000 | **258,397** | 32 KiB | Production ✅ |
| KZG-PLONK BN254 | ≤1,100,000 | **968,457** | 32 KiB | Production ✅ |
| HyperPlonk-KZG | ≤900,000 | target ≤505K | 64 KiB | Phase-3 body (scaffold) |
| Halo2-KZG | ≤700,000 | target ≤580K | 64 KiB | Phase-3 body (scaffold) |
| FRI-STARK (Plonky3) | ≤14M (chunked) | target ≤9.4M | 256 KiB | Phase-3 body (scaffold) |
| Risc0 receipt | ≤14M (chunked) | — | 256 KiB | Stub (Phase 3) |
| Nova folding | ≤900,000 | target ≤885K | 64 KiB | Phase-3 body (scaffold) |
| ProtoStar folding | ≤900,000 | target ≤885K | 64 KiB | Phase-3 body (scaffold) |

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
