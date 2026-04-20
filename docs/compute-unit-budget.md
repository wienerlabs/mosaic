# Compute-Unit Budget Reference

> Authoritative numbers come from `mosaic-bench/bin/bpf-bench`. The targets
> below are the *hard caps* enforced in CI (see ADR-0005).

## Per-system targets

| Proof system | Target CU | `request_heap_frame` | Status |
|---|---|---|---|
| Groth16 BN254 | ≤180,000 | 32 KiB | Phase 1 ✅ |
| KZG-PLONK BN254 | ≤600,000 | 32 KiB | Phase 2 (stub) |
| HyperPlonk-KZG | ≤900,000 | 64 KiB | Phase 2 (stub) |
| Halo2-KZG | ≤700,000 | 64 KiB | Phase 2 (stub) |
| FRI-STARK (Plonky3) | ≤14M (chunked) | 256 KiB | Phase 3 (stub) |
| Risc0 receipt | ≤14M (chunked) | 256 KiB | Phase 3 (stub) |
| Nova folding | ≤900,000 | 64 KiB | Phase 3 (stub) |
| ProtoStar folding | ≤900,000 | 64 KiB | Phase 3 (stub) |

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

### Phase 1 / 2 measured baselines (2026-04-20)

| System | Fixture | Measured | Cap | Headroom |
|---|---|---|---|---|
| Groth16 BN254 | `mul-circuit` (1 PI) | **80,296 CU** | 180,000 | 55.4% |
| Groth16 BN254 batch N=5 | same proof × 5 | **230,626 CU** (46,125/proof) | 300,000 | 23% |
| KZG-PLONK BN254 | `mul-circuit` (1 PI) | **747,666 CU** | 800,000 | 6.5% |

**Batch savings**: 5 × 80,370 loop CU = 401,850 baseline; batched 230,626
= **42.6% reduction**. Per-proof CU drops from 80K to 46K. Break-even
at N=2; savings grow with N (projected ~50% at N=10 once measured).

Sources: `mosaic-bench/src/bin/bpf_bench.rs` against canonical fixtures.
Baselines pinned in `TARGETS[i].baseline_cu`; bench warns on >5% drift.

**PLONK algorithmic vs measured gap.** The ADR-0005 600K target was an
algorithmic estimate; actual measured is ~25% higher because:

- Arkworks `Fr` arithmetic on SBF costs ~2 000 CU per `*` (Montgomery
  limb-by-limb + reduce). PLONK does ~30 Fr multiplications.
- Each `alt_bn128_group_op` syscall has ~400 CU fixed overhead on top
  of the operation; PLONK makes ~20 calls vs Groth16's ~6.
- `scalar_mul_g1` allocates `Vec<u8>` per call (~200 CU/call).

The 600K target remains on the roadmap as optimization goal; 800K is
current enforceable cap. Path to 600K:

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
