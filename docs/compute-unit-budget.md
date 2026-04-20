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

### Phase 1 measured baseline (2026-04-20)

| Fixture | Measured | Cap | Headroom |
|---|---|---|---|
| `mul-circuit` (1 public input) | **80,296 CU** | 180,000 | 55.4% unused |

Source: `mosaic-bench/src/bin/bpf_bench.rs` against the canonical
fixture at `tests/fixtures/groth16/mul-circuit/canonical/`. Measurement
is pinned in `bpf_bench.rs::TARGETS[0].baseline_cu`; the bench warns
(`WARN` status) when a measurement deviates from this by more than 5%.
Issues [#37](https://github.com/wienerlabs/mosaic/issues/37) and
[#38](https://github.com/wienerlabs/mosaic/issues/38) track CU reductions
for the Groth16 hot path; both would drop this number further.

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
