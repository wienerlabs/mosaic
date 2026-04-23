# ADR-0005 — Compute-unit budget targets and CI regression policy

* **Status:** Accepted (2026-04-19)
* **Deciders:** Mosaic core team

## Context

Solana caps a single transaction at 1.4M compute units (CU) by default,
extendable to 14M via `ComputeBudgetInstruction::set_compute_unit_limit`.
Going over the limit fails the transaction — there is no graceful
degradation. Every verifier must therefore declare a target CU budget, and
that budget must be regression-tested on every PR.

The reference Light Protocol Groth16 verifier hits ≤200K CU. We commit to
the same envelope, with PLONK and STARK targets calibrated to the upstream
literature and the eprint 2025/1741 STARK-on-Solana technique.

## Decision

### Per-system CU targets

| System | Hard cap | Last-measured | Default `requested_heap_frame` |
|---|---|---|---|
| Groth16 BN254 | ≤180,000 CU | 83,574 | 32 KiB |
| Groth16 batch N=5 | ≤300,000 CU | 258,397 | 32 KiB |
| KZG-PLONK BN254 | ≤1,100,000 CU | 968,457 | 32 KiB |
| HyperPlonk-KZG | ≤900,000 CU | target ≤505K | 64 KiB |
| Halo2-KZG | ≤700,000 CU | target ≤580K | 64 KiB |
| FRI-STARK (Plonky3) | must fit in 14M CU + chunked upload | target ≤9.4M | 256 KiB |
| Risc0 receipt | must fit in 14M CU + chunked upload | — | 256 KiB |
| Nova folding | ≤900,000 CU | target ≤885K | 64 KiB |
| ProtoStar folding | ≤900,000 CU | target ≤885K | 64 KiB |

**Re-measurement 2026-04-23 (v0.5.0-phase3-complete):** The Phase-2
production targets were re-measured under the `opt-level = "z"` SBF
profile adopted in v0.4.1. The size optimizer favors shared tail-call
destinations over aggressive inlining, which penalizes PLONK's
polynomial-heavy path (linearization MSM) disproportionately versus
Groth16's pairing-dominated path. PLONK hard cap raised 800K → 1,100K
(13% headroom) to accommodate the drift; Groth16 caps retained.
Phase-3 targets remain aspirational pending fixture-driven
re-measurement.

Targets are **soft** in micro-benchmarks (host-side via Criterion) and
**hard** in `bpf-bench` (rejects the PR if the on-chain measurement
exceeds the budget).

### Reporting and gating

- Each verifier crate exposes `estimated_compute_units(vk, proof) -> Option<u32>`.
  Off-chain SDK uses this to short-circuit before submission; on-chain
  dispatcher uses it as a sanity check vs. the remaining CU.
- `mosaic-bench/bin/bpf-bench` runs each system's representative fixture
  through `solana-program-test` and parses CU consumption from program logs.
- CI workflow `bench.yml` runs `bpf-bench` on every PR; if any system
  exceeds its target by more than 5% the PR is blocked. (Tolerance is
  asymmetric: improvements always pass; regressions fail.)

### Heap frame requests

Each system's documented `requested_heap_frame` matches its bump-arena
pattern. `mosaic-program` does **not** request the heap frame itself —
clients are responsible for adding `ComputeBudgetInstruction::request_heap_frame`
to their transactions. The SDK helper in `mosaic-sdk` does this
automatically.

## Consequences

**Positive**:

- Targets are explicit and measurable; CU regressions surface in CI rather
  than at user-submission time.
- Off-chain `estimated_compute_units` lets clients pick the right
  `set_compute_unit_limit` without guessing.
- Chunked-upload contract for STARK / Risc0 is documented as an explicit
  contract, not an emergent property.

**Negative**:

- Maintaining tight CU targets requires representative fixtures per system.
  The Phase-1 fixture set covers Groth16 only; PLONK / STARK fixtures land
  with their respective verifiers.
- 5% regression tolerance is a judgment call. Tighter would block valid
  refactors; looser invites slow drift.

## Procedure for raising a target

1. Open a PR with the new measurement and a written justification (algorithm
   change, syscall change, etc.).
2. Update this ADR with the new target and the date.
3. Update `bpf-bench` thresholds in the same commit.
4. Add an entry to `AUDIT.md` if the change is security-relevant
   (e.g. switching from `sol_alt_bn128_group_op` to a new syscall).

## Validation

- Phase 1: Groth16 host-side micro-benchmark (Criterion).
- Phase 2: Add `bpf-bench` to required CI checks once a representative
  on-chain fixture lands.
- Phase 3: Per-system cost tables published to `docs/compute-unit-budget.md`
  on every release.
