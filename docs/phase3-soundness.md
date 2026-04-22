# Phase-3 Verifier Soundness Gates

Reference document for the cryptographic soundness checks built into each
Phase-3 verifier body. Consolidates the work landed between
`v0.4.0-phase3-bodies` and `v0.4.1-phase3-soundness`, plus the FRI-STARK
session-8/9 extensions post-release. Audit reviewers should start here
to understand which classes of tampered prover data each verifier
surfaces before the final structural check.

## Summary table

| Verifier | Gate(s) | Error variant | Reference |
|---|---|---|---|
| HyperPlonk-KZG | sumcheck round identity | `SumcheckFailed` | [`sumcheck.rs`](../crates/mosaic-hyperplonk/src/sumcheck.rs) |
| HyperPlonk-KZG | permutation term at ξ | `SumcheckFailed` | [`verifier.rs`](../crates/mosaic-hyperplonk/src/verifier.rs) — `permutation_term` |
| Halo2-KZG | vanishing identity `t(ξ)·Z_H(ξ) ?= combined_expr` | `SumcheckFailed` | [`verifier.rs`](../crates/mosaic-halo2/src/verifier.rs) |
| Nova / HyperNova / ProtoStar | Hadamard residual `a·b − u·c − e ?= 0` | `SumcheckFailed` | [`folding.rs`](../crates/mosaic-nova/src/folding.rs) — `hadamard_residual` |
| FRI-STARK | structural query-index derivation | `ProofLengthMismatch` | [`challenges.rs`](../crates/mosaic-stark/src/challenges.rs) |
| FRI-STARK | trace Merkle path | `VerificationFailed` | [`merkle.rs`](../crates/mosaic-stark/src/merkle.rs) |
| FRI-STARK | constraint Merkle path | `VerificationFailed` | (same) |
| FRI-STARK | PoW grinding (`sha256(seed ‖ nonce)`) | `VerificationFailed` | [`challenges.rs`](../crates/mosaic-stark/src/challenges.rs) — `verify_pow` |

## Soundness gate vs final check

Each verifier has a **final structural check** (KZG pairing, multi-poly
opening, or the last FRI layer) that a valid proof must pass to return
`Ok(())`. The soundness gates listed above run **before** that final
check — they surface tampered prover data with specific error codes so
callers can distinguish:

- `ProofLengthMismatch` — wire-format bug.
- `PublicInputOutOfRange` — consensus-critical Fr validation.
- `SumcheckFailed` — a claim-reduction identity didn't hold.
- `VerificationFailed` — a hash tree / path didn't reconstruct correctly.
- `PairingCheckFailed` — the final KZG pairing didn't equal identity.

A senior-engineer integration should:

1. Treat any error return as "proof rejected" — don't branch on specific
   variants for consensus decisions.
2. Use the variant for **diagnostics only** — which category of bug was
   caught.
3. Trust that the soundness gates act as **pre-filters** — a proof that
   reaches the final check has already cleared several independent
   cryptographic conditions.

## Per-verifier walkthrough

### HyperPlonk-KZG

Two soundness gates in front of the KZG batched opening:

**Sumcheck round identity** (`sumcheck::verify_sumcheck`) — for each of
the `log₂(domain)` sumcheck rounds, the verifier checks that the
prover-sent round polynomial `p_r(X) = c_0 + c_1·X + c_2·X²` satisfies

```text
p_r(0) + p_r(1) = C_r
```

where `C_r` is the claim carried over from the previous round (initial
claim is 0 for the zero-check variant). Any round failing the identity
yields `SumcheckFailed`.

**Permutation term reconstruction** (`verifier::permutation_term`) —
after sumcheck closes with a final claim, the verifier independently
computes

```text
gate_value = q_M·a·b + q_L·a + q_R·b + q_O·c + q_C
perm_value = z · [(a + β + γ)(b + 2β + γ)(c + 3β + γ)
                - (a + β·σ_1 + γ)(b + β·σ_2 + γ)(c + β·σ_3 + γ)]
expected   = α · gate_value + perm_value
```

and compares against the sumcheck's final claim. A tampered σ_i or
selector evaluation surfaces here as `SumcheckFailed` before the KZG
opening runs.

**Scaffold caveat:** hardcoded coset constants `(1, 2, 3)` in the
permutation identity. Real Espresso HyperPlonk reads `k_i` from the VK;
session 3f-full will pin this against reference fixtures.

### Halo2-KZG

**Vanishing identity** (`verifier::verify`, lines around the `combined`
computation) — after deriving challenges `(θ, β, γ, y, ξ)`, the verifier
parses the structured `EvaluationBundle` and checks

```text
t(ξ) · Z_H(ξ)  ?=  gate_expr(ξ) + y · perm_expr(ξ) + y² · lookup_expr(ξ)
```

`t(ξ)` reconstructs from the quotient chunks via `compute_t_from_chunks`
(Horner reduction); `Z_H(ξ) = ξ^(2^k) - 1` from `compute_z_h`. The
RHS uses the per-family evaluators in `circuit.rs`. Mismatch yields
`SumcheckFailed`.

**Scaffold caveats:**
- Single-commitment KZG opening vs real Halo2's two-point batched
  multipoint opening.
- Hardcoded permutation cosets (same as HyperPlonk).
- Scaffold evaluation-bundle layout; real Halo2 has variable layouts
  per circuit's column counts.

### Nova / HyperNova / ProtoStar

**Hadamard residual** (`folding::hadamard_residual`) — the folded
instance satisfies the relaxed R1CS relation `A·z ∘ B·z = u·C·z + E`.
At the Spartan evaluation point ξ this reduces to the scalar equation

```text
A(ξ) · B(ξ) - u · C(ξ) - E(ξ)  =  0
```

The verifier parses `(a, b, c, e)` evaluations from the proof's
`hadamard_evals` field (128 B fixed slot) and `u` from the proof
header, then checks the residual. Non-zero residual → `SumcheckFailed`.

**Scaffold caveat:** the `folded_commitment_from_fold` and
`folded_error_commitment` primitives are built and unit-tested but not
wired into the pipeline because the proof layout doesn't yet carry the
two base commitments to fold against. Session 7+ canonical extension.

### FRI-STARK

Four soundness gates — the highest count of any Phase-3 verifier,
reflecting the hash-based verification model's need for multiple
independent paths of trust.

**Structural query-index derivation** (`challenges::derive_query_indices`)
— `num_queries` pseudo-random indices in `[0, 2^domain_log)` via
`sha256(query_seed ‖ counter)`. The transcript absorb-sequence is
domain-separated: changing any prior-absorbed byte shifts every index.
Bad domain sizes (non-power-of-two, zero) are rejected with
`ProofLengthMismatch`.

**Trace Merkle path** (`merkle::verify_path` on `trace_commitment`) — for
each query index, the verifier walks a SHA-256 tree from leaf up to
root, hashing `(left, right)` pairs according to the index bits. A
tampered leaf or path byte yields `VerificationFailed` because the
reconstructed root won't match the committed `trace_commitment`.

**Constraint Merkle path** (same function against `constraint_commitment`)
— session-8 extension: each query carries a *second* `(leaf, path)`
pair, opening the constraint-composition polynomial's commitment at
the same index. Tampered constraint evaluations surface here.

**Proof-of-work grinding** (`challenges::verify_pow`) — `sha256(query_seed
‖ pow_nonce_le)` must have at least `pow_bits` leading zero bits.
Forces a malicious prover who wants to search for a favorable
`query_seed` to clear this target on every attempt, making the attack
exponentially more expensive per bit.

**Scaffold caveats:**
- Per-FRI-layer consistency (fold + authentication) not yet wired.
  Needs an additional structured buffer and Goldilocks field
  arithmetic for the fold relation.
- Out-of-domain quotient consistency (`constraint(z) == Σ α^i ·
  quotient_i(z)`) not yet wired — same Goldilocks blocker.
- Goldilocks arithmetic itself needs an in-tree implementation.

## What tampering tests cover

Every soundness gate has at least one paired rejection test in the
same crate. These tests are documented as such — audit reviewers can
grep for `rejects_tampered_*` or `rejects_mismatched_*` to find the
coverage surface.

| Gate | Rejection test |
|---|---|
| Sumcheck identity | `mosaic-hyperplonk/src/sumcheck.rs::verify_sumcheck_rejects_tampered_first_round` |
| Permutation term | `mosaic-hyperplonk/src/verifier.rs::rejects_tampered_sigma_commitment` |
| Halo2 vanishing | `mosaic-halo2/src/verifier.rs::rejects_tampered_gate_coefficient` |
| Hadamard residual | `mosaic-nova/src/verifier.rs::rejects_tampered_hadamard_evals` |
| Trace Merkle | `mosaic-stark/src/verifier.rs::rejects_mismatched_trace_merkle_leaf` |
| Constraint Merkle | `mosaic-stark/src/verifier.rs::rejects_mismatched_constraint_merkle_leaf` |
| PoW grinding | `mosaic-stark/src/challenges.rs::pow_rejects_random_nonce_at_nonzero_bits` |

## Integration guidance

For protocols integrating Mosaic on Solana:

1. Size compute-unit budgets per-system per `docs/compute-unit-budget.md`
   (not every gate is CU-free — sumcheck and Merkle walks add
   per-round overhead).
2. Treat `OnChainError` as **opaque** for the consensus path. Specific
   variants are for telemetry / dashboards / retry decisions.
3. Don't bypass scaffold caveats — the remaining gaps are genuine
   soundness holes that external fixtures will close. Production
   deployment should pin the specific Mosaic version against the
   verifier families it uses.

## Version history

| Release | Soundness milestone |
|---|---|
| `v0.4.0-phase3-bodies` | Structural validation for all four bodies. No cryptographic gates. |
| `v0.4.1-phase3-soundness` | Four primary gates wired: sumcheck + perm, vanishing, Hadamard, Merkle. |
| `ee9ed73` (session 8) | FRI-STARK gains constraint-Merkle gate. |
| `19a81f5` (session 9) | FRI-STARK gains PoW-grinding gate. |

Total in-tree soundness gates at `HEAD`: **7 cryptographic** +
**1 structural** across four verifier families. Pattern for adding
the next gate in any verifier: extend canonical → parse → verify →
test both happy path and rejection.
