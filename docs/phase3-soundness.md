# Phase-3 Verifier Soundness Gates

Reference document for the cryptographic soundness checks built into
each Phase-3 verifier body. **Current as of
`v0.8.11-hyperplonk-audit-gate`** — sessions 86 → 91 extracted the
primary soundness boundary of every Phase-3 verifier into a named,
publicly callable `verify_*` audit gate following [ADR-0006](adr/0006-verifier-audit-gate-pattern.md).
Plus session 87 closed a real soundness hole exposed by the session-86
extraction work (the folding-challenge `r` was not bound to the four
pre-fold base commits in the Fiat-Shamir transcript, making the new
audit gate vacuous; the fix absorbs all 7 G1 inputs into round 1).

Sessions 21-26 (consolidation) earlier introduced five shared
primitives in `mosaic-zk-primitives` (`fr_from_be_bytes_reduced`,
`derive_fr_challenge`, `fr_be_from_u64`, `verify_two_pair_pairing`,
`commitment_minus_scalar_g1`); the session-23 work added a dedicated
`w_eval` slot to the Nova proof canonical replacing the scaffold
reuse of `public_inputs[0]`.

## Phase-3 audit-gate matrix (sessions 86 → 91)

External audit firms — start here. Each gate is a `pub fn` callable
in isolation with hand-constructed inputs:

| Verifier | Audit gate | Module | Session | Tag |
|---|---|---|---|---|
| Nova / HyperNova / ProtoStar | [`verify_folding_consistency`](../crates/mosaic-nova/src/folding.rs) | `mosaic_nova::folding` | 86 | v0.8.6 |
| Halo2-KZG (lookup) | [`verify_multi_column_lookup_identity`](../crates/mosaic-halo2/src/circuit.rs) | `mosaic_halo2::circuit` | 88 | v0.8.8 |
| FRI-STARK (per-query) | [`verify_fri_query`](../crates/mosaic-stark/src/fri.rs) | `mosaic_stark::fri` | 90 | v0.8.10 |
| HyperPlonk-KZG | [`verify_sumcheck_claim_reduction`](../crates/mosaic-hyperplonk/src/verifier.rs) | `mosaic_hyperplonk::verifier` | 91 | v0.8.11 |

See [ADR-0006](adr/0006-verifier-audit-gate-pattern.md) for the
recipe and contract every audit gate follows.

Audit reviewers should start here to understand which classes of
tampered prover data each verifier surfaces before the final
structural check.

## Summary table — 14 independent gates

| Verifier | Gate | Error variant | Reference |
|---|---|---|---|
| HyperPlonk-KZG | Sumcheck round identity | `SumcheckFailed` | [`sumcheck.rs`](../crates/mosaic-hyperplonk/src/sumcheck.rs) |
| HyperPlonk-KZG | Permutation term at ξ | `SumcheckFailed` | [`verifier.rs`](../crates/mosaic-hyperplonk/src/verifier.rs) — `permutation_term` |
| Halo2-KZG | Vanishing identity `t(ξ)·Z_H(ξ) ?= combined_expr` | `SumcheckFailed` | [`verifier.rs`](../crates/mosaic-halo2/src/verifier.rs) |
| Halo2-KZG | Two-point batched opening at `(ξ, ξω)` | `PairingCheckFailed` | [`kzg.rs`](../crates/mosaic-halo2/src/kzg.rs) — `verify_two_point_opening_scaffold` |
| Halo2-KZG | Multi-poly `v`-weighted MSM batching (session 17) | `PairingCheckFailed` | [`kzg.rs`](../crates/mosaic-halo2/src/kzg.rs) — `verify_two_point_opening_multipoly` |
| Nova / HyperNova / ProtoStar | Hadamard residual `a·b − u·c − e ?= 0` | `SumcheckFailed` | [`folding.rs`](../crates/mosaic-nova/src/folding.rs) — `hadamard_residual` |
| Nova / HyperNova / ProtoStar | Folded-commitment reconstruction `E_1 + r·E_2 + r²·T ?= E_folded` | `VerificationFailed` | [`folding.rs`](../crates/mosaic-nova/src/folding.rs) — `folded_commitment_from_fold` |
| FRI-STARK | Structural query-index derivation | `ProofLengthMismatch` | [`challenges.rs`](../crates/mosaic-stark/src/challenges.rs) — `derive_query_indices` |
| FRI-STARK | Trace Merkle path | `VerificationFailed` | [`merkle.rs`](../crates/mosaic-stark/src/merkle.rs) — `verify_path` |
| FRI-STARK | Constraint Merkle path | `VerificationFailed` | (same) |
| FRI-STARK | PoW grinding `sha256(seed ‖ nonce)` | `VerificationFailed` | [`challenges.rs`](../crates/mosaic-stark/src/challenges.rs) — `verify_pow` |
| FRI-STARK | FRI fold chain walk | `VerificationFailed` | [`fri.rs`](../crates/mosaic-stark/src/fri.rs) — `verify_fold_chain` |
| FRI-STARK | OOD quotient consistency `C(z) ?= Σ α^i · q_i(z)` | `VerificationFailed` | [`verifier.rs`](../crates/mosaic-stark/src/verifier.rs) + [`goldilocks.rs`](../crates/mosaic-stark/src/goldilocks.rs) — `eval_poly_le_bytes` |
| FRI-STARK | Per-layer Merkle authentication | `VerificationFailed` | [`verifier.rs`](../crates/mosaic-stark/src/verifier.rs) (inline) |

## Soundness gate vs final check

Each verifier has a **final structural check** (KZG pairing, multi-
poly opening, or the last FRI layer) that a valid proof must pass
to return `Ok(())`. The soundness gates listed above run **before
or alongside** that final check — they surface tampered prover
data with specific error codes so callers can distinguish:

- `ProofLengthMismatch` — wire-format bug or structural canonical violation.
- `PublicInputOutOfRange` — consensus-critical Fr validation.
- `SumcheckFailed` — a claim-reduction identity didn't hold.
- `VerificationFailed` — a hash tree / auth path / polynomial
  identity didn't reconstruct correctly.
- `PairingCheckFailed` — a KZG pairing didn't equal the Fq12 identity.

A senior-engineer integration should:

1. Treat any error return as "proof rejected" — don't branch on
   specific variants for consensus decisions.
2. Use the variant for **diagnostics only** — which category of bug
   was caught.
3. Trust that the soundness gates act as **pre-filters** — a proof
   that reaches the final check has already cleared several
   independent cryptographic conditions.

## Per-verifier walkthrough

### HyperPlonk-KZG — 2 gates

**Sumcheck round identity** (`sumcheck::verify_sumcheck`) — for each
of the `log₂(domain)` sumcheck rounds, the verifier checks that the
prover-sent round polynomial `p_r(X) = c_0 + c_1·X + c_2·X²`
satisfies

```text
p_r(0) + p_r(1) == C_r
```

where `C_r` is the claim carried over from the previous round
(initial claim is 0 for the zero-check variant). Any round failing
the identity yields `SumcheckFailed`.

**Permutation term reconstruction**
(`verifier::compute_expected_final_claim`) — after sumcheck closes
with a final claim, the verifier independently computes

```text
gate_value = q_M·a·b + q_L·a + q_R·b + q_O·c + q_C
perm_value = z · [(a + β·1 + γ)(b + β·2 + γ)(c + β·3 + γ)
               − (a + β·σ_1 + γ)(b + β·σ_2 + γ)(c + β·σ_3 + γ)]
expected   = α · gate_value + perm_value
```

and compares against the sumcheck's final claim. A tampered σ_i or
selector evaluation surfaces here as `SumcheckFailed` before the
KZG opening runs.

**Scaffold caveat (remaining):** hardcoded coset constants `(1, 2,
3)` in the permutation identity. Real Espresso HyperPlonk reads
`k_i` from the VK; fixture-bound tightening.

### Halo2-KZG — 1 gate + two-point opening

**Vanishing identity** (`verifier::verify`, lines around the
`combined` computation) — after deriving challenges `(θ, β, γ, y,
ξ)`, the verifier parses the structured `EvaluationBundle` and
checks

```text
t(ξ) · Z_H(ξ)  ?=  gate_expr(ξ) + y · perm_expr(ξ) + y² · lookup_expr(ξ)
```

`t(ξ)` reconstructs from the quotient chunks via
`compute_t_from_chunks` (Horner reduction); `Z_H(ξ) = ξ^(2^k) - 1`
from `compute_z_h`. The RHS uses the per-family evaluators in
`circuit.rs`. Mismatch yields `SumcheckFailed`.

**Two-point batched KZG opening**
(`kzg::verify_two_point_opening_scaffold`) — session 16 upgrade
from single-point `ξ` to two-point `(ξ, ξω)`:

```text
A1 = C_ξ - y_ξ·G1 + ξ·W_ξ
A2 = C_ξω - y_ξω·G1 + ξω·W_ξω
A_batched = A1 + u·A2
W_batched = W_ξ + u·W_ξω

e(A_batched, [1]_2) · e(-W_batched, [x]_2) ?= 1
```

The `u` batching challenge is squeezed from keccak(ξ ‖ ω ‖ W_ξ ‖
W_ξω). A single 2-pair `alt_bn128_pairing` syscall covers both
opening points. `ω = VK.omega_fr` — added to the canonical in
session 16 as the BN254 Fr primitive `2^k`-th root of unity.

**Multi-poly `v`-weighted MSM batching (session 17)** —
`kzg::verify_two_point_opening_multipoly` replaces the session-16
single-commitment scaffold with full multi-poly batching:

```text
v-powers:    [1, v, v^2, …, v^{m-1}]
C_ξ_batched  = Σ_i v^i · commits_at_ξ[i]    // MSM
y_ξ_batched  = Σ_i v^i · evals_at_ξ[i]      // Fr dot product
C_ξω_batched = Σ_j v^j · commits_at_ξω[j]
y_ξω_batched = Σ_j v^j · evals_at_ξω[j]
// A1/A2/A_batched/W_batched as before with batched (C, y) pairs
```

`verifier.rs` collects commits_at_ξ = advice + lookup + permutation_z
+ quotient chunks; commits_at_ξω = [permutation_z] (only poly that
evaluates at the shifted point in vanilla Halo2). Each commit is
paired 1:1 with its matching bundle evaluation per the scaffold map
in `collect_evals_at_xi`. `v` and `u` batching challenges are both
derived via domain-separated keccak over the current transcript
state + the respective opening-proof bytes.

The session-17 test `multipoly_rejects_tampered_advice_commit`
verifies tampering a single advice G1 byte (generator swap) hits
`PairingCheckFailed`. `multipoly_rejects_tampered_wire_a_evaluation`
verifies the symmetric path — non-zero wire eval with zero commit
also fails.

**VK-side preprocessed commits (session 20)** — the multi-poly
MSM now folds in `vk.fixed_commits` (selector polynomials Q_M..Q_C)
and `vk.permutation_commits` (σ_1..σ_3) alongside the proof-side
commits. Each VK commit pairs 1:1 with its bundle evaluation
(`collect_commits_at_xi`, `collect_evals_at_xi` in `verifier.rs`).
Tampering any selector or permutation-σ commit in the VK now flips
`C_batched` while leaving `y_batched` unchanged → pairing fails.

Two new session-20 tamper tests:
`multipoly_rejects_tampered_vk_selector_commit` swaps `q_M` in the
VK to the G1 generator and expects `PairingCheckFailed`;
`multipoly_rejects_tampered_vk_permutation_commit` does the same
for `σ_1`. Both exercise the VK-side path that sessions-≤17
silently tolerated.

**Scaffold caveats (remaining):**
- Hardcoded permutation cosets (same as HyperPlonk).
- Scaffold evaluation-bundle layout.

### Nova / HyperNova / ProtoStar — 2 gates

**Hadamard residual** (`folding::hadamard_residual`) — the folded
instance satisfies the relaxed R1CS relation
`A·z ∘ B·z = u·C·z + E`. At the Spartan evaluation point ξ this
reduces to the scalar equation

```text
A(ξ) · B(ξ) - u · C(ξ) - E(ξ)  =  0
```

The verifier parses `(a, b, c, e)` evaluations from the proof's
`hadamard_evals` field (128 B fixed slot) and `u` from the proof
header, then checks the residual. Non-zero residual →
`SumcheckFailed`.

**Folded-commitment reconstruction**
(`folding::folded_commitment_from_fold`) — session 15-nova upgrade.
The verifier independently reconstructs the folded E and W
commitments from the two pre-fold base instances and the cross-term
T using the transcript-derived folding challenge r:

```text
E_folded ?= E_1 + r·E_2 + r²·T
W_folded ?= W_1 + r·W_2 + r²·T
```

Mismatch yields `VerificationFailed`. Catches a malicious prover
who sends inconsistent base/fold commitments — even with a valid
Hadamard residual, the reconstruction disagrees with the declared
E/W.

Canonical extension: proof gains 4 G1 slots (`base_e_1`, `base_e_2`,
`base_w_1`, `base_w_2`) between `u` and `hadamard_evals` =
256 bytes per proof.

**Scaffold caveats (remaining):**
- Single-commitment KZG opening vs Spartan's multi-poly batched
  opening.
- Pre-fold R1CS structure validation (sonobe-style): the base
  commitments are opaque; a fuller audit would verify they
  correspond to valid R1CS instances.

### FRI-STARK — 7 gates (production parity)

The widest soundness coverage in the tree. FRI-STARK went from
scaffold to Plonky3/Winterfell-parity in 9 focused sessions
(7–15).

**Structural query-index derivation** (`challenges::derive_query_indices`)
— `num_queries` pseudo-random indices in `[0, 2^domain_log)` via
`sha256(query_seed ‖ counter)`. The transcript absorb-sequence is
domain-separated: changing any prior-absorbed byte shifts every
index. Bad domain sizes (non-power-of-two, zero) are rejected with
`ProofLengthMismatch`.

**Trace Merkle path** (`merkle::verify_path` on `trace_commitment`) —
for each query index, the verifier walks a SHA-256 tree from leaf
up to root, hashing `(left, right)` pairs according to the index
bits. A tampered leaf or path byte yields `VerificationFailed`
because the reconstructed root won't match the committed
`trace_commitment`.

**Constraint Merkle path** (same function against
`constraint_commitment`) — session-8 extension: each query carries
a *second* `(leaf, path)` pair, opening the constraint-composition
polynomial's commitment at the same index. Tampered constraint
evaluations surface here.

**Proof-of-work grinding** (`challenges::verify_pow`) —
`sha256(query_seed ‖ pow_nonce_le)` must have at least `pow_bits`
leading zero bits. Forces a malicious prover who wants to search
for a favorable `query_seed` to clear this target on every attempt,
making the attack exponentially more expensive per bit.

**FRI fold chain walk** (`fri::verify_fold_chain`) — session 13b.
For each query, walks the full FRI layer sequence applying the
fold relation `f_{i+1}(x²) = (f_x + f_neg_x)/2 + β·(f_x − f_neg_x)/(2x)`
at each layer. Returns the final scalar; tampered layer openings
fail the cross-layer consistency check with `VerificationFailed`.

Each query's `f_x` at layer `i > 0` must equal the fold computed
from layer `i-1` openings — catches inconsistent layer-to-layer
progression.

**OOD quotient consistency** (`verifier.rs` + `goldilocks::eval_poly_le_bytes`)
— session 14c. Verifies that the prover's claimed
out-of-domain constraint evaluation `C(z)` equals the sum
`Σ α^i · q_i(z)` over quotient polynomial evaluations. The
`ood_evals` field carries `constraint_eval` + quotient coefficients;
`α` is the transcript-derived constraint-combining challenge
reduced to Goldilocks.

**Per-layer Merkle authentication** (`verifier.rs` inline) —
session 15. Each FRI layer opening `(f_x, f_neg_x)` is
cryptographically tied to that layer's Merkle root in
`fri_layer_commits`. Closes the last gap: a malicious prover can
no longer send arbitrary fold evaluations — they must authenticate
against the committed tree.

Leaf digest convention: `digest = f_bytes_le ‖ 24 × 0x00` (pad-to-
32). `f(x)` and `f(-x)` live at adjacent indices in each layer's
tree; paths are walked independently and compared against the
layer root.

**No scaffold caveats remaining for FRI-STARK.** Remaining work is
fixture-bound: real Plonky3 AIR-constraint evaluators (circuit-
specific, not protocol-generic).

## What tampering tests cover

Every soundness gate has at least one paired rejection test in the
same crate. These tests are documented as such — audit reviewers
can grep for `rejects_tampered_*` or `rejects_mismatched_*` to find
the coverage surface.

| Gate | Rejection test |
|---|---|
| Sumcheck identity | `mosaic-hyperplonk::sumcheck::verify_sumcheck_rejects_tampered_first_round` |
| Permutation term | `mosaic-hyperplonk::verifier::rejects_tampered_sigma_commitment` |
| Halo2 vanishing | `mosaic-halo2::verifier::rejects_tampered_gate_coefficient` |
| Halo2 two-point opening (session 16) | `mosaic-halo2::kzg::two_point_rejects_tampered_z_next_eval` |
| Halo2 multi-poly MSM (advice commit) | `mosaic-halo2::verifier::multipoly_rejects_tampered_advice_commit` |
| Halo2 multi-poly MSM (wire evaluation) | `mosaic-halo2::verifier::multipoly_rejects_tampered_wire_a_evaluation` |
| Halo2 multi-poly MSM (VK selector q_M) | `mosaic-halo2::verifier::multipoly_rejects_tampered_vk_selector_commit` |
| Halo2 multi-poly MSM (VK permutation σ_1) | `mosaic-halo2::verifier::multipoly_rejects_tampered_vk_permutation_commit` |
| HyperPlonk VK coset sensitivity | `mosaic-hyperplonk::verifier::permutation_term_depends_on_k_cosets` |
| HyperPlonk VK k_1 tamper detection | `mosaic-hyperplonk::verifier::tampered_k_1_breaks_expected_claim` |
| Nova Spartan batched opening (VK a_comm) | `mosaic-nova::verifier::spartan_rejects_tampered_vk_a_comm` |
| Nova Spartan batched opening (a_eval) | `mosaic-nova::verifier::spartan_rejects_tampered_hadamard_a_eval` |
| Nova Spartan batched opening (w_eval slot) | `mosaic-nova::verifier::spartan_rejects_tampered_w_eval_slot` |
| Hadamard residual | `mosaic-nova::verifier::rejects_tampered_hadamard_evals` |
| Nova fold reconstruction | `mosaic-nova::verifier::rejects_tampered_base_e_commitment` |
| Trace Merkle | `mosaic-stark::verifier::rejects_mismatched_trace_merkle_leaf` |
| Constraint Merkle | `mosaic-stark::verifier::rejects_mismatched_constraint_merkle_leaf` |
| PoW grinding | `mosaic-stark::challenges::pow_rejects_random_nonce_at_nonzero_bits` |
| FRI fold chain | `mosaic-stark::fri::chain_rejects_inconsistent_f_x_between_layers` |
| OOD quotient | `mosaic-stark::verifier::rejects_tampered_ood_constraint_eval` |
| Per-layer Merkle | (shares trace-Merkle path tests; dedicated test pending) |

## Primitive inventory

Cryptographic primitives available in-tree for consumers,
integrators, and auditors:

- **`mosaic-zk-primitives`** — BN254 `fr` (byte range + reduction),
  `field` (arkworks arithmetic), `msm` (G1 scalar mul + MSM),
  `transcript` (Keccak-256 Fiat-Shamir), `g1_consts` (generator
  encoders).
- **`mosaic-hyperplonk::sumcheck`** — `RoundPolynomial`,
  `verify_sumcheck`.
- **`mosaic-hyperplonk::mle`** — `eq_poly_eval`,
  `mle_eval_from_cube`.
- **`mosaic-hyperplonk::gate`** — `WireEvals`, `SelectorEvals`,
  `gate_expr`.
- **`mosaic-halo2::circuit`** — `gate_expr`, `permutation_expr`,
  `lookup_expr`, `combined_expr`.
- **`mosaic-halo2::vanishing`** — `compute_z_h`,
  `compute_t_from_chunks`, `vanishing_identity_holds`.
- **`mosaic-halo2::bundle`** — `EvaluationBundle` (16-slot fixed
  layout).
- **`mosaic-nova::folding`** — `hadamard_residual`,
  `folded_commitment_from_fold`, `folded_error_commitment`.
- **`mosaic-stark::goldilocks`** — `Goldilocks(u64)` field with
  `add`, `sub`, `mul`, `neg`, `inverse` (Fermat), `pow`,
  `from_bytes_le`, `to_bytes_le`, `eval_poly_le_bytes`.
- **`mosaic-stark::fri`** — `compute_next_layer_value`,
  `fold_relation_holds`, `verify_fold_chain`.
- **`mosaic-stark::merkle`** — `verify_path`.
- **`mosaic-stark::challenges`** — `derive_challenges`,
  `derive_query_indices`, `derive_layer_betas`, `verify_pow`,
  `has_leading_zero_bits`.

Each primitive has standalone unit tests against an arkworks oracle
or hand-computed closed-form values where applicable.

## Integration guidance

For protocols integrating Mosaic on Solana:

1. **Size compute-unit budgets** per-system per
   `docs/compute-unit-budget.md` (not every gate is CU-free —
   sumcheck and Merkle walks add per-round overhead).
2. **Treat `OnChainError` as opaque** for the consensus path.
   Specific variants are for telemetry / dashboards / retry
   decisions.
3. **Pin Mosaic version explicitly.** Canonical layouts are part of
   the protocol contract; a downstream prover generated against
   `v0.5.0-phase3-complete` won't verify under `v0.4.1-phase3-soundness`.
4. **Don't bypass scaffold caveats.** The remaining gaps
   (HyperPlonk cosets, Halo2 multi-poly MSM, Nova Spartan opening)
   are genuine soundness holes that external fixtures will close.

## Version history

| Release | Soundness milestone |
|---|---|
| `v0.4.0-phase3-bodies` | Structural validation for all four bodies. No cryptographic gates. |
| `v0.4.1-phase3-soundness` | Four primary gates wired: sumcheck+perm, vanishing, Hadamard, Merkle. |
| `ee9ed73` (session 8) | FRI-STARK gains constraint-Merkle gate. |
| `19a81f5` (session 9) | FRI-STARK gains PoW-grinding gate. |
| `0218d1d` (session 13b) | FRI-STARK gains fold-chain gate. |
| `44c182f` (session 14c) | FRI-STARK gains OOD-quotient gate. |
| `d9d2be6` (session 15) | FRI-STARK gains per-layer-Merkle gate (production parity). |
| `ed9363c` (session 15-nova) | Nova gains fold-reconstruction gate. |
| `c0e6280` (session 16) | Halo2 two-point batched opening. |
| **`v0.5.0-phase3-complete`** | **12 independent gates across 4 bodies. Phase-3 protocol-layer soundness complete.** |

Total at `v0.5.0-phase3-complete`: **12 cryptographic + 1 structural**
gates across four verifier families. Pattern for adding the next
gate in any verifier: extend canonical → parse → verify → test both
happy path and rejection.

## What's next (outside this doc's scope)

- Fixture-driven differential testing (external prover CLIs).
- HyperPlonk multi-point KZG reduction (Zeromorph/Pst/Gemini).
- Halo2 multi-poly MSM in opening (per-poly `v` batching).
- Nova Spartan multi-poly opening.
- External security audit engagement.

None block deploy readiness. Tree is audit-ready-surface at the
protocol layer.
