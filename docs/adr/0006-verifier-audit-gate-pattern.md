# ADR-0006 — Verifier audit-gate extraction pattern

* **Status:** Accepted (2026-04-26)
* **Deciders:** Mosaic core team
* **Sessions:** 86, 87, 88, 89, 90, 91 (releases v0.8.6 → v0.8.11)

## Context

Across the Phase-3 verifier track (`mosaic-{nova, halo2, hyperplonk,
stark}`) we observed a recurring inline-pattern smell:

```rust
// inside SomeVerifier::verify
let expected = compute_some_value(...)?;
if expected != proof.declared_value {
    return Err(OnChainError::SomeError);
}
```

The pattern repeats 4+ times per verifier (one per soundness boundary),
mixed with parsing, transcript work, and pairing-check setup. This has
three concrete costs:

1. **Audit readability cost.** External audit firms have to grep
   through hundreds of verifier lines to find the soundness boundaries.
   The pattern is not flagged by name and the rejection error type
   varies subtly between callsites.
2. **Maintenance cost.** Adding a new soundness check (e.g. session 87's
   `r`-binding fix) requires touching the inline pattern in one file
   while the soundness invariant is documented elsewhere.
3. **Doc-vs-code drift cost.** The session-88 audit caught a doc
   claim (`Σ_X m(X) = 0`) that didn't match the actual code path.
   Inline patterns make it easy for the docs to drift from the code
   because the doc sits in a module-level comment but the check sits
   in the verifier body.

The campaign across sessions 86 → 91 extracted these inline patterns
into named, publicly callable, testable audit-gate functions —
**one per primary soundness boundary per verifier**.

## Decision

Every Phase-3 verifier MUST expose its primary soundness check(s) as
a `pub fn verify_*` function with the following contract.

### The pattern

```rust
/// **Session N** — high-level [verifier] [soundness-domain] audit gate.
///
/// Recomputes [the expected value] from [proof inputs + transcript
/// challenges + VK fields] and byte-compares against [the proof's
/// declared value]. Rejects disagreements as
/// [`OnChainError::SpecificErrorType`].
///
/// This is the audit-grade "[plain-English question this gate
/// answers]" check.
///
/// ## Inputs
///
/// - `<input1>` — [what it represents in the verifier flow]
/// - `<input2>` — ...
///
/// ## Errors
///
/// - [`OnChainError::ProofLengthMismatch`] / [validation propagation]
/// - [`OnChainError::SpecificErrorType`] — the soundness violation
pub fn verify_<verifier>_<soundness_domain>(
    /* inputs the auditor would hand-construct to test the gate */
) -> Result<(), OnChainError> {
    // 1. Up-front input validation if the gate has a wide input
    //    surface (multiple slices, optional fields, ...). A single
    //    rejection point with a uniform error type before any syscall
    //    fires.
    if /* shape invariants violated */ {
        return Err(OnChainError::ProofLengthMismatch);
    }

    // 2. Recompute the expected value via the verifier's existing
    //    primitives. No new soundness logic — the gate is a wrapper.
    let expected = primitive_call_a(...)?;
    let recomputed = primitive_call_b(...)?;

    // 3. Byte-compare against the proof's declaration; reject on
    //    mismatch with the gate's named error type.
    if expected != recomputed {
        return Err(OnChainError::SoundnessSpecificError);
    }
    Ok(())
}
```

### Mandatory companion: tests

Every audit gate MUST ship with:

1. **At least one unit test** demonstrating the round-trip identity
   (honest input → `Ok(())`).
2. **At least one unit test** per failure mode in the `Errors` section
   (each error type must be triggerable).
3. **At least one proptest** pinning the audit-grade soundness
   invariant across a randomized input space. Use `proptest_*` naming
   so the property tests are easy to grep for.

### Mandatory companion: lib.rs re-export

The audit gate MUST be re-exported from the crate root so external
consumers and test harnesses can call it without knowing the
internal module structure.

### Audit-pack quartet sync

Every release that adds or changes an audit gate MUST update the
audit-pack quartet in lockstep:

- `Cargo.toml` workspace version bump
- `README.md` release badge
- `CHANGELOG.md` release entry (under `## [Unreleased]` first, then
  promoted on tag)
- `AUDIT.md` milestone entry with auditor / scope / findings table

This is the same discipline established by the v0.8.x audit-coverage
campaign and codified in `docs/audit-coverage-runbook.md`.

## Pattern instances at v0.8.13

### Phase-3 verifiers (sessions 86 → 91)

| Verifier | Audit gate | Recipe | Soundness domain | Session | Tag |
|---|---|---|---|---|---|
| Nova | `verify_folding_consistency` | reconstruct `(E, W)_folded` from base commits + cross-term, byte-compare to declared | folded-instance accumulator consistency | 86 | v0.8.6 |
| Nova | (binding fix, no new gate) | bind `r` to all 7 G1 inputs in transcript | folding-challenge transcript binding | 87 | v0.8.7 |
| Halo2 lookup | `verify_multi_column_lookup_identity` | evaluate log-derivative identity over k-column inputs, reject if non-zero | per-row lookup soundness | 88 | v0.8.8 |
| Halo2 lookup | `MultiColumnLookupEvals::from_basic` | bridge `LookupEvals` → arity-1 `MultiColumnLookupEvals` | backward-compatibility soundness | 89 | v0.8.9 |
| STARK FRI | `verify_fri_query` | walk fold chain + eval final-poly + byte-compare | per-query FRI soundness | 90 | v0.8.10 |
| HyperPlonk | `verify_sumcheck_claim_reduction` | recompute expected claim from `(final_evals, χ, vk)`, byte-compare to sumcheck output | sumcheck claim reduction | 91 | v0.8.11 |

### Phase-2 verifiers (sessions 93 →)

| Verifier | Audit gate | Recipe | Soundness domain | Session | Tag |
|---|---|---|---|---|---|
| Groth16 BN254 | `verify_groth16_pairing_identity` | assemble 4-pair pairing input + execute alt_bn128 syscall + check Fq12 identity byte | pairing-equation soundness | 93 | v0.8.13 |
| KZG-PLONK BN254 | `verify_plonk_pairing_identity` (alias of `verify_pairing`) | assemble 2-pair pairing input over `(-A1, X_2) · (B1, [1]_2)` + execute alt_bn128 syscall + check Fq12 identity byte | pairing-equation soundness (KZG batched opening) | 94 | v0.8.14 |

### Test-suite breakdown

| Audit gate | Unit tests | Proptests | Total |
|---|---|---|---|
| `verify_folding_consistency` | 5 | 4 | 9 |
| `verify_multi_column_lookup_identity` | 4 | 3 | 7 |
| `verify_fri_query` | 5 | 1 | 6 |
| `verify_sumcheck_claim_reduction` | 4 | 2 | 6 |
| `verify_groth16_pairing_identity` | 5 | 0 | 5 |
| `verify_plonk_pairing_identity` | 6 | 0 | 6 |
| **Total** | **29** | **10** | **39** |

Plus session-87's `proptest_base_commit_mutation_cascades` (1) and
session-88's two doc-correction-prompted unit tests (4 from
`MultiColumnLookupEvals::try_new`) and session-89's bridge tests (4) =
**42 audit-gate-related tests** across the campaign.

Note on `verify_groth16_pairing_identity`: the gate is intentionally
covered by 5 unit tests (all error paths via a programmable backend)
without proptest coverage at the unit level, because the success-path
proptest equivalent is the existing differential test suite that
exercises the gate end-to-end against real BN254 fixtures via the
arkworks host backend. Tampered-fixture coverage at the differential
level effectively pins the `acceptance ⇔ valid proof` invariant
across the random fixture space.

## Consequences

### Positive

- **Audit story is greppable.** External auditors run
  `git grep '^pub fn verify_'` in `crates/mosaic-{nova, halo2,
  hyperplonk, stark}/src/` and find every soundness boundary by name.
- **Each gate has a dedicated test suite.** Adding a new soundness
  check inside an existing gate (e.g. session 87's `r`-binding fix)
  surfaces as a focused diff inside that gate's test mod, not as a
  cross-cutting change scattered through the verifier.
- **Doc-vs-code drift surfaces faster.** The audit gate's doc lives
  on the function itself; readers can verify the doc against the
  10-20 line implementation in one screen.
- **Consistent error vocabulary.** Each gate documents its specific
  rejection error type (`SumcheckFailed`, `VerificationFailed`,
  `InternalInvariantViolation`); error-type drift across verifiers
  is caught in code review.
- **Public API surface enables external test harnesses.** Phase-3
  fixture-driven differential testing (the last named pre-audit gap)
  can call audit gates directly with adversarial inputs.

### Negative

- **Function-call indirection cost.** Each gate adds one stack frame
  + register-shuffle vs the inlined pattern. For SBF this is
  negligible (rustc inlines aggressively across mod boundaries with
  `opt-level = "z"`), but worth noting at the API boundary.
- **Slight duplication risk.** A gate that wraps `compute_X(...) +
  if X != Y { reject }` ships *two* public functions (the compute and
  the gate). Auditors must read both. We mitigate this by promoting
  the inner compute function to `pub` only when it has standalone
  audit value (e.g. HyperPlonk's `compute_expected_final_claim`).

### Neutral

- Wire format and on-chain ABI are unaffected; every extraction is a
  byte-equivalent refactor (verified by the existing test suites
  remaining green across the migration commits).

## Recipe for adding a new verifier

When adding a new ZK verifier to the workspace (e.g., a future
`mosaic-bulletproofs` or `mosaic-fflonk` crate), follow this checklist:

1. **Identify the soundness boundaries.** Each is a place in the
   verifier where the proof is rejected if a recomputed value
   disagrees with a prover-declared value. Typical boundaries:
   - Constraint-system identity check (the "is this proof actually
     about this circuit?" gate)
   - Polynomial-opening check (KZG / FRI / IPA pairing or fold)
   - Transcript-binding check (the "did the prover commit to inputs
     before seeing the challenge?" gate — see session 87)
   - Per-element soundness check (the "does this row / query / layer
     pass its local invariant?" gate)

2. **Per soundness boundary, write a `verify_<verifier>_<domain>`
   audit gate** following the contract above.

3. **Per gate, write at least 3 tests** (1 happy path, 1 per failure
   mode, 1 proptest invariant pin).

4. **Re-export the gate from the crate root.**

5. **Document the gate in `docs/audit-coverage-runbook.md`** with
   reproduce + extend recipes for external audit firms.

6. **Update this ADR's instance table** with a row for the new
   verifier's gate(s).

## Related documents

- `docs/audit-coverage-runbook.md` — local-reproduce + extend recipes
  for every audit-coverage surface.
- `docs/phase3-soundness.md` — Phase-3 soundness scope notes per
  verifier (audit-gate functions are now the canonical entry points).
- `AUDIT.md` — audit-log entries for each release (sessions 86 → 91
  are documented in detail).
- `CHANGELOG.md` — release-by-release breakdown of audit-gate
  additions and migrations.

## References

- Session 86 commit / v0.8.6 release notes — Nova folding consistency
  (the originating extraction pattern that this ADR generalizes).
- Session 87 commit / v0.8.7 release notes — the soundness fix the
  session-86 work exposed.
- Session 91 commit / v0.8.11 release notes — completion of the
  4-way Phase-3 verifier symmetry that this ADR codifies.
