# BN254 G2 subgroup-check parity report

> Tracks issue [#35](https://github.com/wienerlabs/mosaic/issues/35).
> Audit-facing. Establishes that Mosaic's host backend and the on-chain
> `alt_bn128` pairing reject the same class of malformed G2 inputs, so a
> forged proof that relies on a non-subgroup point cannot verify on
> either backend.

## The threat

BN254's G2 group is `r · h2` points, where `r` is the prime subgroup
order and `h2` (the cofactor) is large. A pairing is only sound over
points in the order-`r` subgroup. The 2022 subgroup-check bug class
(geth's EIP-197 precompile, and parallel concerns in early Solana) came
from pairings that validated only "on the curve" and not "in the
subgroup" - a point on the curve but outside the subgroup can make a
pairing relation hold for inputs that should not verify, which is a
soundness break for a Groth16 verifier (the proof element `B` is a G2
point supplied by the prover).

So both of Mosaic's pairing backends must reject:

1. **Off-curve** G2 encodings (coordinates that don't satisfy the curve
   equation), and
2. **On-curve but wrong-subgroup** G2 points (the subtle, exploitable
   class).

## Where Mosaic validates

Mosaic does not add its own subgroup check around the pairing; it
delegates G2 validation to the pairing backend, then asserts (here) that
both backends enforce it.

### Host backend (arkworks)

`mosaic_core::syscall` host implementation, `decode_g2`
(`crates/mosaic-core/src/syscall.rs`):

```rust
let point = G2Affine::new_unchecked(x, y);
if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
    return Err(OnChainError::PointNotOnCurve);
}
```

`decode_g1` does the same for G1. So the host backend rejects both
adversarial classes **at decode time**, before any pairing arithmetic,
with `PointNotOnCurve` (`0x0006`).

### On-chain backend (Solana syscall)

The `SolanaSyscallBackend` passes the raw encoding to
`solana_bn254::alt_bn128_pairing`. The syscall performs its own input
validation in the runtime.

## Test evidence

| Adversarial input | Host backend | On-chain syscall |
|---|---|---|
| Off-curve G2 | Rejected `PointNotOnCurve` | Rejected (curve check) |
| On-curve, wrong-subgroup G2 | Rejected `PointNotOnCurve` (`0x06`) | Rejected `AltBn128SyscallFailed` (`0x40`) |

Tests:

- `mosaic_zk_primitives::msm::tests::pairing_rejects_off_curve_g2` - a G2
  with one perturbed `y` byte is rejected by the host pairing.
- `mosaic_zk_primitives::msm::tests::pairing_rejects_wrong_subgroup_g2` -
  constructs an on-curve point outside the prime-order subgroup
  (asserting both `is_on_curve()` and
  `!is_in_correct_subgroup_assuming_on_curve()` to prove the fixture is
  genuinely adversarial) and asserts the host pairing rejects it with
  `PointNotOnCurve`.
- `mosaic_program::tests::verify_proof_sbf::sbf_rejects_wrong_subgroup_g2_in_proof_b`
  - splices the same wrong-subgroup point into a real Groth16 proof's `B`
  element and submits it to the program on the `solana-program-test` VM;
  the program rejects it with `AltBn128SyscallFailed` (`0x40`).

The reusable fixture is
`mosaic_zk_primitives::g1_consts::wrong_subgroup_g2_canonical()` (a
deterministic on-curve, non-subgroup G2 in canonical bytes), so
downstream integrators can run the same parity check against their own
verifier wiring.

## Result

**Parity holds.** Both backends reject the same adversarial G2 classes.
The error codes differ - the host's explicit decode-time check returns
`PointNotOnCurve`, while the on-chain syscall rejects the input at the
syscall boundary and surfaces `AltBn128SyscallFailed` - but the security
decision is identical: **neither backend computes a pairing over a
non-subgroup G2**, so a forged proof relying on such a point cannot
verify on either path.

This matches Light Protocol's `groth16-solana` posture (it relies on the
same syscall's validation). The key difference from a naive verifier is
that the on-chain rejection happens **at the syscall level**
(`0x40`), not via a pairing result that merely "didn't equal 1" - i.e.
the malformed point is refused, not pairing-computed-and-rejected.

## Caveats + scope

- This covers the `B` element of the proof and, by the same decode path,
  the VK's `beta_g2` / `gamma_g2` / `delta_g2`. The VK is trusted (set by
  the circuit author), so the attacker-controlled surface is `B`.
- The on-chain mechanism is the Solana runtime's; a future Solana release
  that changed `alt_bn128_pairing`'s validation would be a P1 liveness
  signal per `docs/rollback-playbook.md` and is exactly what the
  cross-validator determinism harness (#70) + this test guard against.
- **G1 has cofactor 1** on BN254 (`alt_bn128`): the G1 group is
  prime-order, so every on-curve G1 point is already in the subgroup and
  the subgroup check is vacuous for G1. `decode_g1` still runs the same
  `is_in_correct_subgroup_assuming_on_curve` check (cheap, always true on
  a valid point), so the only adversarial G1 class is **off-curve**,
  which both backends reject on the curve-equation check. The
  cofactor-induced wrong-subgroup risk is G2-only, which is exactly the
  surface tested above (the prover-supplied `B` is the G2 element).

## Related

- `crates/mosaic-core/src/syscall.rs` - `decode_g1` / `decode_g2`
- `crates/mosaic-zk-primitives/src/msm.rs` - host parity tests
- `crates/mosaic-program/tests/verify_proof_sbf.rs` - on-chain parity test
- `docs/threat-model.md` - the malformed-input threat (T-3)
- Issue [#35](https://github.com/wienerlabs/mosaic/issues/35) - this report
