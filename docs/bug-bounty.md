# Mosaic bug bounty program (plan)

> Tracks issue [#79](https://github.com/wienerlabs/mosaic/issues/79).
> Status: **draft plan**. The program launches **after** the first
> external audit ([#71](https://github.com/wienerlabs/mosaic/issues/71),
> [#72](https://github.com/wienerlabs/mosaic/issues/72)) and is a gate
> on the mainnet ladder
> ([#66](https://github.com/wienerlabs/mosaic/issues/66)). Every dollar
> figure below is **proposed, pending founder + treasury sign-off** and
> is not a commitment until this document is marked Accepted and the
> treasury is funded.

## Why post-audit

A bug bounty is not a substitute for an audit. Running one before the
code is audited invites researchers to find the same class of issues a
paid audit would surface, at a worse signal-to-noise ratio and without
the structured methodology. The sequence is: complete the external
audit, fix findings, deploy to mainnet, then open the bounty so the
program covers the live, audited surface and rewards what the audit did
not catch.

## 1. Platform decision

| Platform | Strengths | Trade-off |
|---|---|---|
| [Immunefi](https://immunefi.com/) | Largest ZK + crypto researcher community; mature triage; standard severity classification | Higher platform fees; less Solana-native tooling |
| [Cantina](https://cantina.xyz/) | Solana-ecosystem alignment (Light Protocol runs its program here); competitive review option | Smaller dedicated ZK researcher pool than Immunefi |

**Recommendation**: Immunefi for the standing program (the verifier's
risk surface is ZK-soundness, where Immunefi's researcher pool is
deepest), with a time-boxed Cantina competition around the mainnet
launch window for Solana-native coverage. Final choice is the founder's
and is recorded in `docs/decisions/` when made.

## 2. Scope

### In scope

- `mosaic-program` deployed at the mainnet PROGRAM_ID (the address
  recorded in `README.md` after the #68 deploy).
- The verifier crates as compiled into that program: `mosaic-core`,
  `mosaic-groth16`, `mosaic-plonk`, `mosaic-hyperplonk`, `mosaic-halo2`,
  `mosaic-nova`, `mosaic-stark`, `mosaic-chunked`, `mosaic-serde`.

### Out of scope

- Third-party dependencies (the Solana runtime, the `alt_bn128`
  syscalls themselves, the SBF toolchain). Report those to their
  maintainers under their own programs.
- Anything already disclosed in `SECURITY.md` or under an open advisory.
- Findings reachable only by compromising a validator set or the
  upgrade-authority multi-sig (those are operational, not code, risks;
  see `docs/upgrade-authority.md`).
- Social engineering, physical attacks, and spam / automated-scanner
  output without a working proof of concept.
- Host-side tooling that never runs on chain (`mosaic-bench`,
  `mosaic-soak`, `mosaic-demo-sudoku`).

## 3. Severity classification

Aligned with the severity model in `docs/rollback-playbook.md` so a
bounty submission and an internal incident speak the same language.

| Severity | Definition | Proposed payout (USDC) |
|---|---|---|
| Critical | Soundness break: a proof that must not verify, verifies on chain. Direct, unauthorized acceptance of an invalid proof. | proposed, pending sign-off |
| High | Liveness / correctness break reachable from hostile input: a valid proof is wrongly rejected, or the dispatcher can be made to panic / brick a verification path. | proposed, pending sign-off |
| Medium | Griefing or state manipulation without a soundness break (e.g. forcing excess CU consumption, chunked-session denial). | proposed, pending sign-off |
| Low | Informational or minor logic issues with no direct security impact. | proposed, pending sign-off |

The payout bands are set by the founder once the treasury is funded.
They will be benchmarked against comparable ZK-verifier programs at
launch time rather than fixed here, so this document does not commit the
project to a number before the treasury exists.

The **Critical / soundness** tier is the one that matters: for an
on-chain verifier, accepting an invalid proof is the whole threat model.

## 4. Funding + custody

- **Treasury**: a dedicated USDC vault funded before the program goes
  live. Target reserve is set at sign-off (a common reference is a
  small multiple of the projected annual Critical payout).
- **Custody**: the bounty vault is controlled by the **same 2-of-3
  Squads V4 multi-sig** that holds the program upgrade authority, per
  `docs/upgrade-authority.md`. No new signer topology is introduced for
  the bounty; reusing the audited 2-of-3 keeps the custody surface
  minimal and already-reviewed.
- **Launch condition**: treasury funded and the multi-sig payout flow
  dry-run on devnet before the program is announced.

## 5. Process

1. **Submission**: through the chosen platform (Immunefi / Cantina),
   not the public issue tracker. The `.github` issue templates link to
   the program and explicitly tell reporters not to file in-scope
   vulnerabilities publicly.
2. **Acknowledgement SLA**: 48 hours for Critical / High, 7 days for
   Medium / Low.
3. **Triage + validation**: reproduce against a pinned commit; classify
   severity; loop in the audit firm for any Critical soundness claim.
4. **Disclosure**: follow `docs/responsible-disclosure-timeline.md` and
   the embargo windows there. Coordinate ecosystem-wide impact with the
   Solana Foundation security team per #87.
5. **Payout**: within 14 days of validation, from the 2-of-3 vault.
   First valid reporter of a unique issue receives the full reward;
   duplicates are handled at the program's standard discretion.

## 6. Security contact

For anything that should not go through the public platform (or before
the program is live), email **baturalp@wienerlabs.com**, the address
published in `SECURITY.md`. Do not open a public GitHub issue for a
suspected vulnerability.

## 7. Pre-launch checklist

- [ ] External audit complete and findings remediated (#71, #72)
- [ ] Mainnet PROGRAM_ID deployed and recorded (#68)
- [ ] Platform chosen + scope document published (decision in `docs/decisions/`)
- [ ] Payout bands finalized by founder
- [ ] Treasury USDC vault funded under the 2-of-3 Squads V4 multi-sig
- [ ] Multi-sig payout flow dry-run on devnet
- [ ] `SECURITY.md` + issue templates link to the live program
- [ ] Coordinated-disclosure terms aligned with Solana Foundation (#87)
- [ ] Mainnet launch (#66) gated on the program being live

## 8. Related

- `SECURITY.md`: current disclosure policy + contact
- `docs/responsible-disclosure-timeline.md`: embargo windows
- `docs/rollback-playbook.md`: incident response (consumes bounty findings)
- `docs/upgrade-authority.md`: the 2-of-3 Squads V4 that also custodies the vault
- Issues #66 (mainnet ladder), #71 / #72 (audits), #87 (Foundation disclosure)

Status: draft. Finalized and marked Accepted at sign-off, before launch.
