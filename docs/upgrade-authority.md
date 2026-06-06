# Mosaic mainnet upgrade-authority policy

> Tracks issue [#86](https://github.com/wienerlabs/mosaic/issues/86).
> Design doc — will be finalised after audit firm review.

## What this document decides

Three things, each with a non-negotiable answer:

1. **Who can sign a program upgrade**? (multi-sig threshold + signer list)
2. **Where does the keying material live**? (hardware-wallet vendor, recovery)
3. **When does the upgrade authority go away**? (immutability sunset)

## Decision: 2-of-3 founder multi-sig via Squads V4

| Signer | Role | Hardware | Recovery |
|---|---|---|---|
| Baturalp | ZK developer · founder | Ledger Nano S+ | 24-word seed in safety-deposit box A |
| Mehmet | Software developer · founder | Ledger Nano S+ | 24-word seed in safety-deposit box B |
| Ferit | System architect · part-time | Yubikey 5C with Solana plugin | Yubikey backup unit in safety-deposit box C |

**Threshold**: 2-of-3 signatures required to authorize an upgrade.

**Why 2-of-3, not 3-of-5**: at our team size, 3-of-5 means adding non-team
signers (audit firm? community member?). Until we've operated the multi-sig
for at least 90 days, we don't trust ourselves to coordinate across an
external signer in an actual incident. Will revisit at v1.1.0.

**Why Squads V4 and not Realms / SPL token multi-sig**:
- Squads V4 has been audited (Halborn, OtterSec, Trail of Bits)
- Native support for program upgrade transactions
- UI for non-CLI signers (matters for Ferit's Yubikey workflow)
- Used by Light Protocol's groth16-solana production deployment

## Emergency freeze

The upgrade authority can also CLOSE the program, which freezes execution
permanently. This is the rollback mechanism per issue
[#69](https://github.com/wienerlabs/mosaic/issues/69).

**Freeze authorisation**: same 2-of-3 threshold as upgrade.

**Freeze trigger criteria** (any one is sufficient):
- Audit firm flags a soundness issue we cannot patch within 24 h
- Independent researcher publishes a verified soundness PoC
- CU consumption drifts > 50 % vs pinned baseline (could indicate
  malicious behaviour or compiler regression)

We will NOT freeze for performance issues alone, billing disputes,
governance disagreements, or marketing reasons. The freeze authority
is a security tool, not a business tool.

## Sunset: when do we burn the upgrade authority?

**Decision**: defer until v2.0.0. Pre-v2 we keep the ability to upgrade
because soundness fixes will land. Post-v2 we will publish a sunset
schedule.

Two open options for sunset:
1. **Set upgrade authority to all-zeros** (`11111111111111111111111111111111`) —
   program becomes immutable forever.
2. **Hand upgrade authority to a DAO** — requires governance design
   (issue [#41](https://github.com/wienerlabs/mosaic/issues/41) tracks
   code-of-conduct + governance prereq).

The audit firm will recommend which path. The choice is reversible
until we execute it.

## Key-loss recovery

If **one** signer loses both their hardware wallet AND the seed phrase
backup:
- Multi-sig still works at 2-of-3 — no recovery needed
- We rotate the lost signer out using the remaining 2 signatures and
  add a new signer (still 2-of-3)

If **two** signers lose both hardware AND backups simultaneously:
- We cannot authorize new upgrades — the program is effectively immutable
- This is a feature, not a bug. A 2-of-3 design says "if 2 are lost, we
  trust that better than letting 1 sign unilaterally"
- The remaining signer can still authorise a FREEZE (CLOSE the program)
  if needed, IF Squads V4 supports threshold reduction for emergency-
  only operations (TBD — research)

## Devnet rehearsal

Before mainnet (issue [#68](https://github.com/wienerlabs/mosaic/issues/68)):

1. Set up the same 2-of-3 multi-sig on Solana devnet with the same
   hardware wallets
2. Deploy the actual `mosaic_program.so` artifact to devnet under that
   multi-sig
3. Perform a no-op upgrade (re-deploy the same byte stream) — every
   signer signs once
4. Perform a freeze (CLOSE) operation
5. Document the latency from "trigger event" to "freeze landed" — must
   be under 1 hour per the incident playbook

The devnet rehearsal IS the dress rehearsal for mainnet. We will not
deploy to mainnet without completing it.

## Review

This document is reviewed by the audit firm before v1.0.0 cuts.
See `AUDIT-CHECKLIST.md` for the broader audit scope.

Status: draft. Will be finalised by the time we close issue
[#66](https://github.com/wienerlabs/mosaic/issues/66) (mainnet
readiness epic).
