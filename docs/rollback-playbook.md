# Mosaic mainnet — rollback + incident response playbook

> Tracks issue [#69](https://github.com/wienerlabs/mosaic/issues/69).
> This document is the operational runbook for what happens between
> "we suspect something is wrong" and "it's resolved or the program
> is closed". Two operators must be able to execute every step here
> from the document, with no tribal knowledge.

## Quick reference

| Action | Threshold | Who | SLA |
|---|---|---|---|
| Acknowledge alert | Any P0 / P1 signal | On-call | 5 minutes |
| Convene incident channel | Suspected soundness issue | On-call | 15 minutes |
| Pause new integrations | Confirmed critical | Comms lead | 30 minutes |
| Freeze (`solana program close`) | Confirmed soundness break + cannot patch within 4 h | 2-of-3 multi-sig | 1 hour |
| Public disclosure | Per `SECURITY.md` § coordinated disclosure | Comms lead | 24-72 hours (severity dependent) |

## 1. Severity classification

Triage every signal into one of four levels. The level dictates the
rest of the playbook.

### P0 — Soundness break

A proof that should not verify, verifies. Or a proof that should
verify, deterministically does not (and a known-correct sibling
verifies).

- Examples: arkworks reference verifier accepts but Mosaic rejects
  (or vice versa); audit firm finds a malicious-input bypass; whitehat
  publishes a working PoC.
- **Response**: freeze within 1 hour. Public disclosure within 24
  hours per Solana Foundation coordinated-disclosure terms.

### P1 — Liveness break

Program is callable but every dispatch fails for a reason that is
not the proof being invalid (i.e. the dispatcher itself is broken,
or a Solana protocol upgrade broke our syscall assumptions).

- Examples: Solana 2.4 silently changed `alt_bn128_pairing` ABI and
  every call now returns `Custom(0x40)`; `mosaic-chunked` PDA layout
  collision blocks all chunked-upload sessions.
- **Response**: investigate + patch path. Freeze only if liveness
  cannot be restored within 24 hours and integrators have user-funds
  pending on chain.

### P2 — Performance regression

Verifier still works but consumes materially more CU than baseline,
breaking integrators' budgeting.

- Examples: Solana validator client patch increased `alt_bn128`
  syscall cost by 30 %; our bench detected a > 10 % drift after a
  release tag.
- **Response**: investigate. Communicate in advisory channels.
  Patch within next release cycle. No freeze.

### P3 — Documentation / supply chain

A documentation error or supply-chain warning that does not affect
production behaviour.

- **Response**: standard PR cycle. No incident channel needed.

## 2. Detection sources

Order of trust, top to bottom. A higher-trust source overrides a
lower-trust source.

1. **Audit firm direct contact** to <baturalp@wienerlabs.com>
2. **Solana Foundation security team** via their coordinated
   disclosure channel
3. **Independent researcher PoC** with reproducible code
4. **bpf-bench CU regression** in scheduled CI runs (P2 signal)
5. **mosaic-soak `unexpected_failure` count > 0** during a devnet or
   testnet soak (P0 or P1 depending on which fixture failed)
6. **Twitter / Discord / Telegram chatter** — never the initial
   trigger; only used to confirm a separately-reported finding

A signal from sources 1-3 always advances to at least P1
investigation. Sources 4-5 can be triaged in working hours unless
the count is high enough to indicate a sustained issue.

## 3. Communication tree

When an incident is convened, the on-call sends an initial message
to **all** of:

| Channel | Contact | Purpose |
|---|---|---|
| Internal incident channel | `#mosaic-incidents` on Slack (private) | Operational coordination |
| Audit firm (current) | Per `SECURITY.md` audit-firm contact | Embargo + technical review |
| Solana Foundation security | per `SECURITY.md` § coordinated disclosure | Ecosystem-wide impact assessment |
| Light Protocol security | Per `docs/coordinated-disclosure.md` | Light's groth16-solana shares syscall surface |
| Bonsol / Anagram security | Per `docs/coordinated-disclosure.md` | Risc0-in-CIRCOM users; potentially affected if `alt_bn128` is the issue |
| Major integrators | Mailing list (TBD; per #82 reference dapp launch) | Pause new integrations notice |

Initial message template:

```
SUBJECT: [MOSAIC INCIDENT] <severity> — <one-line description>

What we know:
  - <symptom>
  - <when first observed>
  - <source>

What we are doing:
  - <immediate action — e.g. "investigating", "convening operators
    for freeze decision">

What we are NOT yet certain of:
  - <known unknowns>

Next update: <ISO timestamp, max 4 h from now>

Embargoed: do not share outside this thread until coordinated
disclosure timeline begins.
```

Cadence: every 4 hours until resolved or every 12 hours if no new
information.

## 4. Decision tree

Use this tree before reaching for any destructive action.

```
Is the signal confirmed reproducible by a second operator?
  ├── No  → continue investigation; do not freeze
  └── Yes → continue ↓

Can we patch + redeploy within the SLA for this severity?
  ├── Yes (P0 < 4h, P1 < 24h)
  │      → patch path (see § 5)
  │      → freeze ONLY if patch fails
  └── No → freeze decision (see § 6)
```

The decision to freeze is **never unilateral**. It requires 2-of-3
multi-sig signatures per `docs/upgrade-authority.md` and is logged
in the incident channel before the multi-sig transaction is signed.

## 5. Patch path (no freeze)

When the patch path is viable:

1. **Branch off the current release tag.** Name the branch
   `incident/<YYYY-MM-DD>-<short-name>`. Push immediately so
   reviewers can pull.
2. **Land the fix** with a passing unit test that fails on the
   pre-fix branch. This is non-negotiable — no fix lands without a
   regression test.
3. **Run the full test suite** (`cargo test --workspace` +
   `cargo run -p mosaic-soak` locally if RPC reachable).
4. **Tag the release** as `v0.9.X-incident-<YYYY-MM-DD>` per the
   release-engineering policy in `CONTRIBUTING.md`.
5. **Audit firm hot-review** for soundness fixes (mandatory).
   Performance / liveness fixes can skip if the audit firm signs off
   in writing that the change surface is too small to re-audit.
6. **Build the SBF artifact** and record the SHA in
   `docs/audit-signoff.txt` so `scripts/deploy-mainnet.sh` gates
   match.
7. **Deploy to mainnet** with two operators present (per
   `scripts/deploy-mainnet.sh`).
8. **Verify** post-deploy: smoke test the affected dispatch arm
   against a known-good fixture from a different machine than the
   one that deployed.
9. **Resume communications**: send `RESOLVED` message to the full
   communication tree from § 3 with the patch commit SHA + the
   incident-channel summary.

## 6. Freeze path

When the patch path is not viable within SLA:

1. **Convene the 2-of-3 multi-sig signers** per
   `docs/upgrade-authority.md`. Document in the incident channel
   which signers are present.
2. **Cross-validate the freeze trigger.** Both signers independently
   confirm the freeze meets one of the criteria from
   `docs/upgrade-authority.md` § emergency freeze. Document this in
   the channel.
3. **Pause integrations communication.** Comms lead sends a
   pre-coordinated `PAUSE` message to integrators, Solana Foundation
   security, Light Protocol security, Bonsol / Anagram security,
   plus the public Twitter / Discord channels. Pre-coordinated
   template at the bottom of this doc.
4. **Execute the freeze.** Sign the Squads V4 freeze transaction
   from two of the three signers. The freeze (`solana program
   close`) is irreversible on the same program ID — once it lands,
   the program account is closed and the upgrade authority can no
   longer push a fix to the same address.
5. **Record the freeze.** Commit a memo to
   `docs/incidents/<YYYY-MM-DD>-freeze.md` containing:
   - Initial detection timestamp
   - Severity classification rationale
   - Decision-tree path taken
   - Multi-sig signer pubkeys + tx signature for the freeze
6. **Notify Solana Foundation security** that the freeze landed +
   the explorer link to the freeze tx.
7. **Begin postmortem** within 7 days. See § 8.

## 7. Forward-fix path after a freeze

A freeze closes the existing program account. The forward-fix path
is:

1. **Generate a new PROGRAM_ID** (vanity-grind for a name that
   communicates "this is the post-incident fork" — e.g.
   `MosA1cV2...`).
2. **Patch + audit** per § 5 steps 1-5.
3. **Deploy to mainnet** under the new PROGRAM_ID.
4. **Coordinate integrator migration.** Most integrators
   hardcode `PROGRAM_ID`; we expect at least 30 days of integrator
   coordination before the new program reaches the prior tx volume.
5. **Update `README.md` + the docs site** with the new program ID
   and a migration guide.

## 8. Postmortem

Required within 7 days of every incident at P0 or P1 severity.
Optional at P2.

Format (copy this into `docs/incidents/<YYYY-MM-DD>-<short>.md`):

```markdown
# Incident postmortem — <YYYY-MM-DD>

## Summary
One paragraph. What broke, what we did, what the impact was.

## Timeline
- HH:MM UTC — event 1
- HH:MM UTC — event 2
- ...

## Root cause
Technical detail. Cite the commit + line that introduced the bug
if applicable.

## Impact
Number of transactions affected. Estimated value at risk.
Integrators that paused / migrated.

## What went well
- ...

## What went wrong
- ...

## Action items
- [ ] #__ — concrete fix landed
- [ ] #__ — process improvement
- [ ] #__ — communication improvement

## Public summary (for disclosure)
The version of this postmortem that goes on the blog / Twitter
thread once embargo lifts. Pre-cleared with audit firm + Solana
Foundation.
```

## 9. Pre-coordinated communication templates

### Internal incident open

```
SUBJECT: [INCIDENT-OPEN] Mosaic <severity> — <one-line>

(see § 3 template)
```

### Public PAUSE (P0 freeze pending)

```
We've identified a potential issue with the Mosaic verifier
library. Out of an abundance of caution we are pausing new
integrations while we investigate. We will share details on
the recommended actions for current users within the next 24
hours. Existing on-chain transactions are unaffected.

For coordinated-disclosure inquiries: baturalp@wienerlabs.com.

— The Mosaic team
```

### Public FREEZE (post-execute)

```
At <ISO timestamp> UTC we executed an emergency freeze of the
Mosaic verifier program at <PROGRAM_ID>. The freeze landed in
tx <signature> and is observable at <explorer link>.

The freeze decision was made because <one-line — "soundness
issue we could not patch within the response SLA" or similar>.
Full postmortem will publish within 7 days.

Current integrators using this PROGRAM_ID will see VerifyProof
calls fail. We are coordinating with the affected integrators
directly and will publish migration guidance under the new
PROGRAM_ID once the patched program is audited and deployed.

— The Mosaic team
```

### Public RESOLVED (patch path)

```
At <ISO timestamp> UTC we deployed a patched version of the
Mosaic verifier program. The fix is described in CHANGELOG
entry <link>. Full postmortem will publish within 7 days.

No user funds were at risk during this incident. We thank
<acknowledgments> for responsible disclosure.

— The Mosaic team
```

## 10. Table-top exercises

Before mainnet, two table-top exercises must be completed:

1. **Internal**: the team runs a simulated P0 incident end-to-end
   over a 1-hour exercise. The operators must execute every step
   in this document without referencing memory; only the document.
   Record gaps; update this doc.
2. **External**: the same exercise with the audit firm present.
   They challenge the decision tree + the communication tree. Their
   findings update this document.

The simulated incidents:

| Exercise | Simulated incident |
|---|---|
| T-1 | Audit firm reports a malicious-input bypass in `mosaic-groth16`. Operators must convene + decide patch vs freeze + execute. |
| T-2 | Solana 2.4 patch breaks `alt_bn128_pairing` semantics on devnet. Operators must triage P1 + coordinate with Foundation + decide patch path. |
| T-3 | Audit firm reports a finding in `mosaic-chunked` that affects ongoing sessions. Operators must run the patch path while existing on-chain state has user assets. |

Each exercise produces a writeup at
`docs/incidents/tabletop-<exercise>.md`.

## 11. Review

This document is reviewed:

- Before every mainnet release (audit-firm-driven)
- After every real incident (operator-driven)
- Quarterly otherwise (calendar reminder)

Status: draft. Will be finalised by the time we close issue
[#66](https://github.com/wienerlabs/mosaic/issues/66) (mainnet
readiness epic).
