# Outreach email — pre-audit discovery inquiry

**Status:** Draft template. Review + personalize per firm before sending.

---

## Subject line options

1. `Mosaic — audit engagement inquiry, Solana ZK verifier library`
2. `RFQ: Mosaic (multi-proving-system Solana verifier) — Phase 1 audit`
3. `Wiener Labs — audit scoping inquiry for Solana BN254 Groth16 library`

Pick (1) for firms that value precision; (3) for firms that want to see
the scope framing upfront.

---

## Body (generic template)

```
Hi [FIRST NAME / team],

We're the team behind Mosaic (https://github.com/wienerlabs/mosaic), a
proof-system-agnostic on-chain verifier library for Solana written in
Rust. Phase 1 just tagged as v0.1.0-phase1 and shipped:

 - a BN254 Groth16 verifier mirroring Light Protocol's CU envelope,
 - snarkjs + arkworks format adapters with byte-equal round-trip,
 - a chunked-upload protocol for proofs that exceed Solana's 1232-byte
   instruction limit (domain-separated SHA-256 rolling hash, PDA seeds
   bound to (session_id, payer)),
 - 36 tests + a bpf-bench CU regression gate measuring real on-chain
   consumption against ADR-0005 hard caps.

We're opening the door for an independent security audit before Phase 2
(KZG-PLONK + Halo2-KZG) ships. Attaching our RFQ:

    https://github.com/wienerlabs/mosaic/blob/main/docs/audit/rfq.md

What's in scope is ~2400 LoC of library + program code. Threat model,
design docs, and a 12-item self-review checklist are maintained in the
repository so the audit team can see exactly what we've considered.

Specific areas we want challenged:

 - Two-layer error taxonomy as consensus-failure defence (SIMD-0129
   reference).
 - Rolling-hash chunked-upload protocol + PDA-seed front-running
   defence.
 - G2 c0/c1 byte-ordering surface between arkworks and Solana's
   alt_bn128 syscall convention.
 - LE/BE forward-compatibility for the SIMD-0204 activation.

If you're interested, we'd love to schedule a 30–45 minute discovery
call in the next two weeks. Happy to share more context and answer
questions before any formal quote.

Target kick-off window: [INSERT — e.g. 2026-Q3].
Budget range: discussable on call; we've benchmarked against typical
Solana + ZK engagement costs.

Thanks for your time,

[SENDER NAME]
[ROLE], Wiener Labs
baturalp@wienerlabs.com
```

---

## Per-firm personalization notes

### Zellic

Opening paragraph should mention their published Solana ZK audit work.
Flag our PDA-seed front-running defence and chunked-upload rolling hash
explicitly — consistent with their public audit report style.

Suggested additional line:
> *Your team's work on [SPECIFIC RECENT AUDIT, e.g. Sanctum / Jito / etc.]
> was part of how we chose a reference cadence for our own review flow.*

### Veridise

Lead with formal verification angle — our `formal-verify` feature flag
exists as an explicit hook for Kani / Creusot. Mention we designed the
trait surface to be formal-verification-friendly (byte-slice API,
object-safe dispatch).

Suggested additional line:
> *Our trait design keeps `ProofSystem::verify` as a byte-slice API
> specifically to make pre/post conditions expressible in Kani or
> Creusot; we'd welcome conversation about whether that's the right
> shape.*

### OtterSec

Lead with Solana ecosystem depth — they've audited many Solana programs
and will be most comfortable with the PDA / syscall / BPF
vocabulary. Reference our `solana-bn254` + `solana-keccak-hasher`
migration work for the Solana 2.x crate split.

Suggested additional line:
> *We ran into the Solana 2.x crate-split complications (no
> `solana-poseidon` crate yet, alt_bn128 moved to `solana-bn254`); your
> team's familiarity with that landscape would be valuable for the
> Phase 2 path.*

### Asymmetric Research

Lead with BN254 + STARK depth — our chunked-upload protocol is what
unblocks Phase 3 STARK verification on Solana, and they have prior
work on STARK performance. Mention the FRI inline-suppression technique
from eprint 2025/1741 that we're planning to adopt.

Suggested additional line:
> *Our Phase 3 plan adopts the eprint 2025/1741 Winterfell-on-Solana
> FRI technique. A firm that has deep BN254 + STARK background like
> yours would be a natural continuity reviewer across phases.*

---

## Do NOT include in the email

- Specific dollar numbers before the firm has quoted.
- Names of other firms we're talking to.
- Previous failed outreach attempts.
- Complaints about other projects or competing audits.

---

## Private tracking (NOT in the repository)

Firm response tracking lives in the private Wiener Labs
Notion/Linear space, not in this repo. The issue-#61 comment thread on
GitHub references *that* the tracker exists but does not leak contents.

Status fields to track per firm:

| Field | Example |
|---|---|
| First contact date | 2026-04-21 |
| Response time | 3 business days |
| Quote received | 2026-04-28 |
| Quote USD | $42 000 |
| Engagement window | 2026-Q3, 5 weeks |
| Team composition | 1 lead + 2 reviewers |
| References verified | yes — 3 Solana audits in 2025 |
| Pre-audit questions raised | 4 clarifying questions (see Linear) |
| Decision deadline | 2026-05-10 |
| Outcome | engaged / declined / waiting |

---

## Response template — quote received, we're evaluating

```
Hi [FIRST NAME],

Thanks for the quote — we're evaluating it against two other firms we
are in discovery with. Decision target is [DATE, e.g. 2026-05-10].

Could you confirm:

 - Lead auditor availability during the [DATE RANGE] window.
 - Whether findings can be delivered as SARIF alongside the human
   report.
 - Liability cap assumptions for the engagement.

Will come back within [N] business days.

[SENDER]
```

## Response template — engaging

```
Hi [FIRST NAME],

Good news — we'd like to engage for the Phase 1 scope. Next steps:

 1. Kick-off call: [DATE + TIME ZONE].
 2. Mutual NDA: we'll send ours in the next 48 hours.
 3. Engagement contract: standard terms, 30/40/30 milestone split per
    RFQ.
 4. Pre-read: AUDIT.md self-review checklist + threat model. Your lead
    is welcome to submit clarifying questions before kick-off.

Looking forward to working together.

[SENDER]
```

## Response template — declining

```
Hi [FIRST NAME],

Thank you for the thoughtful quote. We've decided to move forward with
a different firm for this engagement, primarily because of
[FACTUAL REASON: scheduling overlap / scope alignment / team
composition]. This isn't a reflection on technical quality.

We'd be glad to engage on a future phase (Phase 2 KZG-PLONK in
[QUARTER]) if that timeline aligns. I'll circle back closer to the
Phase 2 freeze.

Best,

[SENDER]
```
