# Coordinated disclosure with the Solana ZK ecosystem

> Tracks issue [#87](https://github.com/wienerlabs/mosaic/issues/87).
> `SECURITY.md` and `docs/responsible-disclosure-timeline.md` cover how a
> reporter reaches us and our internal turnaround. This document covers
> the **outward** coordination: who else gets told, when, and in what
> form, when a Mosaic finding has ecosystem-wide implications. The
> internal disclosure flow is unchanged; this sits on top of it.

## When ecosystem coordination is triggered

Not every finding needs ecosystem coordination. The trigger is **shared
root cause or shared blast radius**, judged during triage (Stage 2 of
`docs/responsible-disclosure-timeline.md`):

| Finding root cause | Coordinate with |
|---|---|
| The `alt_bn128` syscall itself (G1/G2/pairing/compression) behaves unexpectedly | Solana Foundation security **first** (it is their code), then every project below |
| A bug class in *our* BN254 verifier logic that peer verifiers likely share (e.g. a subgroup-check gap, a transcript malleability) | The peer projects below, under embargo |
| A bug confined to Mosaic's own code with no shared surface | No ecosystem coordination; standard `SECURITY.md` flow |

The deciding question: "if this is real, can the same input break someone
else who uses the same syscall or the same verification pattern?" If yes,
coordinate.

## The ecosystem contact tree

These projects share the `alt_bn128` syscall surface and/or the
BN254-verifier problem space with Mosaic. They are notified under embargo
when the trigger above fires.

| Party | Why they're in the tree | Contact (to establish) |
|---|---|---|
| **Solana Foundation security** | Owns the `alt_bn128` syscalls + the runtime; the authority for any syscall-level issue and for ecosystem-wide coordination | Per the [Solana security disclosure policy](https://solana.com/docs/security-disclosure); `security@solana.org` |
| **Light Protocol** | `groth16-solana` is the reference BN254 Groth16 verifier on Solana; shares our exact syscall + subgroup concerns | Establish a direct security contact |
| **Bonsol / Anagram** | Wrap Risc0 proofs in CIRCOM Groth16 precisely because no native Risc0 verifier exists; affected if the issue is in the shared `alt_bn128` path | Establish a direct security contact |
| **ZK Compression** | Heavy on-chain ZK on Solana; shares the syscall surface | Establish a direct security contact |
| **Major Mosaic integrators** | Direct dependents; need a pause/migrate signal | Integrator security mailing list (stood up with the reference dapp, #82) |

> **Operational TODO (the founder's, not code):** the contacts above are
> *roles*, not yet established relationships. Before mainnet, reach out to
> the Solana Foundation security team and at least Light Protocol to
> exchange security contacts + PGP keys, so the tree is warm before an
> incident, not cold. Tracked as the open sub-tasks of #87.

## Embargo timeline

We follow the **Solana Foundation's coordinated-disclosure timeline** as
the outer bound, and our own `docs/responsible-disclosure-timeline.md` as
the inner commitments. Defaults, severity-dependent:

| Severity | Embargo before public disclosure | Rationale |
|---|---|---|
| Critical (soundness break) | Up to 90 days, or until a fix is deployed + integrators migrated, whichever is **sooner** | Gives integrators time to upgrade the PROGRAM_ID / pause; aligns with Foundation norms |
| High | Up to 90 days | Same |
| Medium | Up to 30 days | Lower blast radius |
| Low / informational | Coordinated, typically immediate after fix | No embargo value |

The embargo clock starts at our acknowledgement. If a third party
(researcher, another project) is about to disclose independently, the
embargo collapses to "disclose as soon as a mitigation exists" - we do
not sit on a publicly-known issue.

## Shared advisory format

When coordinating, all parties publish from a **single shared advisory**
so the ecosystem sees one consistent story rather than divergent partial
accounts. The advisory is drafted by the originating project (us, if the
finding is ours) and cleared with the Foundation before publication.

Advisory skeleton (also the GitHub Security Advisory / RUSTSEC fields):

```
Title:        <one line, no exploit detail before embargo lifts>
Identifier:   GHSA-xxxx / RUSTSEC-YYYY-NNNN / internal MOSAIC-YYYY-NN
Affected:     <projects + version ranges + PROGRAM_IDs>
Severity:     <CVSS or Critical/High/Medium/Low + the soundness/liveness axis>
Root cause:   <syscall vs verifier-logic vs integration> (post-embargo)
Impact:       <what an attacker could do; value at risk>
Mitigation:   <upgrade path; for us, the new PROGRAM_ID + migration guide>
Timeline:     <report -> triage -> fix -> coordinated disclosure dates>
Credit:       <reporter, with consent>
```

For a Mosaic-originated issue we publish as a **GitHub Security Advisory**
on `wienerlabs/mosaic` and, if a crate is affected, a **RUSTSEC** entry;
peers cross-link the same identifier.

## Process (when the trigger fires)

1. **Triage flags ecosystem impact** (Stage 2). Document the shared-cause
   judgement in the incident channel.
2. **Notify the Foundation first** if the root cause is or might be the
   syscall. Let them set the ecosystem-wide coordination cadence.
3. **Notify peers under embargo** using the initial-message template in
   `docs/rollback-playbook.md` § 3, marked embargoed.
4. **Draft the shared advisory**; circulate for technical review +
   Foundation clearance.
5. **Fix + deploy** per `docs/rollback-playbook.md` § 5/6 (patch or
   freeze) and `scripts/deploy-mainnet.sh`.
6. **Publish** the advisory when the embargo lifts (fix deployed +
   integrators migrated, or the timeline expires, or independent
   disclosure forces it).
7. **Postmortem** within 7 days (`docs/rollback-playbook.md` § 8).

## Related

- `SECURITY.md` - reporting policy + the `security-disclosure` link
- `docs/responsible-disclosure-timeline.md` - internal turnaround SLAs
- `docs/rollback-playbook.md` - incident response + the communication tree this feeds
- `docs/bug-bounty.md` - the bounty program that routes in-scope reports here
- Issue [#87](https://github.com/wienerlabs/mosaic/issues/87) - this protocol
- Issue [#66](https://github.com/wienerlabs/mosaic/issues/66) - mainnet ladder
