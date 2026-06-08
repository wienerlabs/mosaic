# Responsible Disclosure Timeline

This document specifies concrete turnaround commitments for vulnerability
reports submitted per [`SECURITY.md`](../SECURITY.md). It exists so
security researchers know what to expect when they email us, and so
auditors can verify we operate a disciplined disclosure process.

## Stages

### Stage 1 — Acknowledgement (≤ 48 hours)

On receipt of a report at `baturalp@wienerlabs.com`:

- **Automated acknowledgement** of receipt within 1 hour (business days
  when PGP-signed; anytime otherwise).
- **Human acknowledgement** within 48 hours of receipt, including:
  - A tracking identifier assigned to the report.
  - Initial assessment of whether the report is in-scope (per
    [`SECURITY.md`](../SECURITY.md)).
  - Next expected contact date.

### Stage 2 — Triage and reproduction (≤ 5 business days)

Within 5 business days of acknowledgement:

- Reproduction attempt against the affected version.
- Severity classification (Critical / High / Medium / Low / Informational)
  using CVSS 3.1.
- Scope confirmation.
- Assigned owner (engineering lead) and proposed mitigation direction.

If triage cannot complete in 5 business days, we communicate the delay
and a revised ETA with the reporter.

### Stage 3 — Fix development (Critical: ≤ 14 days, High: ≤ 30 days, Medium/Low: ≤ 90 days)

- Private branch for the fix; no public issue until disclosure window
  closes.
- Regression tests added; fuzz corpus updated if applicable.
- Reviewer sign-off (at least one engineer beyond the owner).
- Reporter is invited to review the fix pre-release if they want that
  engagement.

### Stage 4 — Coordinated disclosure (≤ 90 days from acknowledgement)

Default disclosure window is **90 days** from the acknowledgement date.
We may shorten this if:

- The vulnerability is already being actively exploited in the wild.
- A coordinated disclosure date has been agreed with the reporter or
  ecosystem partners.

We may extend this if:

- The fix requires a protocol-version bump coordinated with the Solana
  Foundation or downstream projects.
- The reporter explicitly requests a longer window.
- A specific ecosystem conference or security update cadence makes a
  coordinated later release preferable.

### Stage 5 — Public disclosure

Published artifacts:

- A **CVE** via MITRE (or the Wiener Labs CNA once active).
- A **GitHub Security Advisory** linked from the CVE record.
- A **RustSec advisory** so `cargo-audit` flags it.
- An **[`AUDIT.md`](../AUDIT.md) entry** with fix commit SHA.
- A **release note** in [`CHANGELOG.md`](../CHANGELOG.md).
- **Reporter credit** by name (or handle) unless they prefer anonymity.

## Disclosure scenarios and examples

### Low severity, clean fix
Example: style-lint bypass enabling a noisy log. 90-day window applied
fully; fix lands in the next minor release.

### High severity, ecosystem impact
Example: Groth16 pairing-acceptance divergence between host backend and
on-chain syscall. Coordinated disclosure window aligned with the Solana
Foundation and other affected ZK projects; CVE + RustSec + Solana
Foundation advisory released simultaneously.

### Active exploitation
Example: malicious program calling `mosaic-program` with crafted chunked
session causing rent lock. Window shortened to fix + emergency
release + public advisory as fast as the fix can be validated, with
reporter informed daily.

## When we cannot meet these timelines

If we miss a stage ETA, we communicate the delay proactively with:

- The reporter (always).
- The affected partners, if coordinated disclosure is in progress.

A missed timeline is a disclosable event: if the reporter publishes
before we've shipped a fix because we missed our own commitment, that
is our operational failure, not a breach of disclosure etiquette.

## Hall of fame

Once we receive our first valid report, this section lists reporters who
consented to public credit.

## Reciprocal disclosure to Mosaic

We also disclose *to* upstream projects if our fuzzing or code review
surfaces a bug in a dependency. Relevant upstreams:

- `arkworks` ecosystem (`arkworks/arkworks-algebra`, etc.).
- `solana-bn254`, `solana-program`, and the broader `anza-xyz/solana-sdk`
  family.
- `light-poseidon`.
- `sha2`, `tiny-keccak`.
- The Solana Foundation security team for validator-surface issues.

Our reciprocal disclosure follows the upstream project's own policy,
or this document's 90-day default if the upstream has not published one.
