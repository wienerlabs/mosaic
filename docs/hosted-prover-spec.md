# Mosaic hosted prover — service architecture spec

> Tracks issue [#80](https://github.com/wienerlabs/checks/issues/80).
> Status: design spec. Implementation deferred to post-v1.0.0 (after
> the verifier library + mainnet deploy in [#66](https://github.com/wienerlabs/mosaic/issues/66) are settled).
> This document is the architectural contract: it defines the
> boundary between the library and the optional hosted prover so
> implementation can be commissioned independently from the
> verifier-library audit.

## TL;DR

The Mosaic library is a **verifier**. To use it on chain, developers
still need to (a) compile their circuit, (b) run trusted setup
(or use a universal SRS), (c) run the prover to generate a proof,
and (d) call our verifier program with that proof.

Steps (a)-(c) are CPU-heavy + memory-heavy. A small team or solo
developer often cannot afford the infrastructure to run them
themselves. The hosted prover service is **optional infrastructure
that handles steps (a)-(c)** so the developer only has to integrate
with our SDK at the Solana side.

It is not the core of the project. The verifier library works
without it. But it is a meaningful UX moat and a future revenue
line.

## 1. Why this exists

| Friction | Without hosted prover | With hosted prover |
|---|---|---|
| Circuit compile | Developer runs `circom` / `nargo` / `arkworks` locally + manages versions | Service compiles and caches per-circuit artifacts |
| Trusted setup | Developer either uses a universal SRS or runs their own ceremony | Service offers either: shared SRS (most cases) or audited ceremony (sensitive cases) |
| Prover infra | Dev needs 32-64 GB RAM + multi-hour run for non-trivial circuits | Service runs on autoscaling fleet; dev pays per proof |
| Witness privacy | Dev's machine sees private inputs in plaintext | Same — UNLESS the hosted prover runs in TEE (see § 5) |

Target users:

1. **Solana dapp teams** building a single ZK feature into a larger
   product. They want to ship the feature; they do not want to run
   prover infrastructure.
2. **Wallet integrators** adding zk-features (private balance,
   zk-airdrop, etc.) where prover latency directly impacts user
   conversion.
3. **dApp developer relations efforts** at L1s — both Solana
   Foundation and tier-2 wallets routinely ask "is there a managed
   prover I can point devs to?".

## 2. Service boundary

The hosted prover is the **only** part of Mosaic that holds private
state. The verifier library, the on-chain program, the SDK, and the
fixtures are all entirely public.

The hosted prover never touches the verifier code path. It produces
proofs in the canonical encoding (`mosaic-serde::ArkworksCodec`) and
submits them to the customer's account. The verifier library has
zero knowledge of whether a given proof was produced by the hosted
prover or by some other prover.

This boundary is intentional and audit-critical: if the hosted
prover is compromised, integrators can still verify proofs from any
other prover (Light Protocol's tools, Bonsol, their own
infrastructure) without changing a line of integrator code.

## 3. Service surface (proposed)

The service exposes three endpoints over HTTPS + Bearer
authentication. Body formats are JSON; large binary fields are
base-64 encoded.

### `POST /v1/circuits`

Register a circuit. The body specifies the circuit framework
(`circom` / `noir` / `arkworks`), the source bundle (a tarball
hash), and the proving system (`groth16` / `plonk` /
`hyperplonk` / `halo2` / `nova`). The service compiles the circuit,
runs trusted setup (if needed), and stores the resulting verifying
key. The verifying key is returned in two forms:

- `vk_canonical` — the `mosaic-serde` encoding ready to submit to
  the on-chain verifier program.
- `vk_human` — a JSON dump for the developer's records.

```json
{
  "framework": "circom",
  "source_bundle_uri": "s3://customer-bucket/sudoku-v2.tar.gz",
  "source_bundle_sha256": "abcd...",
  "proof_system": "groth16",
  "trusted_setup_strategy": "shared_universal_srs"
}
```

Trusted-setup strategy options:

- `shared_universal_srs` — KZG-based systems (PLONK, HyperPlonk,
  Halo2) use a public universal SRS. No per-circuit ceremony needed.
- `customer_managed_ceremony` — Groth16 customer brings their own
  Phase-2 contribution.
- `service_managed_ceremony` — service runs a multi-party Phase-2
  ceremony with audited contributors. Adds latency and cost.

### `POST /v1/circuits/<id>/prove`

Submit witness + public inputs; receive a proof.

```json
{
  "public_inputs": [...],
  "private_witness_uri": "tee-mounted:///run/secrets/witness.json",
  "priority": "interactive" | "batch"
}
```

The `private_witness_uri` scheme is one of:

- `inline://` — base-64 JSON, transmitted over TLS to the service.
  Safe only when the customer trusts the service operator.
- `tee-mounted://` — the customer pre-uploads the witness to a TEE
  attestation-validated path. The service decrypts inside the
  enclave. Required for compliance-sensitive customers.
- `client-side://` — the customer's SDK runs the witness-extending
  phase locally and uploads only the extended witness (witness
  values, no private inputs). For circuits where this is feasible
  (small witness, large extension).

The response contains:

```json
{
  "proof_canonical": "<base64 mosaic-serde proof>",
  "public_inputs_canonical": "<base64 mosaic-serde public inputs>",
  "prover_runtime_ms": 8421,
  "prover_attestation": "<TEE quote or null>",
  "service_signature": "<ed25519 sig over the above>"
}
```

### `GET /v1/circuits/<id>/health`

Returns service health for this circuit (last successful proof, SRS
generation, queue length).

## 4. Pricing model

Pricing is per-proof, tiered by circuit constraint count:

| Tier | Constraints | Price per proof | Latency target |
|---|---|---|---|
| Small | ≤ 10 K | $0.01 | < 5 s |
| Medium | ≤ 100 K | $0.10 | < 30 s |
| Large | ≤ 1 M | $1.00 | < 5 min |
| XL | > 1 M | Custom | Custom |

A free tier offers 1000 proofs per month on Small circuits for
developer-relations purposes (hackathon teams, OSS contributors,
Solana Foundation grant recipients).

Customer accounts hold a deposit; proofs deduct from the deposit.
Settlement happens off-chain. Prepaid via standard payment rails
(Stripe + USDC).

A token-incentivised tier may exist post-token-launch (see #81).

## 5. Confidentiality posture

Three tiers, customer-elected at circuit registration:

### Tier C1 — operator-trusted

Witness travels to the service over TLS, lives in service memory
during proving, is wiped after.

- Suitable for: developer integrations where the witness is
  derived from public state (DeFi positions, on-chain sudoku, etc.)
- Customer should not pick this tier if private inputs contain PII
  or balance-revealing info.

### Tier C2 — TEE-isolated

Witness lives only in a TEE enclave. The customer pre-uploads via
the TEE attestation channel; the service operator cannot decrypt
the witness even in memory.

- Suitable for: integrations where the operator is not trusted with
  the witness (private balance, KYC-attribute reveal, etc.).
- Costs an additional fixed surcharge per proof (TEE infra +
  attestation overhead).
- Attestation is recorded in `prover_attestation` field of the
  response so the customer can verify the witness never left the
  enclave.

### Tier C3 — split prover (long-term)

Witness is split into shares; multiple operators each prove a piece;
final aggregation produces the canonical proof. No single operator
ever sees the full witness.

- Suitable for: highest-sensitivity customers (privacy-token
  issuers, identity protocols).
- Not in scope for v1. Reference: arkworks' collaborative-snarks
  research thread.

## 6. Operational posture

| Concern | v1 stance |
|---|---|
| Region | Single US-East region initially. Multi-region post-revenue. |
| SLA | 99.5 % for Small / Medium tiers; 99 % for Large. |
| Status page | status.mosaic.solana / Statuspage.io |
| On-call | Mosaic team (Baturalp / Mehmet / Ferit) rotating |
| Logs | Prover logs retained 30 days; witness data NEVER logged |
| Audit | Service operator infrastructure (not the verifier code) goes through SOC 2 Type II within 12 months of revenue start |

## 7. Open product decisions

These are unresolved as of this spec. Decisions land in
`docs/decisions/` once made.

1. **Witness routing for circom circuits.** Circom witness
   generation is currently a binary that runs the witness extension
   in WASM. The hosted prover can either (a) run that WASM inside
   our prover process, (b) run it as a separate sandboxed sidecar,
   or (c) require the customer's SDK to run it client-side and
   upload only the extended witness. Trade-offs are bandwidth vs.
   trust surface. Likely answer: (c) for Tier C1, (b) for Tier C2.

2. **Universal SRS storage.** KZG universal SRS is ~1 GB at degree
   2^20. Hosting it in S3 with per-request range-fetch is feasible
   but adds latency. Hosting it on local SSD per worker adds cost.
   Likely answer: shard the SRS so each worker holds 2^17 powers
   (~120 MB) and proves only circuits up to that size; route bigger
   circuits to dedicated boxes.

3. **Prover binary supply chain.** The arkworks Rust prover is our
   own; the snarkjs PLONK / circom prover is upstream. Customers
   trust the service operator to run the binary they registered.
   We can either (a) accept this trust assumption, (b) reproduce
   builds and publish SHAs, (c) run the prover in TEE so the
   binary's hash is part of the attestation. Likely answer: (b) at
   v1, (c) at v2.

4. **Sharing the SRS across services.** If Light Protocol or Bonsol
   wants to share our universal SRS hosting (because their needs
   are similar), we should expose it as a separate read-only service
   (e.g. `srs.mosaic.solana`). This becomes infra for the broader
   ZK-on-Solana ecosystem. Tracking for after our own service is
   live.

5. **Failover.** Customer-facing failover plan if the service is
   down: customer falls back to local proving with the SDK. The SDK
   ships the same arkworks binary. This means failover is graceful
   degradation, not total outage. Document the SDK fallback path
   explicitly in the developer docs.

## 8. Build sequencing

This entire service ships AFTER the verifier library reaches
mainnet and has at least one external audit completed (per
[#71](https://github.com/wienerlabs/mosaic/issues/71) +
[#72](https://github.com/wienerlabs/mosaic/issues/72)).

Phasing:

| Phase | Deliverable | Pre-requisite |
|---|---|---|
| H0 | This spec | (this commit) |
| H1 | Service skeleton — auth + circuit registration + Groth16-only prover | Verifier v1.0.0 mainnet |
| H2 | PLONK + HyperPlonk + Halo2 prover backends | H1 + KZG universal SRS hosting |
| H3 | Tier C2 (TEE-isolated) confidentiality | H1 + TEE infrastructure |
| H4 | Multi-region failover | H2 + customer demand |
| H5 | Reference dapp (#82) using the hosted prover | H1 |

H1 is the minimum service. Everything else is incremental and
revenue-driven.

## 9. Related issues + docs

- Issue [#80](https://github.com/wienerlabs/mosaic/issues/80) — this spec
- Issue [#81](https://github.com/wienerlabs/mosaic/issues/81) — tokenomics (relevant for token-tier pricing)
- Issue [#82](https://github.com/wienerlabs/mosaic/issues/82) — reference dapp consumes this service
- Issue [#71](https://github.com/wienerlabs/mosaic/issues/71) + [#72](https://github.com/wienerlabs/mosaic/issues/72) — audit gates the service ships after
- `docs/upgrade-authority.md` — multi-sig posture for the verifier; this service does NOT share that key custody
- `docs/rollback-playbook.md` — incident response for the verifier; the service has its own runbook (TBD)

## 10. Open questions for review

For audit firms (Halborn, IronNode) reviewing this spec:

- Does the C1 / C2 / C3 tier split match the threat models you've
  seen with comparable hosted prover services?
- Is the "service signature over canonical proof + public inputs"
  pattern strong enough as a tamper-evidence layer, or do you
  recommend a trusted-timestamp anchor on chain instead?
- Is the SOC 2 timeline (12 months post-revenue) acceptable, or
  should we commit to it earlier?
- Do you flag any conflicts of interest between operating the
  verifier program (with multi-sig upgrade authority) and operating
  a prover service that produces proofs the verifier accepts?

These questions feed the audit-firm scope handoff at
`AUDIT-CHECKLIST.md`.

---

Status: draft. Will iterate alongside the v1.0.0 audit feedback.
