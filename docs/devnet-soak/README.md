# Devnet soak runs

Soak reports landed here document `mosaic-program` running against a
live Solana cluster for hours-to-days under controlled load. They
are the gating evidence for issue
[#67](https://github.com/wienerlabs/mosaic/issues/67) (mainnet-ladder
prerequisite per [#66](https://github.com/wienerlabs/mosaic/issues/66)).

## Running a soak

Build the harness once:

```bash
cargo build --release -p mosaic-soak --bin soak
```

Write a config JSON. Example for a 24-hour devnet pre-mainnet gate
run:

```json
{
  "rpc_url": "https://api.devnet.solana.com",
  "program_id": "MosA1cVer1f1er11111111111111111111111111111",
  "payer_keypair": "/Volumes/USB-VAULT/devnet-payer.json",
  "fixtures_dir": "tests/fixtures",
  "duration": 86400,
  "submit_interval": 12,
  "tampered_ratio": 0.10,
  "report_path": "docs/devnet-soak/2026-05-13.md",
  "cu_drift_tolerance": 0.10
}
```

Run:

```bash
./target/release/soak --config scripts/soak-config-devnet.json
```

The runner prints a progress line every 60 seconds:

```
mosaic-soak: progress — 412 txs · 371 accepted · 41 rejected · 0 unexpected · 1h23m elapsed
```

At end-of-run it writes the markdown report at the configured
`report_path`. Commit the report to this directory.

## Pass / fail criteria

A soak passes if **all** of:

1. `unexpected_failure == 0` for the full duration
2. Every CU drift alert resolves into "investigate but acceptable"
   (drift > tolerance × 1.5 = automatic fail)
3. The cluster experienced no extended outage (>5 minutes consecutive
   RPC errors → re-run)

Pre-mainnet gate per `AUDIT-CHECKLIST.md` requires at least one
**24-hour** soak with `unexpected_failure == 0` and no critical
drift.

## What gets logged

| Field | Source |
|---|---|
| Per-tx outcome (accept / reject / unexpected) | RPC `send_and_confirm_transaction` result |
| Per-tx CU consumption | Parsed from `Program X consumed N` log line |
| Dispatch slug | Parsed from `Program log: mosaic: dispatch <slug>` line |
| Tx signature for failures | RPC response |
| Logs excerpt for failures | First 200 chars of program log messages |

## Fixture layout

The harness sweeps `fixtures_dir/<system>/<circuit>/canonical/` for
`vk.bin`, `proof.bin`, `public_inputs.bin` triples. Currently
recognised systems:

| Subdirectory | `ProofSystemId` byte | Dispatch slug |
|---|---|---|
| `groth16` | `0x01` | `groth16_bn254` |
| `plonk` | `0x02` | `plonk_kzg_bn254` |

Phase-3 fixtures (HyperPlonk, Halo2, Nova, FRI-STARK) ship the
scaffold-acceptance variants from
`crates/mosaic-{system}/src/verifier.rs::tests` and require their
own bin/proof fixture layout to be standardised before the soak
covers them. Tracked in `AUDIT.md` Phase-3 ladder.

## Schema

`SoakReport` JSON schema is `v1`. Future revisions will bump the
`schema_version` field in the report header.

## Related

- Issue [#67](https://github.com/wienerlabs/mosaic/issues/67) — soak harness epic
- Issue [#69](https://github.com/wienerlabs/mosaic/issues/69) — rollback playbook (consumes soak findings)
- Issue [#85](https://github.com/wienerlabs/mosaic/issues/85) — observability stack
- `scripts/deploy-devnet.sh` — deploys the program this harness drives
- `scripts/deploy-mainnet.sh` — checks that a soak report exists before mainnet deploy
