# Reproducible build + on-chain bytecode verification

> Tracks issues [#66](https://github.com/wienerlabs/mosaic/issues/66)
> (mainnet readiness) and
> [#68](https://github.com/wienerlabs/mosaic/issues/68) (reproducible
> deployment). This is the trust anchor for a verifier that holds value
> on chain: anyone can confirm that the bytecode running at the mainnet
> PROGRAM_ID is exactly what the audited source tag builds, without
> trusting Wiener Labs and without running the deploy ceremony.

## TL;DR

```bash
# Verify the deployed program matches this source tree:
scripts/verify-build.sh --program-id <PROGRAM_ID> --url https://api.mainnet-beta.solana.com

# Verify a fresh build matches a published reference SHA:
scripts/verify-build.sh --expected-sha <64-hex>

# Just print the SHA-256 of the build:
scripts/verify-build.sh
```

Exit `0` = verified, `2` = mismatch (do not trust the deployment).

## The trust property

A Groth16 / multi-system verifier is only as trustworthy as the
bytecode that actually runs. The chain stores the program bytes at the
PROGRAM_ID; the audit firm reviewed a specific source revision. The
property we need is a closed loop:

```
audited source revision  --build-->  .so  --hash-->  SHA-256
                                                         |
deployed PROGRAM_ID  --solana program dump-->  bytes  --hash-->  SHA-256
                                                         |
                                              these must be equal
```

`scripts/verify-build.sh --program-id` closes that loop: it rebuilds
from the working tree, fetches the deployed program with
`solana program dump`, and compares them byte-for-byte (allowing for
the BPF upgradeable loader's trailing zero padding of the program-data
account).

## The pinned toolchain

The canonical build uses **platform-tools `v1.52`**:

```bash
cargo-build-sbf --tools-version v1.52 --manifest-path crates/mosaic-program/Cargo.toml
```

`v1.52` is load-bearing and is the same version the CI `test-sbf` job,
`deploy-mainnet.sh`, and this script all use. It is the version whose
cargo can parse the tree's `edition2024` manifests AND whose sBPF the
`solana-program-test` VM executes correctly (see
[#88](https://github.com/wienerlabs/mosaic/issues/88)). Building with a
different platform-tools version will generally produce a different
SHA-256 and must not be used for a verifiable deployment.

The build emits benign `crypto_common::hazmat::SerializableState`
stack-offset warnings for `[u128; N]` code that is unreachable in the
verifier (pulled in by `blake3 1.8.4` via `solana-program`); the build
still finishes and the program runs correctly. These do not affect the
artifact's behaviour. Residual cleanup is tracked in #88.

## Bit-for-bit determinism across machines

`cargo-build-sbf` can embed environment-specific data (absolute paths in
panic metadata, etc.), so two builds of the same source on **different
machines or different working-directory paths** may differ at the byte
level even though both are honest builds of the same source.

For a deployment whose SHA must reproduce bit-for-bit for any third
party, build inside a pinned container with a fixed working directory.
The pattern (mirroring the canonical Solana reproducible-build flow):

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD":/workdir -w /workdir \
  <pinned-solana-build-image> \
  cargo-build-sbf --tools-version v1.52 \
    --manifest-path crates/mosaic-program/Cargo.toml
```

The exact image tag is pinned in the release checklist at deploy time so
the published reference SHA in the release notes is the container build,
not a local build. Until the program is first deployed, the reference
SHA is whatever the release engineer publishes alongside the tag.

`verify-build.sh` runs the local build by default and prints a reminder
to use the container for cross-machine determinism; the
`--program-id` comparison works regardless, because the verifier
rebuilds in the same environment they verify from.

## Procedure at deploy time

1. Tag the audited revision (`v1.0.0-rc.N`).
2. Build inside the pinned container; record the SHA-256.
3. Publish the SHA-256 in the release notes and in
   `docs/audit-signoff.txt` (the value `deploy-mainnet.sh --audited-sha`
   checks against).
4. Deploy via `scripts/deploy-mainnet.sh` (which rebuilds and asserts
   the SHA matches `--audited-sha` before allowing the deploy).
5. After deploy, run `scripts/verify-build.sh --program-id <PROGRAM_ID>`
   from a clean checkout to confirm the closed loop.
6. Anyone can repeat step 5 at any time.

## Related

- `scripts/verify-build.sh`: this verification tool
- `scripts/deploy-mainnet.sh`: gated deploy (checks `--audited-sha`)
- `scripts/deploy-devnet.sh`: the devnet rehearsal of the same flow
- `docs/upgrade-authority.md`: who can change the deployed bytecode (2-of-3 Squads V4)
- `docs/audit-signoff.txt`: the audited SHA the deploy gate enforces
- Issue [#68](https://github.com/wienerlabs/mosaic/issues/68) - reproducible deployment
