#!/usr/bin/env bash
#
# scripts/verify-build.sh - independently verify the Mosaic on-chain
# bytecode matches this source tree.
#
# Tracks issues #66 (mainnet readiness), #68 (reproducible deployment).
#
# Why this file exists:
#   For a trustless on-chain verifier, the property that matters is:
#   "the bytecode running at PROGRAM_ID is exactly what this audited
#   source tag builds." An auditor, integrator, or user must be able to
#   confirm that WITHOUT running the deploy ceremony or trusting us.
#   This script builds the program with the pinned toolchain, hashes the
#   artifact, and (optionally) compares it to a published reference SHA
#   or to the program data fetched live from a cluster.
#
# Modes (combine freely):
#   default              build + print the SHA-256 of the artifact
#   --expected-sha <hex> assert the freshly built artifact matches a
#                        published reference SHA (reproducibility check)
#   --program-id <pk>    dump the deployed program from --url and assert
#                        its bytecode matches the freshly built artifact
#                        (on-chain-matches-source check)
#   --url <rpc>          cluster RPC for --program-id (default mainnet)
#   --skip-build         hash/compare an already-built artifact in place
#
# Run from the repo root:
#
#   scripts/verify-build.sh
#   scripts/verify-build.sh --expected-sha <64-hex>
#   scripts/verify-build.sh --program-id <PROGRAM_ID> --url https://api.devnet.solana.com
#
# Exit codes:
#   0  verified (or SHA printed)
#   1  build / tooling failure
#   2  verification mismatch (bytecode does NOT match)

set -euo pipefail

SBF_OUT="target/deploy/mosaic_program.so"
MANIFEST="crates/mosaic-program/Cargo.toml"
TOOLS_VERSION="v1.52"
EXPECTED_SHA=""
PROGRAM_ID=""
RPC_URL="https://api.mainnet-beta.solana.com"
SKIP_BUILD="false"

fail() {
  echo "verify-build: FAIL - $1" >&2
  exit "${2:-1}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --expected-sha) EXPECTED_SHA="$2"; shift 2 ;;
    --program-id)   PROGRAM_ID="$2"; shift 2 ;;
    --url)          RPC_URL="$2"; shift 2 ;;
    --skip-build)   SKIP_BUILD="true"; shift ;;
    -h|--help)      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

if [ ! -f "$MANIFEST" ]; then
  fail "run from the repo root (no $MANIFEST here)"
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ───────────────────────────────────────────────────────────────────
# 1. Build the canonical artifact with the pinned toolchain.
# ───────────────────────────────────────────────────────────────────
if [ "$SKIP_BUILD" = "false" ]; then
  echo "verify-build: building $SBF_OUT with platform-tools $TOOLS_VERSION"
  echo "  (for bit-for-bit determinism across machines, run this inside"
  echo "   the pinned Docker image - see docs/reproducible-build.md)"
  if ! command -v cargo-build-sbf >/dev/null 2>&1; then
    fail "cargo-build-sbf not on PATH; install the Solana CLI / platform tools"
  fi
  cargo-build-sbf --tools-version "$TOOLS_VERSION" --manifest-path "$MANIFEST" \
    || fail "cargo build-sbf failed"
fi

if [ ! -f "$SBF_OUT" ]; then
  fail "artifact $SBF_OUT not present"
fi

BUILT_SHA="$(sha256_of "$SBF_OUT")"
BUILT_LEN="$(wc -c < "$SBF_OUT" | tr -d ' ')"
echo ""
echo "verify-build: artifact"
echo "  path:   $SBF_OUT"
echo "  size:   $BUILT_LEN bytes"
echo "  sha256: $BUILT_SHA"
echo ""

STATUS_OK="true"

# ───────────────────────────────────────────────────────────────────
# 2. Reproducibility check vs a published reference SHA.
# ───────────────────────────────────────────────────────────────────
if [ -n "$EXPECTED_SHA" ]; then
  if [ "$BUILT_SHA" = "$EXPECTED_SHA" ]; then
    echo "  ✓ matches published reference SHA"
  else
    echo "  ✗ does NOT match published reference SHA"
    echo "      expected: $EXPECTED_SHA"
    echo "      built:    $BUILT_SHA"
    STATUS_OK="false"
  fi
fi

# ───────────────────────────────────────────────────────────────────
# 3. On-chain-matches-source check.
#    `solana program dump` writes the deployed program bytes; the BPF
#    upgradeable loader may zero-pad the program-data account beyond the
#    ELF, so we compare the built artifact against the dump's leading
#    bytes and require the remainder to be zero padding.
# ───────────────────────────────────────────────────────────────────
if [ -n "$PROGRAM_ID" ]; then
  command -v solana >/dev/null 2>&1 || fail "solana CLI required for --program-id"
  DUMP="$(mktemp -t mosaic-dump.XXXXXX.so)"
  trap 'rm -f "$DUMP"' EXIT
  echo "  fetching deployed program $PROGRAM_ID from $RPC_URL"
  solana program dump "$PROGRAM_ID" "$DUMP" --url "$RPC_URL" >/dev/null \
    || fail "solana program dump failed (wrong program-id / cluster?)"
  DUMP_LEN="$(wc -c < "$DUMP" | tr -d ' ')"

  if [ "$DUMP_LEN" -lt "$BUILT_LEN" ]; then
    echo "  ✗ on-chain program ($DUMP_LEN B) is smaller than the build ($BUILT_LEN B)"
    STATUS_OK="false"
  else
    # Compare the leading BUILT_LEN bytes byte-for-byte.
    head -c "$BUILT_LEN" "$DUMP" > "${DUMP}.head"
    if cmp -s "$SBF_OUT" "${DUMP}.head"; then
      # Require the trailing bytes (if any) to be zero padding.
      pad_nonzero=0
      if [ "$DUMP_LEN" -gt "$BUILT_LEN" ]; then
        pad_nonzero="$(tail -c "$((DUMP_LEN - BUILT_LEN))" "$DUMP" | tr -d '\000' | wc -c | tr -d ' ')"
      fi
      if [ "$pad_nonzero" -eq 0 ]; then
        echo "  ✓ on-chain bytecode matches the freshly built artifact"
        echo "      (deployed $DUMP_LEN B = $BUILT_LEN B program + $((DUMP_LEN - BUILT_LEN)) B zero padding)"
      else
        echo "  ✗ on-chain program has $pad_nonzero non-zero trailing bytes past the ELF"
        STATUS_OK="false"
      fi
    else
      echo "  ✗ on-chain bytecode does NOT match the freshly built artifact"
      STATUS_OK="false"
    fi
    rm -f "${DUMP}.head"
  fi
fi

echo ""
if [ "$STATUS_OK" = "true" ]; then
  echo "verify-build: OK"
  exit 0
else
  echo "verify-build: MISMATCH - do not trust this deployment"
  exit 2
fi
