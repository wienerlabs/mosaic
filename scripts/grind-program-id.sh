#!/usr/bin/env bash
#
# scripts/grind-program-id.sh - grind a vanity PROGRAM_ID keypair.
#
# Tracks issue #68 (PROGRAM_ID generation + reproducible deployment).
#
# Why this file exists:
#   The mainnet PROGRAM_ID is permanent and public. A recognizable
#   vanity prefix (e.g. "Mos...") makes it self-evidently the Mosaic
#   program in explorers and integrator configs, and a single canonical
#   grind run produces the one keypair the deploy ceremony uses. This
#   wraps `solana-keygen grind` with the project conventions + safety
#   rails so the runbook is one command, not tribal knowledge.
#
# The grind keypair IS the program-id authority for the initial deploy.
# It is NOT the upgrade authority (that is the 2-of-3 Squads V4 multi-sig
# set at deploy time, per docs/upgrade-authority.md). Treat this keypair
# as sensitive and store it offline.
#
# Usage:
#   scripts/grind-program-id.sh                       # prefix "Mos", out -> ./out/
#   scripts/grind-program-id.sh --prefix Mosaic       # longer = exponentially slower
#   scripts/grind-program-id.sh --out ~/keys          # write keypair there
#   scripts/grind-program-id.sh --ignore-case         # case-insensitive match
#
# base58 has 58 symbols, so each extra fixed prefix character multiplies
# the expected attempts by ~58. "Mos" is seconds; "Mosaic" can be hours.
#
# Exit codes:
#   0  keypair ground + printed
#   1  tooling / argument failure

set -euo pipefail

PREFIX="Mos"
OUT_DIR="out"
IGNORE_CASE=""

fail() { echo "grind-program-id: FAIL - $1" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)      PREFIX="$2"; shift 2 ;;
    --out)         OUT_DIR="$2"; shift 2 ;;
    --ignore-case) IGNORE_CASE="--ignore-case"; shift ;;
    -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

command -v solana-keygen >/dev/null 2>&1 \
  || fail "solana-keygen not on PATH; install the Solana CLI"

# base58 excludes 0 O I l - reject prefixes that can never match.
case "$PREFIX" in
  *[0OIl]*) fail "prefix '$PREFIX' contains a non-base58 character (0, O, I, or l)" ;;
esac

if [ "${#PREFIX}" -ge 5 ] && [ -z "$IGNORE_CASE" ]; then
  echo "grind-program-id: note - prefix '$PREFIX' (${#PREFIX} chars) is"
  echo "  case-sensitive; this can take a long time. Ctrl-C to abort."
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "grind-program-id: grinding a keypair whose pubkey starts with '$PREFIX'..."
solana-keygen grind --starts-with "${PREFIX}:1" $IGNORE_CASE

# solana-keygen writes <PUBKEY>.json into the cwd; surface it.
kp="$(ls -t ./"${PREFIX}"*.json 2>/dev/null | head -1 || true)"
if [ -z "$kp" ]; then
  # --ignore-case may produce a differently-cased filename; fall back to newest json.
  kp="$(ls -t ./*.json 2>/dev/null | head -1 || true)"
fi
[ -n "$kp" ] || fail "no keypair file found after grind"

pubkey="$(solana-keygen pubkey "$kp")"
echo ""
echo "grind-program-id: OK"
echo "  keypair: $OUT_DIR/$(basename "$kp")"
echo "  PROGRAM_ID: $pubkey"
echo ""
echo "Next:"
echo "  1. Move the keypair OFFLINE (it is not safe inside the repo)."
echo "  2. Record PROGRAM_ID in README.md + the deploy runbook."
echo "  3. Deploy with scripts/deploy-devnet.sh --keypair <path> first,"
echo "     then scripts/deploy-mainnet.sh for the real run."
echo "  4. Verify post-deploy with scripts/verify-build.sh --program-id $pubkey"
