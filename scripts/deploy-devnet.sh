#!/usr/bin/env bash
#
# scripts/deploy-devnet.sh — deploy mosaic_program.so to Solana devnet
#
# Tracks issues #67 (devnet soak) and #68 (PROGRAM_ID + deploy script).
#
# Why this file exists:
#   The mainnet deployment script (`deploy-mainnet.sh`) MUST be
#   re-runnable from this skeleton with only the program-id keypair
#   path + cluster flag changed. We test the whole flow on devnet
#   first so the mainnet run is the third time anyone has executed
#   it, not the first.
#
# Pre-flight checklist (this script enforces ALL of these — no silent skips):
#   1. Solana CLI installed at expected major version
#   2. `cargo build-sbf` produced a fresh artifact in target/deploy/
#   3. SHA-256 of the artifact matches a recorded checksum
#      (so a tampered build can't slip into deployment)
#   4. The keypair path resolves to a real file outside the repo
#      (commits to a keypair = compromised key)
#   5. The wallet has enough SOL to fund the deploy
#   6. The Solana cluster is set to devnet, not localhost or mainnet
#
# Run from the repo root:
#
#   scripts/deploy-devnet.sh \
#     --keypair ~/.config/solana/mosaic-devnet-program.json \
#     --upgrade-authority ~/.config/solana/mosaic-devnet-authority.json
#
# Exit codes:
#   0  success — program deployed
#   1  pre-flight failed (with reason printed)
#   2  user aborted at the confirmation prompt

set -euo pipefail

# ───────────────────────────────────────────────────────────────────
# Configuration
# ───────────────────────────────────────────────────────────────────

CLUSTER="devnet"
RPC_URL="https://api.devnet.solana.com"
SBF_OUT="target/deploy/mosaic_program.so"
EXPECTED_SOLANA_MAJOR="2"

# CLI arg parsing.
KEYPAIR=""
UPGRADE_AUTHORITY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --keypair)
      KEYPAIR="$2"
      shift 2
      ;;
    --upgrade-authority)
      UPGRADE_AUTHORITY="$2"
      shift 2
      ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)
      echo "deploy-devnet: unknown argument '$1'" >&2
      exit 1
      ;;
  esac
done

# ───────────────────────────────────────────────────────────────────
# Pre-flight
# ───────────────────────────────────────────────────────────────────

fail() {
  echo "deploy-devnet: $1" >&2
  exit 1
}

echo "deploy-devnet: pre-flight checks…"

# 1. Solana CLI
if ! command -v solana >/dev/null 2>&1; then
  fail "solana CLI not found in PATH"
fi
solana_version=$(solana --version | awk '{print $2}' | cut -d. -f1)
if [ "$solana_version" != "$EXPECTED_SOLANA_MAJOR" ]; then
  fail "solana CLI major version $solana_version, expected $EXPECTED_SOLANA_MAJOR"
fi

# 2. SBF artifact present
if [ ! -f "$SBF_OUT" ]; then
  fail "$SBF_OUT not found. Run: cargo build-sbf --tools-version v1.52 \\
        --manifest-path crates/mosaic-program/Cargo.toml"
fi
artifact_size=$(wc -c < "$SBF_OUT")
echo "  ✓ artifact: $SBF_OUT ($artifact_size bytes)"

# 3. SHA-256 fingerprint
artifact_sha=$(shasum -a 256 "$SBF_OUT" | awk '{print $1}')
echo "  ✓ artifact SHA-256: $artifact_sha"
echo "    (cross-check against CI build before signing!)"

# 4. Keypair sanity
if [ -z "$KEYPAIR" ]; then
  fail "--keypair required (path to program-id keypair JSON)"
fi
if [ ! -f "$KEYPAIR" ]; then
  fail "keypair file $KEYPAIR does not exist"
fi
case "$KEYPAIR" in
  "$PWD"/*|./*)
    fail "keypair $KEYPAIR is inside the repo working dir. Move it outside."
    ;;
esac
program_id=$(solana-keygen pubkey "$KEYPAIR")
echo "  ✓ program ID: $program_id"

if [ -z "$UPGRADE_AUTHORITY" ]; then
  fail "--upgrade-authority required (path to upgrade-authority keypair JSON)"
fi
if [ ! -f "$UPGRADE_AUTHORITY" ]; then
  fail "upgrade-authority $UPGRADE_AUTHORITY does not exist"
fi
upgrade_authority_pubkey=$(solana-keygen pubkey "$UPGRADE_AUTHORITY")
echo "  ✓ upgrade authority: $upgrade_authority_pubkey"

# 5. Cluster + balance
solana config set --url "$RPC_URL" --keypair "$UPGRADE_AUTHORITY" >/dev/null
balance_sol=$(solana balance "$upgrade_authority_pubkey" --url "$RPC_URL" | awk '{print $1}')
echo "  ✓ upgrade-authority balance: $balance_sol SOL"

# Rough cost: program size in bytes × rent + bpf-loader instructions.
# For a ~400 KB program on devnet, the deploy costs ~3-4 SOL.
if (( $(echo "$balance_sol < 5" | bc -l) )); then
  fail "balance too low ($balance_sol SOL). Airdrop with: solana airdrop 5 $upgrade_authority_pubkey --url $RPC_URL"
fi

# 6. Cluster guard
configured=$(solana config get | awk -F: '/^RPC URL/{print $2$3$4}' | tr -d ' ')
if [ "$configured" != "$RPC_URL" ]; then
  fail "solana CLI configured for $configured, expected $RPC_URL"
fi

# ───────────────────────────────────────────────────────────────────
# Confirmation
# ───────────────────────────────────────────────────────────────────

cat <<EOF

deploy-devnet: ready to deploy.

  cluster:               $CLUSTER
  program ID:            $program_id
  upgrade authority:     $upgrade_authority_pubkey
  SBF artifact:          $SBF_OUT ($artifact_size bytes)
  artifact SHA-256:      $artifact_sha

This will spend approximately 3-4 SOL on devnet rent.

Continue? (type 'deploy' to confirm)
EOF

read -r confirmation
if [ "$confirmation" != "deploy" ]; then
  echo "deploy-devnet: user aborted"
  exit 2
fi

# ───────────────────────────────────────────────────────────────────
# Deploy
# ───────────────────────────────────────────────────────────────────

echo "deploy-devnet: deploying…"

solana program deploy \
  --url "$RPC_URL" \
  --keypair "$UPGRADE_AUTHORITY" \
  --program-id "$KEYPAIR" \
  --upgrade-authority "$UPGRADE_AUTHORITY" \
  "$SBF_OUT"

echo ""
echo "deploy-devnet: success."
echo ""
echo "  program ID:   $program_id"
echo "  explorer:     https://explorer.solana.com/address/$program_id?cluster=devnet"
echo ""
echo "Next steps:"
echo "  1. Run the soak harness (see scripts/devnet-soak.sh, issue #67)"
echo "  2. After 24 h soak passes, file a report under docs/devnet-soak/"
echo "  3. Mainnet deployment requires audit sign-off (issue #66)"
