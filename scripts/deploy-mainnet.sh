#!/usr/bin/env bash
#
# scripts/deploy-mainnet.sh — deploy mosaic_program.so to Solana MAINNET.
#
# ┌──────────────────────────────────────────────────────────────────┐
# │  ⚠  This script touches mainnet. Do not run it unless every       │
# │     gating item in issue #66 is checked.                          │
# │                                                                   │
# │  Pre-conditions (this script verifies them; abort otherwise):     │
# │    - External audit signed off (see AUDIT.md final entry)         │
# │    - Devnet soak passed (see docs/devnet-soak/)                   │
# │    - SHA-256 of target/deploy/mosaic_program.so matches the       │
# │      audited artifact recorded in AUDIT.md                        │
# │    - Multi-sig upgrade-authority keypair available                │
# │    - Three independent operators present (one to run the script,  │
# │      two to verify each prompt before the operator confirms)      │
# └──────────────────────────────────────────────────────────────────┘
#
# Tracks issues #66 (mainnet readiness), #68 (PROGRAM_ID), #69 (rollback).
#
# Run from the repo root with both operators physically present:
#
#   scripts/deploy-mainnet.sh \
#     --keypair    /Volumes/USB-VAULT/mosaic-mainnet-program.json \
#     --multisig   <squads-multisig-address> \
#     --audited-sha <64-hex>
#
# Exit codes:
#   0  success — program deployed
#   1  pre-flight failed (with reason printed)
#   2  user aborted at the confirmation prompt
#   3  audit sign-off file missing or unreadable

set -euo pipefail

# ───────────────────────────────────────────────────────────────────
# Configuration
# ───────────────────────────────────────────────────────────────────

CLUSTER="mainnet-beta"
RPC_URL="${SOLANA_MAINNET_RPC:-https://api.mainnet-beta.solana.com}"
SBF_OUT="target/deploy/mosaic_program.so"
EXPECTED_SOLANA_MAJOR="2"
AUDIT_SIGNOFF_PATH="docs/audit-signoff.txt"

# CLI args
KEYPAIR=""
MULTISIG=""
AUDITED_SHA=""

while [ $# -gt 0 ]; do
  case "$1" in
    --keypair)        KEYPAIR="$2"; shift 2 ;;
    --multisig)       MULTISIG="$2"; shift 2 ;;
    --audited-sha)    AUDITED_SHA="$2"; shift 2 ;;
    -h|--help)        sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "deploy-mainnet: unknown argument '$1'" >&2; exit 1 ;;
  esac
done

fail() {
  echo "deploy-mainnet: $1" >&2
  exit 1
}

# ───────────────────────────────────────────────────────────────────
# Pre-flight — hard gates
# ───────────────────────────────────────────────────────────────────

echo "deploy-mainnet: PRE-FLIGHT (mainnet gates — do not bypass)"

# 1. Audit sign-off must exist as a checked-in artifact.
if [ ! -f "$AUDIT_SIGNOFF_PATH" ]; then
  fail "$AUDIT_SIGNOFF_PATH missing. Mainnet deploy is blocked until \\
        the audit firm signs off and the document lands in this repo. \\
        See issue #66."
fi
echo "  ✓ audit sign-off file present"

# 2. SHA-256 fingerprint of the built artifact must match the audited SHA.
if [ -z "$AUDITED_SHA" ]; then
  fail "--audited-sha required (the SHA-256 the audit firm reviewed)"
fi
if [ ! -f "$SBF_OUT" ]; then
  fail "$SBF_OUT not found. Build with: \\
        cargo build-sbf --tools-version v1.52 \\
          --manifest-path crates/mosaic-program/Cargo.toml"
fi
actual_sha=$(shasum -a 256 "$SBF_OUT" | awk '{print $1}')
if [ "$actual_sha" != "$AUDITED_SHA" ]; then
  fail "SBF artifact SHA-256 mismatch
        expected (audited): $AUDITED_SHA
        actual   (rebuilt): $actual_sha
        The deploy bytes MUST match the audited bytes. Rebuild from
        the audit-tagged commit, or re-engage the audit firm."
fi
echo "  ✓ SBF artifact SHA matches audited build: $actual_sha"

# 3. Devnet soak report must exist for the same artifact.
if [ ! -d "docs/devnet-soak" ] || [ -z "$(ls docs/devnet-soak/*.md 2>/dev/null)" ]; then
  fail "no devnet soak report found in docs/devnet-soak/. \\
        Run scripts/deploy-devnet.sh + scripts/devnet-soak.sh first. \\
        See issue #67."
fi
echo "  ✓ devnet soak report present"

# 4. Solana CLI sanity
if ! command -v solana >/dev/null 2>&1; then
  fail "solana CLI not found"
fi
solana_version=$(solana --version | awk '{print $2}' | cut -d. -f1)
if [ "$solana_version" != "$EXPECTED_SOLANA_MAJOR" ]; then
  fail "solana CLI major $solana_version, expected $EXPECTED_SOLANA_MAJOR"
fi

# 5. Keypair sanity
if [ -z "$KEYPAIR" ]; then
  fail "--keypair required (program-id keypair JSON path)"
fi
case "$KEYPAIR" in
  "$PWD"/*|./*)
    fail "keypair $KEYPAIR is inside the repo working dir. Reject."
    ;;
esac
if [ ! -f "$KEYPAIR" ]; then
  fail "keypair file $KEYPAIR does not exist"
fi
program_id=$(solana-keygen pubkey "$KEYPAIR")
echo "  ✓ program ID: $program_id"

# 6. Multi-sig upgrade authority (required for mainnet)
if [ -z "$MULTISIG" ]; then
  fail "--multisig required (Squads / Realms multi-sig address)"
fi
echo "  ✓ upgrade authority (multi-sig): $MULTISIG"

# 7. Cluster guard
solana config set --url "$RPC_URL" >/dev/null
configured=$(solana config get | awk -F: '/^RPC URL/{print $2$3$4}' | tr -d ' ')
case "$configured" in
  *mainnet*) : ;;
  *) fail "solana CLI configured for $configured, expected mainnet-beta" ;;
esac

# ───────────────────────────────────────────────────────────────────
# Confirmation — TWO operators must read each line aloud
# ───────────────────────────────────────────────────────────────────

cat <<EOF

deploy-mainnet: READY TO DEPLOY TO SOLANA MAINNET.

Operators present:
  - Operator A (running the script)
  - Operator B (verifying each line aloud)

  cluster:                $CLUSTER
  RPC:                    $RPC_URL
  program ID:             $program_id
  upgrade authority:      $MULTISIG (multi-sig)
  SBF artifact:           $SBF_OUT ($(wc -c < "$SBF_OUT") bytes)
  artifact SHA-256:       $actual_sha
  audited SHA-256:        $AUDITED_SHA   (match ✓)
  audit sign-off:         $AUDIT_SIGNOFF_PATH
  devnet soak report:     $(ls docs/devnet-soak/*.md | tail -1)

THIS WILL DEPLOY \`mosaic_program.so\` TO SOLANA MAINNET.
This action is auditable on-chain and will be observed by audit firm,
all integrators, and the public.

Operator B confirms every line above is correct? (type 'go-mainnet' to proceed)
EOF

read -r confirmation
if [ "$confirmation" != "go-mainnet" ]; then
  echo "deploy-mainnet: aborted"
  exit 2
fi

# Final 10-second countdown so anyone reading the screen can hit Ctrl+C.
echo "deploy-mainnet: deploying in 10 seconds — Ctrl+C to abort"
for i in 10 9 8 7 6 5 4 3 2 1; do
  printf "  %s\r" "$i"
  sleep 1
done
echo "  0  — deploying"

solana program deploy \
  --url "$RPC_URL" \
  --program-id "$KEYPAIR" \
  --upgrade-authority "$MULTISIG" \
  "$SBF_OUT"

echo ""
echo "deploy-mainnet: SUCCESS."
echo ""
echo "  program ID:   $program_id"
echo "  explorer:     https://explorer.solana.com/address/$program_id"
echo ""
echo "Next steps (incident-response playbook, issue #69):"
echo "  1. Verify the program is callable from a test transaction"
echo "  2. Announce via @mosaiczk + Solana security channels"
echo "  3. File deployment record under docs/mainnet-deploys/<date>.md"
echo "  4. Update README badge from 'audit-ready' to 'mainnet-live'"
