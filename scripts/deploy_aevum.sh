#!/usr/bin/env bash
set -euo pipefail

# Turnkey deploy script for QDay Aevum Testnet (Chain ID 44005, Shanghai EVM)
# Requires PRIVATE_KEY in env (never hardcode keys). Pass --dry-run to simulate without broadcasting.

RPC_URL="${RPC_URL:-https://rpc-test.qday.info}"
FORGE_BIN="${FORGE_BIN:-forge}"
DRY_RUN="${1:-}"

if [ -z "${PRIVATE_KEY:-}" ]; then
    echo "ERROR: PRIVATE_KEY env var is required"
    exit 1
fi

cd "$(dirname "$0")/../contracts"

if [ "$DRY_RUN" = "--dry-run" ]; then
    echo "[deploy_aevum] Running dry-run simulation against $RPC_URL (Chain 44005)..."
    "$FORGE_BIN" script script/Deploy.s.sol:DeployPqcInvoiceEscrow --rpc-url "$RPC_URL"
else
    echo "[deploy_aevum] Broadcasting to $RPC_URL (Chain 44005)..."
    "$FORGE_BIN" script script/Deploy.s.sol:DeployPqcInvoiceEscrow --rpc-url "$RPC_URL" --broadcast
fi
