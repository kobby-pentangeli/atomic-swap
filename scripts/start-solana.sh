#!/bin/bash
set -e
export PATH="/root/.local/share/solana/install/active_release/bin:$PATH"

echo "[INFO] Starting Solana test validator..."
echo "[INFO] PATH: $PATH"
echo "[INFO] Solana version:"
solana --version

echo "[INFO] Ensuring ledger directory exists..."
mkdir -p /app/.solana-ledger

echo "[INFO] Starting validator without external program dependencies..."
solana-test-validator \
    --rpc-port 8899 \
    --ledger /app/.solana-ledger \
    --quiet \
    --reset

echo "[ERROR] Solana test validator exited unexpectedly"
exit 1