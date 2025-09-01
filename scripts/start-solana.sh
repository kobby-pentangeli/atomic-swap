#!/bin/bash
set -e
export PATH="/root/.local/share/solana/install/active_release/bin:$PATH"

echo "[INFO] Starting Solana test validator..."
echo "[INFO] PATH: $PATH"
echo "[INFO] Solana version:"
solana --version

echo "[INFO] Ensuring ledger directory exists..."
mkdir -p /app/.solana-ledger

METAPLEX_PROGRAM="/app/metaplex.so"
LEDGER_METAPLEX="/app/.solana-ledger/metaplex.so"

if [ ! -f "$METAPLEX_PROGRAM" ]; then
    echo "[INFO] Dumping Metaplex program from mainnet..."
    solana program dump -u m metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s "$METAPLEX_PROGRAM"

    for i in {1..5}; do
        if [ -f "$METAPLEX_PROGRAM" ] && [ -s "$METAPLEX_PROGRAM" ]; then
            echo "[INFO] Program dump successful"
            break
        fi
        echo "[WARN] Attempt $i: Program file not ready, waiting..."
        sleep 2
    done
    
    if [ ! -f "$METAPLEX_PROGRAM" ] || [ ! -s "$METAPLEX_PROGRAM" ]; then
        echo "[ERROR] Failed to dump metaplex.so after retries!"
        exit 1
    fi
fi

echo "[INFO] Copying program to ledger directory..."
cp "$METAPLEX_PROGRAM" "$LEDGER_METAPLEX"

echo "[INFO] Final verification of program file..."
if [ ! -f "$LEDGER_METAPLEX" ]; then
    echo "[ERROR] Program file does not exist: $LEDGER_METAPLEX"
    exit 1
fi

if [ ! -r "$LEDGER_METAPLEX" ]; then
    echo "[ERROR] Program file is not readable: $LEDGER_METAPLEX"
    exit 1
fi

FILE_SIZE=$(stat -c%s "$LEDGER_METAPLEX" 2>/dev/null || echo "0")
if [ "$FILE_SIZE" -eq 0 ]; then
    echo "[ERROR] Program file is empty: $LEDGER_METAPLEX"
    exit 1
fi

echo "[INFO] Program file verified: size=$FILE_SIZE bytes"
ls -la "$LEDGER_METAPLEX"

sync
sleep 1

echo "[INFO] Starting validator..."
solana-test-validator \
    --rpc-port 8899 \
    --ledger /app/.solana-ledger \
    --quiet \
    --bpf-program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s "$LEDGER_METAPLEX" \
    --url https://api.mainnet-beta.solana.com

echo "[ERROR] Solana test validator exited unexpectedly"
exit 1