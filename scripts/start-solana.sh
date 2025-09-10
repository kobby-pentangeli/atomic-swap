#!/bin/bash
set -e
export PATH="/root/.local/share/solana/install/active_release/bin:$PATH"

echo "[INFO] Starting Solana test validator..."
echo "[INFO] PATH: $PATH"
echo "[INFO] Solana version:"
solana --version

echo "[INFO] Ensuring ledger directory exists..."
mkdir -p /app/.solana-ledger

# Metaplex Token Metadata Program ID
METAPLEX_PROGRAM_ID="metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
METAPLEX_PROGRAM="/app/metaplex.so"

# Download Metaplex program if not exists or is empty
if [ ! -f "$METAPLEX_PROGRAM" ] || [ ! -s "$METAPLEX_PROGRAM" ]; then
    echo "[INFO] Downloading Metaplex Token Metadata program from mainnet..."
    
    # Try with timeout to avoid hanging
    if timeout 60 solana program dump -u mainnet-beta "$METAPLEX_PROGRAM_ID" "$METAPLEX_PROGRAM"; then
        echo "[INFO] Metaplex program downloaded successfully"
    else
        echo "[WARN] Failed to download from mainnet-beta, trying with short URL..."
        if timeout 60 solana program dump -u m "$METAPLEX_PROGRAM_ID" "$METAPLEX_PROGRAM"; then
            echo "[INFO] Metaplex program downloaded successfully"
        else
            echo "[ERROR] Failed to download Metaplex program. Check network connectivity."
            exit 1
        fi
    fi
    
    # Verify download
    if [ ! -f "$METAPLEX_PROGRAM" ] || [ ! -s "$METAPLEX_PROGRAM" ]; then
        echo "[ERROR] Metaplex program file is missing or empty after download"
        exit 1
    fi
fi

# Get file size for verification
PROGRAM_SIZE=$(stat -c%s "$METAPLEX_PROGRAM" 2>/dev/null || stat -f%z "$METAPLEX_PROGRAM" 2>/dev/null || echo "0")
echo "[INFO] Metaplex program size: ${PROGRAM_SIZE} bytes"

if [ "$PROGRAM_SIZE" -eq 0 ]; then
    echo "[ERROR] Metaplex program file is empty"
    exit 1
fi

echo "[INFO] Starting Solana test validator with Metaplex program..."
solana-test-validator \
    --rpc-port 8899 \
    --ledger /app/.solana-ledger \
    --bpf-program "$METAPLEX_PROGRAM_ID" "$METAPLEX_PROGRAM" \
    --reset \
    --quiet

echo "[ERROR] Solana test validator exited unexpectedly"
exit 1