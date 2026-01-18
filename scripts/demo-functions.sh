# Demo functions for cross-chain atomic swap.
#
# This file is appended to the generated atomic_swap.sh configuration file.
# It expects the following environment variables to be set:
#   - BTC_CLI_CMD: Bitcoin CLI command (environment-specific)
#   - BTC_RPC_URL, BTC_RPC_USER, BTC_RPC_PASSWORD, BTC_NETWORK
#   - ETH_RPC_URL, NFT_CONTRACT_ADDRESS
#   - SOL_RPC_URL, SOL_WS_URL, SOL_PROGRAM_ID
#   - BUYER_BTC_PRIVKEY, BUYER_BTC_ADDRESS, BUYER_BTC_PUBKEY
#   - SELLER_BTC_PRIVKEY, SELLER_BTC_ADDRESS, SELLER_BTC_PUBKEY
#   - BUYER_ETH_PRIVKEY, BUYER_ETH_ADDRESS
#   - SELLER_ETH_PRIVKEY, SELLER_ETH_ADDRESS
#   - BUYER_SOL_KEYPAIR, SELLER_SOL_KEYPAIR
#   - BTC_AMOUNT, ETH_NFT_PRICE, SOL_NFT_PRICE
#   - TOKEN_ID, METADATA_URI, NFT_NAME, NFT_SYMBOL, HTLC_TIMEOUT

# Step 1: Lock bitcoin
lock_btc() {
    echo "Starting Cross-Chain Atomic Swap..."
    echo "Generating initial blocks and funding the buyer address..."

    eval "$BTC_CLI_CMD" generatetoaddress 101 "$BUYER_BTC_ADDRESS"

    RUST_LOG=info ./target/release/client lock-btc \
        --btc-rpc "$BTC_RPC_URL" \
        --btc-user "$BTC_RPC_USER" \
        --btc-pass "$BTC_RPC_PASSWORD" \
        --btc-network "$BTC_NETWORK" \
        --buyer-btc-key "$BUYER_BTC_PRIVKEY" \
        --seller-btc-pubkey "$SELLER_BTC_PUBKEY" \
        --btc-amount "$BTC_AMOUNT" \
        --timeout "$HTLC_TIMEOUT" \
        --secret-output ".swap/secrets/swap.secret"
}

# Step 2: Commit NFT with shared secret
commit_for_mint() {
    local chain="$1"
    local secret_hash="$2"

    if [ -z "$chain" ] || [ -z "$secret_hash" ]; then
        echo "Usage: commit_for_mint --chain <eth|sol> <SECRET_HASH>"
        echo "  or:  commit_for_mint <SECRET_HASH> --chain <eth|sol>"
        return 1
    fi

    # Handle argument order flexibility
    if [ "$chain" = "--chain" ]; then
        chain="$2"
        secret_hash="$3"
    elif [ "$secret_hash" = "--chain" ]; then
        secret_hash="$1"
        chain="$3"
    fi

    case "$chain" in
        "eth")
            RUST_LOG=info ./target/release/client commit-for-mint \
                --chain "eth" \
                --eth-rpc "$ETH_RPC_URL" \
                --seller-eth-key "$SELLER_ETH_PRIVKEY" \
                --nft-contract "$NFT_CONTRACT_ADDRESS" \
                --secret-hash "$secret_hash" \
                --token-id "$TOKEN_ID" \
                --nft-price "$ETH_NFT_PRICE" \
                --buyer-address "$BUYER_ETH_ADDRESS" \
                --metadata-uri "$METADATA_URI"
            ;;
        "sol")
            RUST_LOG=info ./target/release/client commit-for-mint \
                --chain "sol" \
                --sol-rpc "$SOL_RPC_URL" \
                --sol-ws "$SOL_WS_URL" \
                --seller-sol-keypair "$SELLER_SOL_KEYPAIR" \
                --program-id "$SOL_PROGRAM_ID" \
                --name "$NFT_NAME" \
                --symbol "$NFT_SYMBOL" \
                --secret-hash "$secret_hash" \
                --token-id "$TOKEN_ID" \
                --nft-price "$SOL_NFT_PRICE" \
                --metadata-uri "$METADATA_URI"
            ;;
        *)
            echo "Error: Invalid chain '$chain'. Use 'eth' or 'sol'"
            return 1
            ;;
    esac
}

# Step 3: Mint the NFT with shared secret
mint_with_secret() {
    local chain=""
    local secret=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --chain)
                chain="$2"
                shift 2
                ;;
            --secret-file)
                local secret_file="$2"
                if [ -z "$secret_file" ]; then
                    echo "Error: --secret-file requires a path argument"
                    return 1
                fi
                if [ ! -f "$secret_file" ]; then
                    echo "Error: Secret file not found: $secret_file"
                    return 1
                fi
                secret=$(grep "^SECRET=" "$secret_file" | cut -d'=' -f2)
                shift 2
                ;;
            *)
                # Positional argument (secret or chain)
                if [ -z "$secret" ]; then
                    secret="$1"
                elif [ -z "$chain" ]; then
                    chain="$1"
                fi
                shift
                ;;
        esac
    done

    if [ -z "$chain" ] || [ -z "$secret" ]; then
        echo "Usage: mint_with_secret --chain <eth|sol> <SECRET>"
        echo "  or:  mint_with_secret <SECRET> --chain <eth|sol>"
        echo "  or:  mint_with_secret --chain <eth|sol> --secret-file .swap/secrets/swap.secret"
        return 1
    fi

    case "$chain" in
        "eth")
            RUST_LOG=info ./target/release/client mint-with-secret \
                --chain "eth" \
                --eth-rpc "$ETH_RPC_URL" \
                --buyer-eth-key "$BUYER_ETH_PRIVKEY" \
                --nft-contract "$NFT_CONTRACT_ADDRESS" \
                --secret "$secret" \
                --token-id "$TOKEN_ID"
            ;;
        "sol")
            RUST_LOG=info ./target/release/client mint-with-secret \
                --chain "sol" \
                --sol-rpc "$SOL_RPC_URL" \
                --sol-ws "$SOL_WS_URL" \
                --buyer-sol-keypair "$BUYER_SOL_KEYPAIR" \
                --program-id "$SOL_PROGRAM_ID" \
                --secret "$secret" \
                --token-id "$TOKEN_ID"
            ;;
        *)
            echo "Error: Invalid chain '$chain'. Use 'eth' or 'sol'"
            return 1
            ;;
    esac
}

# Step 4: Claim bitcoin after secret reveal
claim_btc() {
    local secret=""
    local secret_hash=""
    local lock_txid=""

    # Check if --secret-file is provided
    if [ "$1" = "--secret-file" ]; then
        local secret_file="$2"
        if [ -z "$secret_file" ]; then
            echo "Error: --secret-file requires a path argument"
            return 1
        fi
        if [ ! -f "$secret_file" ]; then
            echo "Error: Secret file not found: $secret_file"
            return 1
        fi
        # Parse the secret file (format: KEY=VALUE per line)
        secret=$(grep "^SECRET=" "$secret_file" | cut -d'=' -f2)
        secret_hash=$(grep "^SECRET_HASH=" "$secret_file" | cut -d'=' -f2)
        lock_txid=$(grep "^LOCK_TXID=" "$secret_file" | cut -d'=' -f2)
    else
        # Positional arguments
        secret="$1"
        secret_hash="$2"
        lock_txid="$3"
    fi

    if [ -z "$secret" ] || [ -z "$secret_hash" ] || [ -z "$lock_txid" ]; then
        echo "Usage: claim_btc <SECRET> <SECRET_HASH> <LOCK_TXID>"
        echo "  or:  claim_btc --secret-file .swap/secrets/swap.secret"
        return 1
    fi

    RUST_LOG=info ./target/release/client claim-btc \
        --btc-rpc "$BTC_RPC_URL" \
        --btc-user "$BTC_RPC_USER" \
        --btc-pass "$BTC_RPC_PASSWORD" \
        --btc-network "$BTC_NETWORK" \
        --seller-btc-key "$SELLER_BTC_PRIVKEY" \
        --buyer-btc-pubkey "$BUYER_BTC_PUBKEY" \
        --secret "$secret" \
        --secret-hash "$secret_hash" \
        --lock-txid "$lock_txid" \
        --lock-vout 0 \
        --timeout "$HTLC_TIMEOUT"
}

# Cancel an expired or unwanted commitment
cancel_commit() {
    local chain=""
    local token_id=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --chain)
                chain="$2"
                shift 2
                ;;
            --token-id)
                token_id="$2"
                shift 2
                ;;
            *)
                # Positional argument
                if [ -z "$chain" ]; then
                    chain="$1"
                elif [ -z "$token_id" ]; then
                    token_id="$1"
                fi
                shift
                ;;
        esac
    done

    # Default token_id if not provided
    if [ -z "$token_id" ]; then
        token_id="$TOKEN_ID"
    fi

    if [ -z "$chain" ]; then
        echo "Usage: cancel_commit --chain <eth|sol> [--token-id <ID>]"
        echo "  or:  cancel_commit <eth|sol> [<TOKEN_ID>]"
        echo ""
        echo "Cancels an expired commitment. Only the seller (committer) can cancel."
        echo "If --token-id is not specified, defaults to \$TOKEN_ID."
        return 1
    fi

    case "$chain" in
        "eth")
            RUST_LOG=info ./target/release/client cancel-commit \
                --chain "eth" \
                --eth-rpc "$ETH_RPC_URL" \
                --caller-eth-key "$SELLER_ETH_PRIVKEY" \
                --nft-contract "$NFT_CONTRACT_ADDRESS" \
                --token-id "$token_id"
            ;;
        "sol")
            RUST_LOG=info ./target/release/client cancel-commit \
                --chain "sol" \
                --sol-rpc "$SOL_RPC_URL" \
                --sol-ws "$SOL_WS_URL" \
                --caller-sol-keypair "$SELLER_SOL_KEYPAIR" \
                --program-id "$SOL_PROGRAM_ID" \
                --token-id "$token_id"
            ;;
        *)
            echo "Error: Invalid chain '$chain'. Use 'eth' or 'sol'"
            return 1
            ;;
    esac
}

# Refund Bitcoin from HTLC after timeout expiry (buyer only)
refund_btc() {
    local secret_file=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --secret-file)
                secret_file="$2"
                shift 2
                ;;
            *)
                # Positional argument (secret file path)
                if [ -z "$secret_file" ]; then
                    secret_file="$1"
                fi
                shift
                ;;
        esac
    done

    # Default to standard secret file location
    if [ -z "$secret_file" ]; then
        secret_file=".swap/secrets/swap.secret"
    fi

    if [ ! -f "$secret_file" ]; then
        echo "Error: Secret file not found: $secret_file"
        echo ""
        echo "Usage: refund_btc [--secret-file <PATH>]"
        echo ""
        echo "Refunds locked Bitcoin to the buyer after the HTLC timeout expires."
        echo "Requires the secret file generated during lock_btc."
        echo ""
        echo "If --secret-file is not specified, defaults to .swap/secrets/swap.secret"
        return 1
    fi

    RUST_LOG=info ./target/release/client refund-btc \
        --btc-rpc "$BTC_RPC_URL" \
        --btc-user "$BTC_RPC_USER" \
        --btc-pass "$BTC_RPC_PASSWORD" \
        --btc-network "$BTC_NETWORK" \
        --buyer-btc-key "$BUYER_BTC_PRIVKEY" \
        --seller-btc-pubkey "$SELLER_BTC_PUBKEY" \
        --secret-file "$secret_file" \
        --lock-vout 0 \
        --timeout "$HTLC_TIMEOUT"
}

# Graceful shutdown (local only)
stop_services() {
    echo "Stopping all demo services..."

    # Stop Bitcoin
    if eval "$BTC_CLI_CMD" stop 2>/dev/null; then
        echo "Bitcoin stopped"
    else
        echo "Bitcoin was not running or failed to stop gracefully"
        pkill -f "bitcoind.*regtest" 2>/dev/null || true
    fi

    # Stop Hardhat
    if [ -f ".swap/hardhat.pid" ]; then
        local hardhat_pid=$(cat ".swap/hardhat.pid")
        if ps -p "$hardhat_pid" > /dev/null 2>&1; then
            kill "$hardhat_pid" && echo "Hardhat stopped"
        fi
        rm -f ".swap/hardhat.pid"
    fi

    # Stop Solana
    if [ -f ".swap/solana.pid" ]; then
        local solana_pid=$(cat ".swap/solana.pid")
        if ps -p "$solana_pid" > /dev/null 2>&1; then
            kill "$solana_pid" && echo "Solana test validator stopped"
        fi
        rm -f ".swap/solana.pid"
    else
        pkill -f "solana-test-validator" 2>/dev/null && echo "Solana test validator stopped" || true
    fi

    echo "All services stopped"
}

print_demo_help() {
    echo "Demo configuration loaded!"
    echo "Available commands:"
    echo "  lock_btc           - Lock up Bitcoin in the HTLC"
    echo "  commit_for_mint    - Seller commits to mint (requires secret hash)"
    echo "  mint_with_secret   - Buyer mints the NFT with secret reveal"
    echo "  claim_btc          - Seller claims Bitcoin (requires secret, hash, txid)"
    echo "  cancel_commit      - Cancel an expired commitment (seller only)"
    echo "  refund_btc         - Reclaim Bitcoin after timeout expiry (buyer only)"
    echo "  stop_services      - Stop all running services"
    echo ""
    echo "Bitcoin RPC: $BTC_RPC_URL"
    echo "Ethereum RPC: $ETH_RPC_URL"
    echo "NFT Contract: $NFT_CONTRACT_ADDRESS"
    echo ""
    echo "Secrets directory: .swap/secrets/"
    echo "Keypairs directory: .swap/keypairs/"
}

# Display help when sourced
print_demo_help
