#!/bin/bash

generate_test_accounts() {
    log "Generating test accounts and keys..."
    log "Generating Bitcoin test accounts..."

    # Build the xpriv derivation binary if needed
    if [ ! -f "$SETUP_DIR/target/release/derive_privkey" ]; then
        log "Building key derivation helper..."
        cargo build --release --bin derive_privkey
    fi

    local buyer_btc_address seller_btc_address
    local buyer_btc_privkey seller_btc_privkey
    local buyer_btc_pubkey seller_btc_pubkey

    if buyer_btc_address=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnewaddress "buyer" 2>/dev/null); then
        if addr_info=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getaddressinfo "$buyer_btc_address" 2>/dev/null); then
            buyer_btc_pubkey=$(echo "$addr_info" | jq -r .pubkey)
            
            # Get derivation path
            local hdkeypath=$(echo "$addr_info" | jq -r .hdkeypath)
            
            # Get the wallet's master private key directly
            local wallet_info=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getwalletinfo)
            local wallet_name=$(echo "$wallet_info" | jq -r .walletname)
            
            # Get descriptors with private keys
            local descriptors=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" listdescriptors true)
            
            local path_prefix=""
            if [[ "$hdkeypath" =~ m/84h/1h/0h/0/ ]]; then
                path_prefix="84h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/49h/1h/0h/0/ ]]; then
                path_prefix="49h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/44h/1h/0h/0/ ]]; then
                path_prefix="44h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/86h/1h/0h/0/ ]]; then
                path_prefix="86h/1h/0h/0"
            fi

            local desc=$(echo "$descriptors" | jq -r --arg prefix "$path_prefix" '.descriptors[] | select(.desc | contains($prefix)) | select(.desc | test("/0/\\*")) | .desc' | head -1)
            
            if [[ -n "$desc" ]]; then
                local base_xpriv=""
                
                base_xpriv=$(echo "$desc" | sed -n 's/.*(\[.*\]\([a-zA-Z0-9]*\)\/.*/\1/p')
                
                if [[ -z "$base_xpriv" ]]; then
                    base_xpriv=$(echo "$desc" | grep -oE 'tprv[a-zA-Z0-9]+')
                fi
                
                if [[ -z "$base_xprv" ]]; then
                    base_xprv=$(echo "$desc" | sed -n 's/.*]\([^/]*\)\/.*/\1/p')
                fi
                
                if [[ -n "$base_xpriv" && -n "$hdkeypath" ]]; then
                    if buyer_btc_privkey=$("$SETUP_DIR/target/release/derive_privkey" "$base_xpriv" "$hdkeypath" 2>&1); then
                        echo "Buyer private key derived successfully"
                    else
                        error "Failed to derive buyer private key"
                    fi
                else
                    error "Failed to extract xpriv ($base_xpriv) or hdkeypath ($hdkeypath) for buyer"
                fi
            else
                error "Failed to find appropriate descriptor for buyer"
            fi
        else
            error "Failed to get buyer address info"
        fi
    else
        error "Failed to generate buyer Bitcoin address"
    fi

    if seller_btc_address=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnewaddress "seller" 2>/dev/null); then
        if addr_info=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getaddressinfo "$seller_btc_address" 2>/dev/null); then
            seller_btc_pubkey=$(echo "$addr_info" | jq -r .pubkey)
            
            local hdkeypath=$(echo "$addr_info" | jq -r .hdkeypath)
            
            local descriptors=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" listdescriptors true)
            
            local path_prefix=""
            if [[ "$hdkeypath" =~ m/84h/1h/0h/0/ ]]; then
                path_prefix="84h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/49h/1h/0h/0/ ]]; then
                path_prefix="49h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/44h/1h/0h/0/ ]]; then
                path_prefix="44h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/86h/1h/0h/0/ ]]; then
                path_prefix="86h/1h/0h/0"
            fi
            
            local desc=$(echo "$descriptors" | jq -r --arg prefix "$path_prefix" '.descriptors[] | select(.desc | contains($prefix)) | select(.desc | test("/0/\\*")) | .desc' | head -1)
            
            if [[ -n "$desc" ]]; then
                local base_xpriv=""
                base_xpriv=$(echo "$desc" | grep -oE 'tprv[a-zA-Z0-9]+')
                
                if [[ -z "$base_xpriv" ]]; then
                    base_xpriv=$(echo "$desc" | sed -n 's/.*(\([^)]*\)).*/\1/p' | grep -oE 'tprv[a-zA-Z0-9]+')
                fi
                
                if [[ -n "$base_xpriv" && -n "$hdkeypath" ]]; then
                    if seller_btc_privkey=$("$SETUP_DIR/target/release/derive_privkey" "$base_xpriv" "$hdkeypath" 2>&1); then
                        echo "Seller private key derived successfully"
                    else
                        error "Failed to derive seller private key"
                    fi
                else
                    error "Failed to extract xpriv ($base_xpriv) or hdkeypath ($hdkeypath) for seller"
                fi
            else
                error "Failed to find appropriate descriptor for seller"
            fi
        else
            error "Failed to get seller address info"
        fi
    else
        error "Failed to generate seller Bitcoin address"
    fi
    
    log "Funding buyer Bitcoin address..."
    bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" generatetoaddress 5 "$buyer_btc_address" > /dev/null
    bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" generatetoaddress 1 "$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnewaddress)" > /dev/null
    
    local buyer_eth_privkey="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    local buyer_eth_address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    local seller_eth_privkey="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    local seller_eth_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    
    local contract_address="N/A"
    if [ -f "$SETUP_DIR/agent/eth/contract_address.txt" ]; then
        contract_address=$(cat "$SETUP_DIR/agent/eth/contract_address.txt")
    fi
    
    log "Creating demo configuration..."

    local program_id="11111111111111111111111111111112"
    if [ -f "$SETUP_DIR/agent/sol/program_id.txt" ]; then
        program_id=$(cat "$SETUP_DIR/agent/sol/program_id.txt")
    elif [ -f "$SETUP_DIR/program_id.txt" ]; then
        program_id=$(cat "$SETUP_DIR/program_id.txt")
    fi

    cat > "$SETUP_DIR/atomic_swap.sh" << EOF
#!/bin/bash

# Cross-Chain Secret Mint Demo Configuration
# Generated by setup.sh on $(date)

# Bitcoin Configuration
export BTC_RPC_URL="http://localhost:18443"
export BTC_RPC_USER="user"
export BTC_RPC_PASSWORD="password"
export BTC_NETWORK="regtest"
export BTC_DATA_DIR="$BITCOIN_DATA_DIR"

# Ethereum Configuration  
export ETH_RPC_URL="http://localhost:8545"
export NFT_CONTRACT_ADDRESS="$contract_address"

# Solana Configuration
export SOL_RPC_URL="http://localhost:8899"
export SOL_WS_URL="ws://localhost:8900"
export SOL_PROGRAM_ID="$program_id"

# Buyer Keys
export BUYER_BTC_PRIVKEY="$buyer_btc_privkey"
export BUYER_BTC_ADDRESS="$buyer_btc_address"
export BUYER_BTC_PUBKEY="$buyer_btc_pubkey"
export BUYER_ETH_PRIVKEY="$buyer_eth_privkey"
export BUYER_ETH_ADDRESS="$buyer_eth_address"
export BUYER_SOL_KEYPAIR="buyer-keypair.json"

# Seller Keys
export SELLER_BTC_PRIVKEY="$seller_btc_privkey"
export SELLER_BTC_PUBKEY="$seller_btc_pubkey"
export SELLER_BTC_ADDRESS="$seller_btc_address"
export SELLER_ETH_PRIVKEY="$seller_eth_privkey"
export SELLER_ETH_ADDRESS="$seller_eth_address"
export SELLER_SOL_KEYPAIR="seller-keypair.json"

# Demo Parameters
export BTC_AMOUNT="100000"  # 0.001 BTC in satoshis
export ETH_NFT_PRICE="1000000000000000000"  # 1 ETH in wei
export SOL_NFT_PRICE="1000000000"  # 1 SOL in lamports
export TOKEN_ID="1"
export METADATA_URI="https://example.com/nft/1.json"
export NFT_NAME="Demo NFT"
export NFT_SYMBOL="DEMO"
export HTLC_TIMEOUT="144"  # blocks

# Step 1: Lock bitcoin
lock_btc() {
    echo "Starting Cross-Chain Atomic Swap..."
    echo "Generating initial blocks and funding the buyer address..."

    bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" generatetoaddress 101 "$buyer_btc_address"
    
    RUST_LOG=info ./target/release/client lock-btc \\
        --btc-rpc "\$BTC_RPC_URL" \\
        --btc-user "\$BTC_RPC_USER" \\
        --btc-pass "\$BTC_RPC_PASSWORD" \\
        --btc-network "\$BTC_NETWORK" \\
        --buyer-btc-key "\$BUYER_BTC_PRIVKEY" \\
        --seller-btc-pubkey "\$SELLER_BTC_PUBKEY" \\
        --btc-amount "\$BTC_AMOUNT" \\
        --timeout "\$HTLC_TIMEOUT"
}

# Commit NFT with shared secret
commit_for_mint() {
    local chain="\$1"
    local secret_hash="\$2"
    
    if [ -z "\$chain" ] || [ -z "\$secret_hash" ]; then
        echo "Usage: commit_for_mint --chain <eth|sol> <SECRET_HASH>"
        echo "  or:  commit_for_mint <SECRET_HASH> --chain <eth|sol>"
        return 1
    fi
    
    # Handle argument order flexibility
    if [ "\$chain" = "--chain" ]; then
        chain="\$2"
        secret_hash="\$3"
    elif [ "\$secret_hash" = "--chain" ]; then
        secret_hash="\$1"
        chain="\$3"
    fi
    
    case "\$chain" in
        "eth")
            RUST_LOG=info ./target/release/client commit-for-mint \\
                --chain "eth" \\
                --eth-rpc "\$ETH_RPC_URL" \\
                --seller-eth-key "\$SELLER_ETH_PRIVKEY" \\
                --nft-contract "\$NFT_CONTRACT_ADDRESS" \\
                --secret-hash "\$secret_hash" \\
                --token-id "\$TOKEN_ID" \\
                --nft-price "\$ETH_NFT_PRICE" \\
                --buyer-address "\$BUYER_ETH_ADDRESS" \\
                --metadata-uri "\$METADATA_URI"
            ;;
        "sol")
            RUST_LOG=info ./target/release/client commit-for-mint \\
                --chain "sol" \\
                --sol-rpc "\$SOL_RPC_URL" \\
                --sol-ws "\$SOL_WS_URL" \\
                --seller-sol-keypair "\$SELLER_SOL_KEYPAIR" \\
                --program-id "\$SOL_PROGRAM_ID" \\
                --name "\$NFT_NAME" \\
                --symbol "\$NFT_SYMBOL" \\
                --secret-hash "\$secret_hash" \\
                --token-id "\$TOKEN_ID" \\
                --nft-price "\$SOL_NFT_PRICE" \\
                --metadata-uri "\$METADATA_URI"
            ;;
        *)
            echo "Error: Invalid chain '\$chain'. Use 'eth' or 'sol'"
            return 1
            ;;
    esac
}

# Mint the NFT with shared secret
mint_with_secret() {
    local chain="\$1"
    local secret="\$2"
    
    if [ -z "\$chain" ] || [ -z "\$secret" ]; then
        echo "Usage: mint_with_secret --chain <eth|sol> <SECRET>"
        echo "  or:  mint_with_secret <SECRET> --chain <eth|sol>"
        return 1
    fi
    
    # Handle argument order flexibility
    if [ "\$chain" = "--chain" ]; then
        chain="\$2"
        secret="\$3"
    elif [ "\$secret" = "--chain" ]; then
        secret="\$1"
        chain="\$3"
    fi
    
    case "\$chain" in
        "eth")
            RUST_LOG=info ./target/release/client mint-with-secret \\
                --chain "eth" \\
                --eth-rpc "\$ETH_RPC_URL" \\
                --buyer-eth-key "\$BUYER_ETH_PRIVKEY" \\
                --nft-contract "\$NFT_CONTRACT_ADDRESS" \\
                --secret "\$secret" \\
                --token-id "\$TOKEN_ID"
            ;;
        "sol")
            RUST_LOG=info ./target/release/client mint-with-secret \\
                --chain "sol" \\
                --sol-rpc "\$SOL_RPC_URL" \\
                --sol-ws "\$SOL_WS_URL" \\
                --buyer-sol-keypair "\$BUYER_SOL_KEYPAIR" \\
                --program-id "\$SOL_PROGRAM_ID" \\
                --secret "\$secret" \\
                --token-id "\$TOKEN_ID"
            ;;
        *)
            echo "Error: Invalid chain '\$chain'. Use 'eth' or 'sol'"
            return 1
            ;;
    esac
}

# Claim bitcoin after secret reveal
claim_btc() {
    local secret="\$1"
    local secret_hash="\$2"
    local lock_txid="\$3"
    
    if [ -z "\$secret" ] || [ -z "\$secret_hash" ] || [ -z "\$lock_txid" ]; then
        echo "Usage: claim_btc <SECRET> <SECRET_HASH> <LOCK_TXID>"
        return 1
    fi
    
    RUST_LOG=info ./target/release/client claim-btc \\
        --seller-btc-key "\$SELLER_BTC_PRIVKEY" \\
        --buyer-btc-pubkey "\$BUYER_BTC_PUBKEY" \\
        --secret "\$secret" \\
        --secret-hash "\$secret_hash" \\
        --lock-txid "\$lock_txid" \\
        --lock-vout 0 \\
        --timeout "\$HTLC_TIMEOUT"
}

# Graceful shutdown
stop_services() {
    echo "Stopping all demo services..."
    
    # Stop Bitcoin
    if bitcoin-cli -regtest -datadir="\$BTC_DATA_DIR" stop 2>/dev/null; then
        echo "Bitcoin stopped"
    else
        echo "Bitcoin was not running or failed to stop gracefully"
        # Force kill if needed
        pkill -f "bitcoind.*regtest" 2>/dev/null || true
    fi
    
    # Stop Hardhat
    if [ -f "$SETUP_DIR/agent/eth/hardhat.pid" ]; then
        local hardhat_pid=\$(cat "$SETUP_DIR/agent/eth/hardhat.pid")
        if ps -p "$hardhat_pid" > /dev/null 2>&1; then
            kill "$hardhat_pid" && echo "Hardhat stopped"
        fi
        rm -f "$SETUP_DIR/agent/eth/hardhat.pid"
    fi

    # Stop Solana
    if [ -f "$SETUP_DIR/agent/sol/solana.pid" ]; then
        local solana_pid=$(cat "$SETUP_DIR/agent/sol/solana.pid")
        if ps -p "$solana_pid" > /dev/null 2>&1; then
            kill "$solana_pid" && echo "Solana test validator stopped"
        fi
        rm -f "$SETUP_DIR/agent/sol/solana.pid"
    else
        pkill -f "solana-test-validator" 2>/dev/null && echo "Solana test validator stopped" || true
    fi
    
    echo "All services stopped"
}

echo "Demo configuration loaded!"
echo "Available commands:"
echo "  lock_btc           - Lock up Bitcoin in the HTLC"
echo "  commit_for_mint    - Seller commits to mint (requires secret hash)"
echo "  mint_with_secret   - Buyer mints the NFT with secret reveal"
echo "  claim_btc          - Seller claims Bitcoin (requires secret, hash, txid)"
echo "  stop_services      - Stop all running services"
echo ""
echo "Bitcoin RPC: \$BTC_RPC_URL"
echo "Ethereum RPC: \$ETH_RPC_URL"
echo "NFT Contract: \$NFT_CONTRACT_ADDRESS"
EOF
    
    chmod +x "$SETUP_DIR/atomic_swap.sh"
    
    success "Test accounts and configuration created!"
}