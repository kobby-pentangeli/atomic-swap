#!/bin/bash

# Test account generation for cross-chain atomic swap.
#
# This script generates Bitcoin keypairs, retrieves Ethereum test keys,
# and creates the demo configuration file (.swap/atomic_swap.sh).
#
# Prerequisites: This file must be sourced after config.sh
# Usage: Sourced by setup.sh and docker-setup.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

    if buyer_btc_address=$(btc_cli getnewaddress "buyer" 2>/dev/null); then
        if addr_info=$(btc_cli getaddressinfo "$buyer_btc_address" 2>/dev/null); then
            buyer_btc_pubkey=$(echo "$addr_info" | jq -r .pubkey)

            # Get derivation path
            local hdkeypath=$(echo "$addr_info" | jq -r .hdkeypath)

            # Get the wallet's master private key directly
            local wallet_info=$(btc_cli getwalletinfo)
            local wallet_name=$(echo "$wallet_info" | jq -r .walletname)

            # Get descriptors with private keys
            local descriptors=$(btc_cli listdescriptors true)

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

                if [[ -z "$base_xpriv" ]]; then
                    base_xpriv=$(echo "$desc" | sed -n 's/.*]\([^/]*\)\/.*/\1/p')
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

    if seller_btc_address=$(btc_cli getnewaddress "seller" 2>/dev/null); then
        if addr_info=$(btc_cli getaddressinfo "$seller_btc_address" 2>/dev/null); then
            seller_btc_pubkey=$(echo "$addr_info" | jq -r .pubkey)

            local hdkeypath=$(echo "$addr_info" | jq -r .hdkeypath)

            local descriptors=$(btc_cli listdescriptors true)

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
    btc_cli generatetoaddress 5 "$buyer_btc_address" > /dev/null
    btc_cli generatetoaddress 1 "$(btc_cli getnewaddress)" > /dev/null

    local buyer_eth_privkey="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    local buyer_eth_address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    local seller_eth_privkey="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    local seller_eth_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

    local contract_address="N/A"
    if [ -f "$SWAP_DIR/contract_address.txt" ]; then
        contract_address=$(cat "$SWAP_DIR/contract_address.txt")
    fi

    log "Creating demo configuration..."

    local program_id="11111111111111111111111111111112"
    if [ -f "$SWAP_DIR/program_id.txt" ]; then
        program_id=$(cat "$SWAP_DIR/program_id.txt")
    fi

    # Ensure .swap directory exists
    mkdir -p "$SWAP_DIR/secrets"

    # Determine the bitcoin-cli command for the generated script
    local btc_cli_cmd
    if [ "$IS_DOCKER" = "true" ]; then
        btc_cli_cmd="bitcoin-cli -rpcconnect=\"\$BTC_RPC_HOST\" -rpcport=\"\$BTC_RPC_PORT\" -rpcuser=\"\$BTC_RPC_USER\" -rpcpassword=\"\$BTC_RPC_PASSWORD\" -regtest"
    else
        btc_cli_cmd="bitcoin-cli -regtest -datadir=\"\$BTC_DATA_DIR\""
    fi

    # Generate the atomic_swap.sh configuration file
    cat > "$SWAP_DIR/atomic_swap.sh" << EOF
#!/bin/bash

# Cross-Chain Atomic Swap Demo Configuration
# Generated by setup.sh on $(date)
# Environment: $([ "$IS_DOCKER" = "true" ] && echo "Docker" || echo "Local")

# Bitcoin Configuration
export BTC_RPC_HOST="$BTC_RPC_HOST"
export BTC_RPC_PORT="$BTC_RPC_PORT"
export BTC_RPC_URL="$BTC_RPC_URL"
export BTC_RPC_USER="$BTC_RPC_USER"
export BTC_RPC_PASSWORD="$BTC_RPC_PASSWORD"
export BTC_NETWORK="regtest"
export BTC_DATA_DIR="$BITCOIN_DATA_DIR"

# Ethereum Configuration
export ETH_RPC_URL="$ETH_RPC_URL"
export NFT_CONTRACT_ADDRESS="$contract_address"

# Solana Configuration
export SOL_RPC_URL="$SOL_RPC_URL"
export SOL_WS_URL="$SOL_WS_URL"
export SOL_PROGRAM_ID="$program_id"

# Buyer Keys
export BUYER_BTC_PRIVKEY="$buyer_btc_privkey"
export BUYER_BTC_ADDRESS="$buyer_btc_address"
export BUYER_BTC_PUBKEY="$buyer_btc_pubkey"
export BUYER_ETH_PRIVKEY="$buyer_eth_privkey"
export BUYER_ETH_ADDRESS="$buyer_eth_address"
export BUYER_SOL_KEYPAIR=".swap/keypairs/buyer.json"

# Seller Keys
export SELLER_BTC_PRIVKEY="$seller_btc_privkey"
export SELLER_BTC_PUBKEY="$seller_btc_pubkey"
export SELLER_BTC_ADDRESS="$seller_btc_address"
export SELLER_ETH_PRIVKEY="$seller_eth_privkey"
export SELLER_ETH_ADDRESS="$seller_eth_address"
export SELLER_SOL_KEYPAIR=".swap/keypairs/seller.json"

# Demo Parameters
export BTC_AMOUNT="100000"  # 0.001 BTC in satoshis
export ETH_NFT_PRICE="1000000000000000000"  # 1 ETH in wei
export SOL_NFT_PRICE="1000000000"  # 1 SOL in lamports
export TOKEN_ID="1"
export METADATA_URI="https://example.com/nft/1.json"
export NFT_NAME="Demo NFT"
export NFT_SYMBOL="DEMO"
export HTLC_TIMEOUT="144"  # blocks

# Bitcoin CLI command (environment-specific)
export BTC_CLI_CMD="$btc_cli_cmd"

EOF

    # Append the demo functions from the shared template
    cat "$SCRIPT_DIR/demo-functions.sh" >> "$SWAP_DIR/atomic_swap.sh"

    chmod +x "$SWAP_DIR/atomic_swap.sh"

    success "Test accounts and configuration created!"
    log "To load the configuration: source .swap/atomic_swap.sh"
}
