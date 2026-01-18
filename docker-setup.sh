#!/bin/bash

set -e

# Force Docker environment mode and set base directory
# config.sh will derive BITCOIN_DATA_DIR, SWAP_DIR, LOG_FILE from SETUP_DIR
export IS_DOCKER="true"
export SETUP_DIR="/app"

# Source shared configuration and scripts
source "$SETUP_DIR/scripts/logging.sh"
source "$SETUP_DIR/scripts/config.sh"
source "$SETUP_DIR/scripts/accounts.sh"

wait_for_bitcoin() {
    local max_attempts=30
    local attempt=1
    log "Waiting for Bitcoin to start..."
    while [ $attempt -le $max_attempts ]; do
        if btc_cli getnetworkinfo &>/dev/null; then
            success "Bitcoin is ready!"
            return 0
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done
    error "Bitcoin failed to start within $((max_attempts * 2)) seconds"
    return 1
}

wait_for_ethereum() {
    local max_attempts=30
    local attempt=1
    log "Waiting for Ethereum node to start..."
    while [ $attempt -le $max_attempts ]; do
        if curl -s -X POST -H 'Content-Type: application/json' \
            --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            "http://$ETH_RPC_HOST:$ETH_RPC_PORT" &>/dev/null; then
            success "Ethereum node is ready!"
            return 0
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done
    error "Ethereum node failed to start within $((max_attempts * 2)) seconds"
    return 1
}

wait_for_solana() {
    local max_attempts=60
    local attempt=1
    log "Waiting for Solana test validator to start..."

    while [ $attempt -le 10 ]; do
        if nc -z "$SOL_RPC_HOST" "$SOL_RPC_PORT" 2>/dev/null; then
            log "Solana port $SOL_RPC_PORT is open"
            break
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done

    attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -s -X POST "http://$SOL_RPC_HOST:$SOL_RPC_PORT" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":1,"method":"getVersion"}' 2>/dev/null | grep -q "result"; then
            success "Solana RPC is responding!"

            sleep 5

            if solana cluster-version --url "$SOL_RPC_URL" 2>/dev/null; then
                success "Solana test validator is fully ready!"
                return 0
            fi
        fi

        if curl -s "http://$SOL_RPC_HOST:$SOL_RPC_PORT/health" 2>/dev/null | grep -q "ok"; then
            log "Solana health check passed"
            sleep 3
            if solana cluster-version --url "$SOL_RPC_URL" 2>/dev/null; then
                success "Solana test validator is ready!"
                return 0
            fi
        fi

        echo -n "."
        sleep 3
        ((attempt++))
    done

    log "Debug: Attempting direct curl to Solana RPC..."
    curl -v "http://$SOL_RPC_HOST:$SOL_RPC_PORT" 2>&1 | head -20

    error "Solana test validator failed to start within $((max_attempts * 3)) seconds"
    return 1
}

setup_bitcoin() {
    log "Setting up Bitcoin wallet..."
    if ! btc_cli listwallets | grep -q "testwallet"; then
        btc_cli createwallet "testwallet"
    fi
    log "Generating initial blocks..."
    address=$(btc_cli getnewaddress "initial")
    btc_cli generatetoaddress 101 "$address"
}

setup_ethereum() {
    log "Setting up Ethereum development environment..."

    cd "$SETUP_DIR/agent/eth"

    # Clean and reinstall dependencies
    log "Ensuring correct dependencies..."
    rm -rf node_modules
    npm install --silent

    log "Compiling smart contracts..."
    npx hardhat compile

    log "Deploying NFT contract with Ignition..."
    npx hardhat ignition deploy ignition/modules/NFTSecretMint.ts --network docker

    local deployment_file="ignition/deployments/chain-31337/deployed_addresses.json"
    if [ ! -f "$deployment_file" ]; then
        error "Deployment artifacts not found! Check hardhat.log for details"
    fi

    local contract_address
    if contract_address=$(jq -r '.["NFTSecretMintModule#NFTSecretMint"]' "$deployment_file" 2>/dev/null); then
        if [ -z "$contract_address" ] || [ "$contract_address" == "null" ]; then
            error "Failed to extract contract address from $deployment_file"
        fi
    else
        error "Failed to parse deployment file $deployment_file"
    fi

    # Write contract address to .swap directory
    mkdir -p "$SWAP_DIR"
    echo "$contract_address" > "$SWAP_DIR/contract_address.txt"
    log "Contract deployed at: $contract_address"

    cd "$SETUP_DIR"
    success "Ethereum environment ready!"
}

setup_solana() {
    # Ensure Solana tools are available
    export PATH="/root/.local/share/solana/install/active_release/bin:$PATH"

    DEFAULT_SIGNER="/root/.config/solana/id.json"

    log "Generating Solana keypairs..."

    # Ensure .swap/keypairs directory exists
    mkdir -p "$SWAP_DIR/keypairs"

    if [ ! -f "$DEFAULT_SIGNER" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile $DEFAULT_SIGNER
    fi

    if [ ! -f "$SWAP_DIR/keypairs/buyer.json" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile "$SWAP_DIR/keypairs/buyer.json"
    fi

    if [ ! -f "$SWAP_DIR/keypairs/seller.json" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile "$SWAP_DIR/keypairs/seller.json"
    fi

    local default_signer=$(solana-keygen pubkey $DEFAULT_SIGNER)
    local buyer_pubkey=$(solana-keygen pubkey "$SWAP_DIR/keypairs/buyer.json")
    local seller_pubkey=$(solana-keygen pubkey "$SWAP_DIR/keypairs/seller.json")

    log "Funding Solana accounts..."
    solana airdrop 20 "$default_signer" --url "$SOL_RPC_URL"
    solana airdrop 10 "$buyer_pubkey" --url "$SOL_RPC_URL"
    solana airdrop 10 "$seller_pubkey" --url "$SOL_RPC_URL"

    log "Buyer Solana address: $buyer_pubkey"
    log "Seller Solana address: $seller_pubkey"

    if [ -d "$SETUP_DIR/agent/sol" ]; then
        log "Building and deploying Solana program..."
        cd "$SETUP_DIR/agent/sol"

        log "Syncing Anchor keys..."
        anchor keys sync

        log "Building Anchor program... might take a while"
        anchor build

        log "Deploying program to local validator..."
        anchor deploy --provider.cluster "$SOL_RPC_URL"

        # Extract program ID and write to .swap directory
        if [ -f "target/deploy/sol_htlc-keypair.json" ]; then
            local program_id=$(solana-keygen pubkey target/deploy/sol_htlc-keypair.json)
            echo "$program_id" > "$SWAP_DIR/program_id.txt"
            log "Program deployed with ID: $program_id"
        else
            warn "Program keypair not found, checking Anchor.toml..."
            local program_id=$(grep -o 'sol_htlc = "[^"]*"' Anchor.toml | cut -d'"' -f2)
            if [ -n "$program_id" ]; then
                echo "$program_id" > "$SWAP_DIR/program_id.txt"
                log "Program ID from Anchor.toml: $program_id"
            else
                error "Could not determine program ID. Check anchor build output."
            fi
        fi

        cd "$SETUP_DIR"
    else
        warn "Solana agent directory not found at $SETUP_DIR/agent/sol, skipping program deployment"
        echo "11111111111111111111111111111112" > "$SWAP_DIR/program_id.txt"
        warn "Using placeholder program ID. Deploy your actual program and update SOL_PROGRAM_ID"
    fi

    success "Solana environment ready!"
}

verify_setup() {
    log "Verifying setup..."

    if btc_info=$(btc_cli getblockchaininfo 2>/dev/null); then
        local block_count=$(echo "$btc_info" | jq -r .blocks)
        log "Bitcoin: $block_count blocks in regtest chain"
    else
        warn "Bitcoin verification failed"
    fi

    if curl -s -X POST -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        "$ETH_RPC_URL" &>/dev/null; then
        log "Ethereum: Hardhat node responding"
    else
        warn "Ethereum node not responding"
    fi

    if [ -f "$SWAP_DIR/contract_address.txt" ]; then
        local contract_address=$(cat "$SWAP_DIR/contract_address.txt")
        log "NFT Contract: $contract_address deployed"
    else
        warn "Contract address file not found in .swap/"
    fi

    if solana cluster-version --url "$SOL_RPC_URL" &>/dev/null; then
        log "Solana: Test validator responding"
    else
        warn "Solana test validator not responding"
    fi

    if [ -f "$SWAP_DIR/keypairs/buyer.json" ] && [ -f "$SWAP_DIR/keypairs/seller.json" ]; then
        log "Solana keypairs: Generated successfully in .swap/keypairs/"
    else
        warn "Solana keypair files not found in .swap/keypairs/"
    fi

    if [ -f "$SETUP_DIR/target/release/atomic-swap" ] || [ -f "$SETUP_DIR/target/release/client" ]; then
        log "Rust client: Built successfully"
    else
        warn "Rust client binary not found, but build may have completed"
    fi

    if [ -f "$SWAP_DIR/atomic_swap.sh" ]; then
        log "Configuration: .swap/atomic_swap.sh generated"
    else
        warn "Configuration file not found in .swap/"
    fi

    success "Setup verification completed!"
}

print_usage_instructions() {
    echo
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}  Setup Complete! ${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo
    echo -e "${BLUE}To run the demo:${NC}"
    echo
    echo -e "1. ${YELLOW}Source the demo configuration:${NC}"
    echo "   source .swap/atomic_swap.sh"
    echo
    echo -e "2. ${YELLOW}Follow the rest of the demo guide${NC}"
    echo
    echo -e "${BLUE}Configuration saved to:${NC} .swap/atomic_swap.sh"
    echo -e "${BLUE}Keypairs saved to:${NC} .swap/keypairs/"
    echo -e "${BLUE}Secrets will be saved to:${NC} .swap/secrets/"
    echo -e "${BLUE}Setup log saved to:${NC} setup.log"
    echo -e "${BLUE}Bitcoin data directory:${NC} $BITCOIN_DATA_DIR"
    echo
    echo -e "${YELLOW}Services running:${NC}"
    echo "  > Bitcoin regtest: $BTC_RPC_URL"
    echo "  > Ethereum (Hardhat): $ETH_RPC_URL"
    echo "  > Solana test validator: $SOL_RPC_URL"
    if [ -f "$SWAP_DIR/contract_address.txt" ]; then
        echo "   Ethereum NFT contract addr: $(cat "$SWAP_DIR/contract_address.txt")"
    fi
    if [ -f "$SWAP_DIR/program_id.txt" ]; then
        echo "   Solana NFT program ID: $(cat "$SWAP_DIR/program_id.txt")"
    fi
    echo
}

main() {
    log "Starting Cross-Chain Atomic Swap setup (Docker environment)..."
    mkdir -p "$SWAP_DIR"
    > "$LOG_FILE"

    wait_for_bitcoin
    wait_for_ethereum
    wait_for_solana

    setup_bitcoin
    setup_ethereum
    setup_solana

    # Use shared generate_test_accounts from scripts/accounts.sh
    generate_test_accounts
    verify_setup

    success "Setup completed successfully!"
    print_usage_instructions
}

cleanup() {
    log "Cleaning up on exit..."
}

trap cleanup EXIT

main "$@"
