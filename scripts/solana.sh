#!/bin/bash

wait_for_solana() {
    local max_attempts=30
    local attempt=1
    
    log "Waiting for Solana test validator to start..."

    # Use the appropriate RPC URL based on environment
    local rpc_url="http://localhost:8899"
    if [ "$IS_DOCKER" = "true" ]; then
        rpc_url="http://solana:8899"
    fi
    
    while [ $attempt -le $max_attempts ]; do
        if solana cluster-version --url "$rpc_url" &>/dev/null; then
            success "Solana test validator is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    error "Solana test validator failed to start within $((max_attempts * 2)) seconds"
    return 1
}

setup_solana() {
    log "Setting up Solana development environment..."

    if [ "$IS_DOCKER" = "true" ]; then
        log "Solana test validator running in separate container"
        log "Waiting for Solana validator to be ready..."
        wait_for_solana
    else
        if ! command -v solana &> /dev/null; then
            warn "Solana CLI not found. Installing..."
            
            log "Downloading and installing Solana CLI..."
            sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
            export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
            
            if ! command -v solana &> /dev/null; then
                error "Failed to install Solana CLI. Please install manually: https://solana.com/docs/intro/installation#install-the-solana-cli"
            fi
        fi
        
        if ! command -v anchor &> /dev/null; then
            warn "Anchor framework not found. Installing..."
            
            log "Installing Anchor..."
            cargo install --git https://github.com/solana-foundation/anchor avm --force && avm install latest && avm use latest
            
            if ! command -v anchor &> /dev/null; then
                error "Failed to install Anchor. Please install manually: https://solana.com/docs/intro/installation#install-anchor-cli"
            fi
        fi
        
        log "Starting Solana test validator..."
        pkill -f "solana-test-validator" 2>/dev/null || true
        sleep 2

        solana-test-validator \
            --reset \
            --rpc-port 8899 \
            --ledger .solana-ledger \
            --log \
            --clone metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s \
            --clone-upgradeable-program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s \
            --url https://api.mainnet-beta.solana.com \
            > solana.log 2>&1 &
        
        local solana_pid=$!
        echo "$solana_pid" > $SETUP_DIR/agent/sol/solana.pid
        
        wait_for_solana
    fi
    
    log "Generating Solana keypairs..."
    
    if [ ! -f "buyer-keypair.json" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile buyer-keypair.json
    fi
    
    if [ ! -f "seller-keypair.json" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile seller-keypair.json
    fi
    
    local buyer_pubkey=$(solana-keygen pubkey buyer-keypair.json)
    local seller_pubkey=$(solana-keygen pubkey seller-keypair.json)
    
    log "Funding Solana accounts..."
    solana airdrop 10 "$buyer_pubkey" --url http://localhost:8899
    solana airdrop 10 "$seller_pubkey" --url http://localhost:8899
    
    log "Buyer Solana address: $buyer_pubkey"
    log "Seller Solana address: $seller_pubkey"

    if [ -d "$SETUP_DIR/agent/sol" ]; then
        log "Building and deploying Solana program..."
        cd "$SETUP_DIR/agent/sol"
        
        log "Syncing Anchor keys..."
        anchor keys sync
        
        log "Building Anchor program..."
        anchor build
        
        log "Deploying program to local validator..."
        anchor deploy --provider.cluster localnet
        
        # Extract program ID
        if [ -f "target/deploy/sol_htlc-keypair.json" ]; then
            local program_id=$(solana-keygen pubkey target/deploy/sol_htlc-keypair.json)
            echo "$program_id" > program_id.txt
            log "Program deployed with ID: $program_id"
        else
            warn "Program keypair not found, checking Anchor.toml..."
            local program_id=$(grep -o 'sol_htlc = "[^"]*"' Anchor.toml | cut -d'"' -f2)
            if [ -n "$program_id" ]; then
                echo "$program_id" > program_id.txt
                log "Program ID from Anchor.toml: $program_id"
            else
                error "Could not determine program ID. Check anchor build output."
            fi
        fi
        
        cd "$SETUP_DIR"
    else
        warn "Solana agent directory not found at $SETUP_DIR/agent/sol, skipping program deployment"
        echo "11111111111111111111111111111112" > program_id.txt
        warn "Using placeholder program ID. Deploy your actual program and update SOL_PROGRAM_ID"
    fi
    
    success "Solana environment ready!"
}