#!/bin/bash

wait_for_ethereum() {
    local max_attempts=30
    local attempt=1
    
    log "Waiting for Ethereum node to start..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -X POST -H 'Content-Type: application/json' \
            --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            http://localhost:8545 &>/dev/null; then
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

setup_ethereum() {
    log "Setting up Ethereum development environment..."
    
    if [ ! -d "$SETUP_DIR/agent/eth" ]; then
        warn "Ethereum agent directory not found at $SETUP_DIR/agent/eth, skipping Ethereum setup"
        return 0
    fi
    
    cd "$SETUP_DIR/agent/eth"
    
    log "Installing npm dependencies..."
    npm install --silent
    
    log "Compiling smart contracts..."
    npx hardhat compile

    log "Starting Hardhat network..."
    
    if [ -f hardhat.pid ]; then
        local old_pid=$(cat hardhat.pid)
        if ps -p "$old_pid" > /dev/null 2>&1; then
            log "Stopping existing Hardhat process (PID: $old_pid)..."
            kill "$old_pid" 2>/dev/null || true
            sleep 2
        fi
        rm -f hardhat.pid
    fi
    
    pkill -f "hardhat node" 2>/dev/null || true
    sleep 2
    
    npx hardhat node > hardhat.log 2>&1 &
    local hardhat_pid=$!
    echo "$hardhat_pid" > hardhat.pid

    wait_for_ethereum
    
    log "Deploying NFT contract with Ignition..."
    npx hardhat ignition deploy ignition/modules/NFTSecretMint.ts --network localhost

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
    
    echo "$contract_address" > contract_address.txt
    log "Contract deployed at: $contract_address"
    
    cd "$SETUP_DIR"
    success "Ethereum environment ready!"
}