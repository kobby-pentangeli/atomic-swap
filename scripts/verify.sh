#!/bin/bash

verify_setup() {
    log "Verifying setup..."

    if btc_info=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getblockchaininfo 2>/dev/null); then
        local block_count=$(echo "$btc_info" | jq -r .blocks)
        log "Bitcoin: $block_count blocks in regtest chain"
    else
        warn "Bitcoin verification failed"
    fi
    
    if curl -s -X POST -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        http://localhost:8545 &>/dev/null; then
        log "Ethereum: Hardhat node responding"
    else
        warn "Ethereum node not responding"
    fi
    
    if [ -f "$SETUP_DIR/agent/eth/contract_address.txt" ]; then
        local contract_address=$(cat "$SETUP_DIR/agent/eth/contract_address.txt")
        log "NFT Contract: $contract_address deployed"
    else
        warn "Contract address file not found"
    fi

    if solana cluster-version --url http://localhost:8899 &>/dev/null; then
        log "Solana: Test validator responding"
    else
        warn "Solana test validator not responding"
    fi
    
    if [ -f "buyer-keypair.json" ] && [ -f "seller-keypair.json" ]; then
        log "Solana keypairs: Generated successfully"
    else
        warn "Solana keypair files not found"
    fi
    
    if [ -f "$SETUP_DIR/target/release/atomic-swap" ] || [ -f "$SETUP_DIR/target/release/client" ]; then
        log "Rust client: Built successfully"
    else
        warn "Rust client binary not found, but build may have completed"
    fi
    
    success "Setup verification completed!"
}