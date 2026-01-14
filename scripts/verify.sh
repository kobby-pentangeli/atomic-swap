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

    if [ -f "$SWAP_DIR/contract_address.txt" ]; then
        local contract_address=$(cat "$SWAP_DIR/contract_address.txt")
        log "NFT Contract: $contract_address deployed"
    else
        warn "Contract address file not found in .swap/"
    fi

    if solana cluster-version --url http://localhost:8899 &>/dev/null; then
        log "Solana: Test validator responding"
    else
        warn "Solana test validator not responding"
    fi

    if [ -f "$SWAP_DIR/program_id.txt" ]; then
        local program_id=$(cat "$SWAP_DIR/program_id.txt")
        log "Solana Program ID: $program_id deployed"
    else
        warn "Program ID file not found in .swap/"
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
