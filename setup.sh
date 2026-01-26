#!/bin/bash

set -e

# Set base directory before sourcing config
export SETUP_DIR="$(pwd)"

# Source shared configuration and scripts
source "$SETUP_DIR/scripts/logging.sh"
source "$SETUP_DIR/scripts/config.sh"
source "$SETUP_DIR/scripts/prerequisites.sh"
source "$SETUP_DIR/scripts/bitcoin.sh"
source "$SETUP_DIR/scripts/ethereum.sh"
source "$SETUP_DIR/scripts/solana.sh"
source "$SETUP_DIR/scripts/accounts.sh"
source "$SETUP_DIR/scripts/verify.sh"
source "$SETUP_DIR/scripts/instructions.sh"

main() {
    log "Starting cross-chain atomic swap setup (local environment)..."
    mkdir -p "$SWAP_DIR"

    log "Demo outputs directory: $SWAP_DIR"
    log "Setup log: $LOG_FILE"
    log "Bitcoin data directory: $BITCOIN_DATA_DIR"

    > "$LOG_FILE"

    stop_bitcoin_processes
    check_prerequisites
    setup_bitcoin
    setup_ethereum
    setup_solana

    log "Building the atomic swap client..."
    if [ -d "$SETUP_DIR/client" ]; then
        cd "$SETUP_DIR/client"
        cargo build --release
        cd "$SETUP_DIR"
        success "Client built successfully!"
    else
        warn "Client directory not found, skipping Rust build"
    fi

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
