#!/bin/bash

set -e

SETUP_DIR="$(pwd)"
BITCOIN_DATA_DIR="$SETUP_DIR/.bitcoin"
BITCOIN_CONF="$BITCOIN_DATA_DIR/bitcoin.conf"
LOG_FILE="$SETUP_DIR/setup.log"

# Check if running in Docker
IS_DOCKER=${IS_DOCKER:-false}

source "$SETUP_DIR/scripts/logging.sh"
source "$SETUP_DIR/scripts/prerequisites.sh"
source "$SETUP_DIR/scripts/bitcoin.sh"
source "$SETUP_DIR/scripts/ethereum.sh"
source "$SETUP_DIR/scripts/solana.sh"
source "$SETUP_DIR/scripts/accounts.sh"
source "$SETUP_DIR/scripts/verify.sh"
source "$SETUP_DIR/scripts/instructions.sh"

main() {
    log "Starting cross-chain atomic swap setup..."
    log "Running in Docker: $IS_DOCKER"
    log "Setup log: $LOG_FILE"
    log "Bitcoin data directory: $BITCOIN_DATA_DIR"
    
    > "$LOG_FILE"
    
    # Skip Bitcoin process stop in Docker (managed by compose)
    if [ "$IS_DOCKER" = "false" ]; then
        stop_bitcoin_processes
    fi
    
    check_prerequisites

    # Skip Rust build in Docker (already built in Dockerfile)
    if [ "$IS_DOCKER" = "false" ]; then
        log "Building client..."
        if [ -d "$SETUP_DIR/client" ]; then
            cd "$SETUP_DIR/client"
            cargo build --release
            cd "$SETUP_DIR"
            success "Client built successfully!"
        else
            warn "Client directory not found, skipping Rust build"
        fi
    fi
    
    setup_bitcoin
    setup_ethereum
    setup_solana
    generate_test_accounts
    verify_setup
    
    success "Setup completed successfully!"
    
    # Don't exit in Docker mode, keep container running
    if [ "$IS_DOCKER" = "true" ]; then
        log "Docker setup complete. Container remains running for demo commands."
        log "Use: docker-compose exec app bash"
        log "Then: source atomic_swap.sh"
        tail -f /dev/null
    else
        print_usage_instructions
    fi
}

cleanup() {
    log "Cleaning up on exit..."
}

trap cleanup EXIT

main "$@"