#!/bin/bash

check_command() {
    if ! command -v "$1" &> /dev/null; then
        warn "$1 is not installed."
        return 1
    fi
    return 0
}

install_jq() {
    log "Installing jq for JSON parsing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y jq
    elif command -v brew &> /dev/null; then
        brew install jq
    elif command -v yum &> /dev/null; then
        sudo yum install -y jq
    else
        error "Could not install jq automatically. Please install manually: https://stedolan.github.io/jq/download/"
    fi
}

install_bitcoin_core() {
    warn "Bitcoin Core not found. Attempting to install..."
    
    if command -v apt-get &> /dev/null; then
        log "Installing Bitcoin Core via apt-get..."
        sudo apt-get update && sudo apt-get install -y bitcoind
    elif command -v brew &> /dev/null; then
        log "Installing Bitcoin Core via Homebrew..."
        brew install bitcoin
    else
        error "Could not install Bitcoin Core automatically. Please install manually: https://bitcoin.org/en/download"
    fi
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! check_command "cargo"; then
        error "Rust/Cargo not found. Please install: https://rustup.rs/"
    fi
    
    if ! check_command "node"; then
        error "Node.js not found. Please install Node.js 18+: https://nodejs.org/"
    fi
    
    if ! check_command "npm"; then
        error "npm not found. Please install Node.js with npm."
    fi
    
    if ! check_command "jq"; then
        install_jq
    fi

    if ! check_command "bitcoind" || ! check_command "bitcoin-cli"; then
        install_bitcoin_core
    fi
    
    success "All prerequisites found!"
}