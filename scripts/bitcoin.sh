#!/bin/bash

stop_bitcoin_processes() {
    log "Checking for existing Bitcoin processes..."
    
    # Stop Bitcoin Core using bitcoin-cli if it's running
    if command -v bitcoin-cli &> /dev/null; then
        bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" stop 2>/dev/null && log "Stopped Bitcoin via bitcoin-cli (project datadir)" || true
        bitcoin-cli -regtest stop 2>/dev/null && log "Stopped Bitcoin via bitcoin-cli (default)" || true
    fi
    
    sleep 3
    
    if pgrep -f "bitcoind" > /dev/null; then
        warn "Force killing remaining bitcoind processes..."
        pkill -f "bitcoind" 2>/dev/null || true
        sleep 2
    fi
    
    if pgrep -f "bitcoind" > /dev/null; then
        error "Could not stop existing bitcoind processes. Please stop them manually and try again."
    fi
    
    success "No Bitcoin processes running"
}

wait_for_bitcoin() {
    local max_attempts=30
    local attempt=1
    
    # Use the appropriate RPC host based on environment
    local rpc_host="localhost"
    if [ "$IS_DOCKER" = "true" ]; then
        rpc_host="bitcoin"
    fi
    
    log "Waiting for bitcoind to start on $rpc_host:18443..."
    
    while [ $attempt -le $max_attempts ]; do
        if bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnetworkinfo &>/dev/null; then
            success "bitcoind is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    error "bitcoind failed to start within $((max_attempts * 2)) seconds"
    return 1
}

setup_bitcoin_wallet() {
    log "Setting up Bitcoin wallet..."
    local existing_wallets
    if existing_wallets=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" listwallets 2>/dev/null); then
        if ! echo "$existing_wallets" | grep -q "testwallet"; then
            log "Creating new wallet 'testwallet'..."
            bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" createwallet "testwallet"
        else
            log "Wallet 'testwallet' already exists"
        fi
    else
        warn "Could not list wallets, attempting to create..."
        bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" createwallet "testwallet" 2>/dev/null || true
    fi
    
    log "Generating initial blocks and funding addresses..."
    local address
    if address=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnewaddress "initial" 2>/dev/null); then
        bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" generatetoaddress 101 "$address" > /dev/null
        log "Generated 101 blocks to address: $address"
    else
        error "Failed to generate new address for initial funding"
    fi
}

setup_bitcoin() {
    log "Setting up Bitcoin regtest environment..."

    if [ "$IS_DOCKER" = "true" ]; then
        log "Bitcoin already running in separate container, configuring wallet..."
        # Wait for Bitcoin to be ready
        wait_for_bitcoin
        
        # Setup wallet and initial funding
        setup_bitcoin_wallet
        success "Bitcoin regtest environment ready!"
        return 0
    fi

    mkdir -p "$BITCOIN_DATA_DIR"
    
    log "Creating Bitcoin configuration..."
    cat > "$BITCOIN_CONF" << 'EOF'
# Global configuration
server=1
rest=1
txindex=1
fallbackfee=0.0001
debug=1
logips=1
dbcache=300
maxmempool=50
daemon=1

# Regtest specific configuration
[regtest]
rpcuser=user
rpcpassword=password
rpcport=18443
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
port=18444
listen=1
discover=0
EOF

    log "Starting bitcoind in regtest mode with custom data directory..."
    bitcoind -regtest -datadir="$BITCOIN_DATA_DIR" -daemon
    
    wait_for_bitcoin
    setup_bitcoin_wallet
    
    success "Bitcoin regtest environment ready!"
}