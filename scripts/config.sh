#!/bin/bash

# Environment configuration for cross-chain atomic swap setup.
#
# This script detects whether we're running locally or in Docker and sets
# appropriate configuration variables. It should be sourced before other scripts.
#
# Environment detection priority:
#   1. Explicit IS_DOCKER=true/false environment variable
#   2. Auto-detect by checking if 'bitcoin' hostname resolves (Docker network)

# Detect Docker environment if not explicitly set
if [ -z "$IS_DOCKER" ]; then
    if getent hosts bitcoin &>/dev/null; then
        IS_DOCKER="true"
    else
        IS_DOCKER="false"
    fi
fi

export IS_DOCKER

if [ "$IS_DOCKER" = "true" ]; then
    export BTC_RPC_HOST="bitcoin"
    export BTC_RPC_PORT="18443"

    export ETH_RPC_HOST="ethereum"
    export ETH_RPC_PORT="8545"

    export SOL_RPC_HOST="solana"
    export SOL_RPC_PORT="8899"
    export SOL_WS_PORT="8900"

    SETUP_DIR="${SETUP_DIR:-/app}"
    BITCOIN_DATA_DIR="${BITCOIN_DATA_DIR:-$SETUP_DIR/.bitcoin}"
else
    export BTC_RPC_HOST="localhost"
    export BTC_RPC_PORT="18443"

    export ETH_RPC_HOST="localhost"
    export ETH_RPC_PORT="8545"

    export SOL_RPC_HOST="localhost"
    export SOL_RPC_PORT="8899"
    export SOL_WS_PORT="8900"

    SETUP_DIR="${SETUP_DIR:-$(pwd)}"
    BITCOIN_DATA_DIR="${BITCOIN_DATA_DIR:-$SETUP_DIR/.bitcoin}"
fi

export SETUP_DIR
export BITCOIN_DATA_DIR
export BITCOIN_CONF="$BITCOIN_DATA_DIR/bitcoin.conf"
export SWAP_DIR="${SWAP_DIR:-$SETUP_DIR/.swap}"
export LOG_FILE="${LOG_FILE:-$SWAP_DIR/setup.log}"

export BTC_RPC_USER="${BTC_RPC_USER:-user}"
export BTC_RPC_PASSWORD="${BTC_RPC_PASSWORD:-password}"

export BTC_RPC_URL="http://$BTC_RPC_HOST:$BTC_RPC_PORT"
export ETH_RPC_URL="http://$ETH_RPC_HOST:$ETH_RPC_PORT"
export SOL_RPC_URL="http://$SOL_RPC_HOST:$SOL_RPC_PORT"
export SOL_WS_URL="ws://$SOL_RPC_HOST:$SOL_WS_PORT"

# Bitcoin CLI wrapper that uses correct connection method for the environment
btc_cli() {
    if [ "$IS_DOCKER" = "true" ]; then
        bitcoin-cli -rpcconnect="$BTC_RPC_HOST" -rpcport="$BTC_RPC_PORT" \
            -rpcuser="$BTC_RPC_USER" -rpcpassword="$BTC_RPC_PASSWORD" -regtest "$@"
    else
        bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" "$@"
    fi
}

export -f btc_cli
