#!/bin/bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SETUP_DIR="$(pwd)"
BITCOIN_DATA_DIR="$SETUP_DIR/.bitcoin"
BITCOIN_CONF="$BITCOIN_DATA_DIR/bitcoin.conf"
LOG_FILE="$SETUP_DIR/setup.log"

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: $1" >> "$LOG_FILE"
}

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

wait_for_service() {
    local service_name="$1"
    local max_attempts=30
    local attempt=1
    
    log "Waiting for $service_name to start..."
    
    while [ $attempt -le $max_attempts ]; do
        if bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnetworkinfo &>/dev/null; then
            success "$service_name is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    error "$service_name failed to start within $((max_attempts * 2)) seconds"
    return 1
}

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

main() {
    log "Starting Cross-Chain Secret Mint setup..."
    log "Setup log: $LOG_FILE"
    log "Bitcoin data directory: $BITCOIN_DATA_DIR"
    
    > "$LOG_FILE"
    
    stop_bitcoin_processes

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
    fi
    
    success "All prerequisites found!"

    log "Building Rust client..."
    if [ -d "$SETUP_DIR/client" ]; then
        cd "$SETUP_DIR/client"
        cargo build --release
        cd "$SETUP_DIR"
        success "Rust client built successfully!"
    else
        warn "Client directory not found, skipping Rust build"
    fi
    
    setup_bitcoin
    setup_ethereum
    generate_test_accounts
    verify_setup
    
    success "Setup completed successfully!"
    print_usage_instructions
}

setup_bitcoin() {
    log "Setting up Bitcoin regtest environment..."
    
    # Create Bitcoin data directory in project root
    mkdir -p "$BITCOIN_DATA_DIR"
    
    # Create bitcoin.conf with better configuration
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
    
    wait_for_service "bitcoind"
    
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
    
    success "Bitcoin regtest environment ready!"
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

generate_test_accounts() {
    log "Generating test accounts and keys..."
    log "Generating Bitcoin test accounts..."

    # Build the xpriv derivation binary if needed
    if [ ! -f "$SETUP_DIR/target/release/derive_privkey" ]; then
        log "Building key derivation helper..."
        cargo build --release --bin derive_privkey
    fi

    local buyer_btc_address seller_btc_address
    local buyer_btc_privkey seller_btc_privkey
    local buyer_btc_pubkey seller_btc_pubkey

    if buyer_btc_address=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnewaddress "buyer" 2>/dev/null); then
        if addr_info=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getaddressinfo "$buyer_btc_address" 2>/dev/null); then
            buyer_btc_pubkey=$(echo "$addr_info" | jq -r .pubkey)
            
            # Get derivation path
            local hdkeypath=$(echo "$addr_info" | jq -r .hdkeypath)
            echo "[DEBUG] HD key path: $hdkeypath"
            
            # Get the wallet's master private key directly
            local wallet_info=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getwalletinfo)
            local wallet_name=$(echo "$wallet_info" | jq -r .walletname)
            
            # Get descriptors with private keys
            local descriptors=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" listdescriptors true)
            echo "[DEBUG] Raw descriptors output:"
            echo "$descriptors"
            
            local path_prefix=""
            if [[ "$hdkeypath" =~ m/84h/1h/0h/0/ ]]; then
                path_prefix="84h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/49h/1h/0h/0/ ]]; then
                path_prefix="49h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/44h/1h/0h/0/ ]]; then
                path_prefix="44h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/86h/1h/0h/0/ ]]; then
                path_prefix="86h/1h/0h/0"
            fi
            
            echo "[DEBUG] Looking for descriptor with path prefix: $path_prefix"

            local desc=$(echo "$descriptors" | jq -r --arg prefix "$path_prefix" '.descriptors[] | select(.desc | contains($prefix)) | select(.desc | test("/0/\\*")) | .desc' | head -1)
            echo "[DEBUG] Selected descriptor: $desc"
            
            if [[ -n "$desc" ]]; then
                local base_xpriv=""
                
                base_xpriv=$(echo "$desc" | sed -n 's/.*(\[.*\]\([a-zA-Z0-9]*\)\/.*/\1/p')
                
                if [[ -z "$base_xpriv" ]]; then
                    base_xpriv=$(echo "$desc" | grep -oE 'tprv[a-zA-Z0-9]+')
                fi
                
                if [[ -z "$base_xprv" ]]; then
                    base_xprv=$(echo "$desc" | sed -n 's/.*]\([^/]*\)\/.*/\1/p')
                fi
                
                echo "[DEBUG] Extracted base xpriv: '$base_xpriv'"
                
                if [[ -n "$base_xpriv" && -n "$hdkeypath" ]]; then
                    echo "[DEBUG] Calling: $SETUP_DIR/target/release/derive_privkey '$base_xpriv' '$hdkeypath'"
                    if buyer_btc_privkey=$("$SETUP_DIR/target/release/derive_privkey" "$base_xpriv" "$hdkeypath" 2>&1); then
                        echo "[DEBUG] Buyer private key derived successfully"
                    else
                        echo "[DEBUG] Derivation failed: $buyer_btc_privkey"
                        error "Failed to derive buyer private key"
                    fi
                else
                    error "Failed to extract xpriv ($base_xpriv) or hdkeypath ($hdkeypath) for buyer"
                fi
            else
                error "Failed to find appropriate descriptor for buyer"
            fi
        else
            error "Failed to get buyer address info"
        fi
    else
        error "Failed to generate buyer Bitcoin address"
    fi

    if seller_btc_address=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnewaddress "seller" 2>/dev/null); then
        if addr_info=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getaddressinfo "$seller_btc_address" 2>/dev/null); then
            seller_btc_pubkey=$(echo "$addr_info" | jq -r .pubkey)
            
            local hdkeypath=$(echo "$addr_info" | jq -r .hdkeypath)
            echo "[DEBUG] HD key path: $hdkeypath"
            
            local descriptors=$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" listdescriptors true)
            
            local path_prefix=""
            if [[ "$hdkeypath" =~ m/84h/1h/0h/0/ ]]; then
                path_prefix="84h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/49h/1h/0h/0/ ]]; then
                path_prefix="49h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/44h/1h/0h/0/ ]]; then
                path_prefix="44h/1h/0h/0"
            elif [[ "$hdkeypath" =~ m/86h/1h/0h/0/ ]]; then
                path_prefix="86h/1h/0h/0"
            fi
            
            echo "[DEBUG] Looking for descriptor with path prefix: $path_prefix"
            
            local desc=$(echo "$descriptors" | jq -r --arg prefix "$path_prefix" '.descriptors[] | select(.desc | contains($prefix)) | select(.desc | test("/0/\\*")) | .desc' | head -1)
            echo "[DEBUG] Selected descriptor: $desc"
            
            if [[ -n "$desc" ]]; then
                local base_xpriv=""
                base_xpriv=$(echo "$desc" | grep -oE 'tprv[a-zA-Z0-9]+')
                
                echo "[DEBUG] Method 1 result: '$base_xpriv'"
                
                if [[ -z "$base_xpriv" ]]; then
                    base_xpriv=$(echo "$desc" | sed -n 's/.*(\([^)]*\)).*/\1/p' | grep -oE 'tprv[a-zA-Z0-9]+')
                    echo "[DEBUG] Method 2 result: '$base_xpriv'"
                fi
                
                echo "[DEBUG] Extracted base xprv: '$base_xpriv'"
                
                if [[ -n "$base_xpriv" && -n "$hdkeypath" ]]; then
                    echo "[DEBUG] Calling: $SETUP_DIR/target/release/derive_privkey '$base_xpriv' '$hdkeypath'"
                    if seller_btc_privkey=$("$SETUP_DIR/target/release/derive_privkey" "$base_xpriv" "$hdkeypath" 2>&1); then
                        echo "[DEBUG] Seller private key derived successfully"
                    else
                        echo "[DEBUG] Derivation failed: $seller_btc_privkey"
                        error "Failed to derive seller private key"
                    fi
                else
                    error "Failed to extract xpriv ($base_xpriv) or hdkeypath ($hdkeypath) for seller"
                fi
            else
                error "Failed to find appropriate descriptor for seller"
            fi
        else
            error "Failed to get seller address info"
        fi
    else
        error "Failed to generate seller Bitcoin address"
    fi
    
    log "Funding buyer Bitcoin address..."
    bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" generatetoaddress 5 "$buyer_btc_address" > /dev/null
    bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" generatetoaddress 1 "$(bitcoin-cli -regtest -datadir="$BITCOIN_DATA_DIR" getnewaddress)" > /dev/null
    
    local buyer_eth_privkey="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    local buyer_eth_address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    local seller_eth_privkey="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    local seller_eth_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    
    local contract_address="N/A"
    if [ -f "$SETUP_DIR/agent/eth/contract_address.txt" ]; then
        contract_address=$(cat "$SETUP_DIR/agent/eth/contract_address.txt")
    fi
    
    log "Creating demo configuration..."
    cat > "$SETUP_DIR/demo_config.sh" << EOF
#!/bin/bash

# Cross-Chain Secret Mint Demo Configuration
# Generated by setup.sh on $(date)

# Bitcoin Configuration
export BTC_RPC_URL="http://localhost:18443"
export BTC_RPC_USER="user"
export BTC_RPC_PASSWORD="password"
export BTC_NETWORK="regtest"
export BTC_DATA_DIR="$BITCOIN_DATA_DIR"

# Ethereum Configuration  
export ETH_RPC_URL="http://localhost:8545"
export NFT_CONTRACT_ADDRESS="$contract_address"

# Buyer Keys
export BUYER_BTC_PRIVKEY="$buyer_btc_privkey"
export BUYER_BTC_ADDRESS="$buyer_btc_address"
export BUYER_BTC_PUBKEY="$buyer_btc_pubkey"
export BUYER_ETH_PRIVKEY="$buyer_eth_privkey"
export BUYER_ETH_ADDRESS="$buyer_eth_address"

# Seller Keys
export SELLER_BTC_PRIVKEY="$seller_btc_privkey"
export SELLER_BTC_PUBKEY="$seller_btc_pubkey"
export SELLER_BTC_ADDRESS="$seller_btc_address"
export SELLER_ETH_PRIVKEY="$seller_eth_privkey"
export SELLER_ETH_ADDRESS="$seller_eth_address"

# Demo Parameters
export BTC_AMOUNT="1000000"  # 0.01 BTC in satoshis
export NFT_PRICE="1000000000000000000"  # 1 ETH in wei
export TOKEN_ID="1"
export METADATA_URI="https://example.com/nft/1.json"
export HTLC_TIMEOUT="144"  # blocks

# Helper function to run demo
run_demo() {
    echo "Starting Cross-Chain Atomic Swap Demo..."
    if [ ! -d "$SETUP_DIR/client" ]; then
        echo "Client directory not found at $SETUP_DIR/client"
        return 1
    fi
    
    cd "$SETUP_DIR/client"
    
    RUST_LOG=info cargo run --release -- atomic-swap \\
        --btc-rpc "\$BTC_RPC_URL" \\
        --btc-user "\$BTC_RPC_USER" \\
        --btc-pass "\$BTC_RPC_PASSWORD" \\
        --btc-network "\$BTC_NETWORK" \\
        --buyer-btc-key "\$BUYER_BTC_PRIVKEY" \\
        --seller-btc-pubkey "\$SELLER_BTC_PUBKEY" \\
        --eth-rpc "\$ETH_RPC_URL" \\
        --buyer-eth-key "\$BUYER_ETH_PRIVKEY" \\
        --nft-contract "\$NFT_CONTRACT_ADDRESS" \\
        --btc-amount "\$BTC_AMOUNT" \\
        --nft-price "\$NFT_PRICE" \\
        --token-id "\$TOKEN_ID" \\
        --metadata-uri "\$METADATA_URI" \\
        --timeout "\$HTLC_TIMEOUT"
}

# Helper function for seller commitment
seller_commit() {
    local secret_hash="\$1"
    if [ -z "\$secret_hash" ]; then
        echo "Usage: seller_commit <SECRET_HASH>"
        return 1
    fi
    
    if [ ! -d "$SETUP_DIR/client" ]; then
        echo "Client directory not found at $SETUP_DIR/client"
        return 1
    fi
    
    cd "$SETUP_DIR/client"
    
    RUST_LOG=info cargo run --release -- commit-for-mint \\
        --seller-eth-key "\$SELLER_ETH_PRIVKEY" \\
        --nft-contract "\$NFT_CONTRACT_ADDRESS" \\
        --secret-hash "\$secret_hash" \\
        --token-id "\$TOKEN_ID" \\
        --nft-price "\$NFT_PRICE" \\
        --buyer-address "\$BUYER_ETH_ADDRESS" \\
        --metadata-uri "\$METADATA_URI"
}

# Helper function for Bitcoin claim
seller_claim_btc() {
    local secret="\$1"
    local secret_hash="\$2"
    local lock_txid="\$3"
    
    if [ -z "\$secret" ] || [ -z "\$secret_hash" ] || [ -z "\$lock_txid" ]; then
        echo "Usage: seller_claim_btc <SECRET> <SECRET_HASH> <LOCK_TXID>"
        return 1
    fi
    
    if [ ! -d "$SETUP_DIR/client" ]; then
        echo "Client directory not found at $SETUP_DIR/client"
        return 1
    fi
    
    cd "$SETUP_DIR/client"
    
    RUST_LOG=info cargo run --release -- claim-btc \\
        --seller-btc-key "\$SELLER_BTC_PRIVKEY" \\
        --buyer-btc-pubkey "\$BUYER_BTC_PUBKEY" \\
        --secret "\$secret" \\
        --secret-hash "\$secret_hash" \\
        --lock-txid "\$lock_txid" \\
        --lock-vout 0 \\
        --timeout "\$HTLC_TIMEOUT"
}

# Helper function to stop all services
stop_services() {
    echo "Stopping all demo services..."
    
    # Stop Bitcoin
    if bitcoin-cli -regtest -datadir="\$BTC_DATA_DIR" stop 2>/dev/null; then
        echo "Bitcoin stopped"
    else
        echo "Bitcoin was not running or failed to stop gracefully"
        # Force kill if needed
        pkill -f "bitcoind.*regtest" 2>/dev/null || true
    fi
    
    # Stop Hardhat
    if [ -f "$SETUP_DIR/agent/eth/hardhat.pid" ]; then
        local hardhat_pid=\$(cat "$SETUP_DIR/agent/eth/hardhat.pid")
        if ps -p "\$hardhat_pid" > /dev/null 2>&1; then
            kill "\$hardhat_pid" && echo "Hardhat stopped"
        fi
        rm -f "$SETUP_DIR/agent/eth/hardhat.pid"
    fi
    
    echo "All services stopped"
}

echo "Demo configuration loaded!"
echo "Available commands:"
echo "  run_demo           - Run the full automated atomic swap demo"
echo "  seller_commit      - Seller commits to mint (requires secret hash)"
echo "  seller_claim_btc   - Seller claims Bitcoin (requires secret, hash, txid)"
echo "  stop_services      - Stop all running services"
echo ""
echo "Bitcoin RPC: \$BTC_RPC_URL"
echo "Ethereum RPC: \$ETH_RPC_URL"
echo "NFT Contract: \$NFT_CONTRACT_ADDRESS"
EOF
    
    chmod +x "$SETUP_DIR/demo_config.sh"
    
    success "Test accounts and configuration created!"
}

verify_setup() {
    log "Verifying setup..."
    
    # Check Bitcoin
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
    
    if [ -f "$SETUP_DIR/target/release/crosschain-secret-mint" ] || [ -f "$SETUP_DIR/target/release/client" ]; then
        log "Rust client: Built successfully"
    else
        warn "Rust client binary not found, but build may have completed"
    fi
    
    success "Setup verification completed!"
}

print_usage_instructions() {
    echo
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}  Setup Complete! 🚀${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo
    echo -e "${BLUE}To run the demo:${NC}"
    echo
    echo -e "1. ${YELLOW}Source the demo configuration:${NC}"
    echo "   source ./demo_config.sh"
    echo
    echo -e "2. ${YELLOW}Run the full automated demo:${NC}"
    echo "   run_demo"
    echo
    echo -e "3. ${YELLOW}Or run individual steps:${NC}"
    echo "   # Start monitoring (optional):"
    echo "   RUST_LOG=info cargo run --release -- monitor --eth-key \$BUYER_ETH_PRIVKEY --nft-contract \$NFT_CONTRACT_ADDRESS"
    echo
    echo "   # In separate terminals, follow the step-by-step instructions from the buyer's output"
    echo
    echo -e "${BLUE}Configuration saved to:${NC} demo_config.sh"
    echo -e "${BLUE}Setup log saved to:${NC} setup.log"
    echo -e "${BLUE}Bitcoin data directory:${NC} $BITCOIN_DATA_DIR"
    echo
    echo -e "${YELLOW}Services running:${NC}"
    echo "  • Bitcoin regtest: http://localhost:18443"
    echo "  • Ethereum (Hardhat): http://localhost:8545"
    if [ -f "$SETUP_DIR/agent/eth/contract_address.txt" ]; then
        echo "  • NFT Contract: $(cat "$SETUP_DIR/agent/eth/contract_address.txt")"
    fi
    echo
    echo -e "${YELLOW}To stop services:${NC}"
    echo "  stop_services  # (after sourcing demo_config.sh)"
    echo "  # Or manually:"
    echo "  bitcoin-cli -regtest -datadir=\"$BITCOIN_DATA_DIR\" stop"
    echo "  kill \$(cat agent/eth/hardhat.pid 2>/dev/null) 2>/dev/null || true"
    echo
    echo -e "${YELLOW}Note:${NC} Bitcoin data is stored in project directory: $BITCOIN_DATA_DIR"
}

cleanup() {
    log "Cleaning up on exit..."
}

trap cleanup EXIT

main "$@"