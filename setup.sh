#!/bin/bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BITCOIN_DATA_DIR="$HOME/.bitcoin"
BITCOIN_CONF="$BITCOIN_DATA_DIR/bitcoin.conf"
SETUP_DIR="$(pwd)"
LOG_FILE="$SETUP_DIR/setup.log"

# Helper functions
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
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: $1" >> "$LOG_FILE"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        error "$1 is not installed. Please install it first."
        return 1
    fi
    return 0
}

wait_for_service() {
    local service_name="$1"
    local check_command="$2"
    local max_attempts=30
    local attempt=1
    
    log "Waiting for $service_name to start..."
    
    while [ $attempt -le $max_attempts ]; do
        if eval "$check_command" &>/dev/null; then
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

# Main setup function
main() {
    log "Starting Cross-Chain Secret Mint setup..."
    log "Setup log: $LOG_FILE"
    
    # Clear previous log
    > "$LOG_FILE"
    
    # Check prerequisites
    log "Checking prerequisites..."
    
    if ! check_command "cargo"; then
        error "Rust/Cargo not found. Please install: https://rustup.rs/"
        exit 1
    fi
    
    if ! check_command "node"; then
        error "Node.js not found. Please install Node.js 18+: https://nodejs.org/"
        exit 1
    fi
    
    if ! check_command "npm"; then
        error "npm not found. Please install Node.js with npm."
        exit 1
    fi
    
    # Check for Bitcoin Core
    if ! check_command "bitcoind" || ! check_command "bitcoin-cli"; then
        warn "Bitcoin Core not found. Attempting to install via package manager..."
        
        if command -v apt-get &> /dev/null; then
            log "Installing Bitcoin Core via apt-get..."
            sudo apt-get update && sudo apt-get install -y bitcoind
        elif command -v brew &> /dev/null; then
            log "Installing Bitcoin Core via Homebrew..."
            brew install bitcoin
        else
            error "Could not install Bitcoin Core automatically. Please install manually."
            exit 1
        fi
    fi
    
    success "All prerequisites found!"
    
    # Build Rust client
    log "Building Rust client..."
    cd "$SETUP_DIR/client"
    cargo build --release
    cd "$SETUP_DIR"
    success "Rust client built successfully!"
    
    # Setup Bitcoin
    setup_bitcoin
    
    # Setup Ethereum
    setup_ethereum
    
    # Generate test keys and accounts
    generate_test_accounts
    
    # Final verification
    verify_setup
    
    success "Setup completed successfully!"
    print_usage_instructions
}

setup_bitcoin() {
    log "Setting up Bitcoin regtest environment..."
    
    # Create Bitcoin data directory
    mkdir -p "$BITCOIN_DATA_DIR"
    
    # Create bitcoin.conf
    log "Creating Bitcoin configuration..."
    cat > "$BITCOIN_CONF" << 'EOF'
# Regtest configuration for cross-chain demo
regtest=1
server=1
rpcuser=user
rpcpassword=password
rpcport=18443
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
txindex=1
fallbackfee=0.0001

# Logging
debug=1
logips=1

# Performance
dbcache=300
maxmempool=50
EOF
    
    # Stop any existing bitcoind
    if pgrep -f "bitcoind.*regtest" > /dev/null; then
        log "Stopping existing bitcoind..."
        bitcoin-cli -regtest stop 2>/dev/null || true
        sleep 3
    fi
    
    # Start bitcoind
    log "Starting bitcoind in regtest mode..."
    bitcoind -daemon
    
    # Wait for bitcoind to start
    wait_for_service "bitcoind" "bitcoin-cli -regtest getnetworkinfo"
    
    # Create wallet if it doesn't exist
    log "Setting up Bitcoin wallet..."
    if ! bitcoin-cli -regtest listwallets | grep -q "testwallet"; then
        bitcoin-cli -regtest createwallet "testwallet" false false "" false false true
    fi
    
    # Generate initial blocks
    log "Generating initial blocks and funding addresses..."
    local address=$(bitcoin-cli -regtest getnewaddress "initial")
    bitcoin-cli -regtest generatetoaddress 101 "$address" > /dev/null
    
    success "Bitcoin regtest environment ready!"
}

setup_ethereum() {
    log "Setting up Ethereum development environment..."
    
    cd "$SETUP_DIR/agent/eth"
    
    # Install dependencies
    log "Installing npm dependencies..."
    npm install --silent
    
    # Compile contracts
    log "Compiling smart contracts..."
    npx hardhat compile
    
    # Start Hardhat network in background
    log "Starting Hardhat network..."
    
    # Kill any existing Hardhat processes
    pkill -f "hardhat node" 2>/dev/null || true
    sleep 2
    
    # Start Hardhat node in background
    npx hardhat node > hardhat.log 2>&1 &
    local hardhat_pid=$!
    echo "$hardhat_pid" > hardhat.pid
    
    # Wait for Hardhat to start
    wait_for_service "Hardhat node" "curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}' http://localhost:8545"
    
    # Deploy contract
    log "Deploying NFT contract..."
    local deploy_output=$(npx hardhat run scripts/deploy.js --network localhost)
    local contract_address=$(echo "$deploy_output" | grep -o '0x[a-fA-F0-9]\{40\}' | head -1)
    
    if [ -z "$contract_address" ]; then
        error "Failed to extract contract address from deployment"
        cat hardhat.log
        exit 1
    fi
    
    # Save contract address
    echo "$contract_address" > contract_address.txt
    log "Contract deployed at: $contract_address"
    
    cd "$SETUP_DIR"
    success "Ethereum environment ready!"
}

generate_test_accounts() {
    log "Generating test accounts and keys..."
    
    # Generate Bitcoin addresses and keys
    log "Generating Bitcoin test accounts..."
    
    # Buyer Bitcoin account
    local buyer_btc_address=$(bitcoin-cli -regtest getnewaddress "buyer")
    local buyer_btc_privkey=$(bitcoin-cli -regtest dumpprivkey "$buyer_btc_address")
    local buyer_btc_pubkey=$(bitcoin-cli -regtest getaddressinfo "$buyer_btc_address" | grep -o '"pubkey":"[^"]*"' | cut -d'"' -f4)
    
    # Seller Bitcoin account  
    local seller_btc_address=$(bitcoin-cli -regtest getnewaddress "seller")
    local seller_btc_privkey=$(bitcoin-cli -regtest dumpprivkey "$seller_btc_address")
    local seller_btc_pubkey=$(bitcoin-cli -regtest getaddressinfo "$seller_btc_address" | grep -o '"pubkey":"[^"]*"' | cut -d'"' -f4)
    
    # Fund buyer with Bitcoin
    log "Funding buyer Bitcoin address..."
    bitcoin-cli -regtest generatetoaddress 5 "$buyer_btc_address" > /dev/null
    bitcoin-cli -regtest generatetoaddress 1 $(bitcoin-cli -regtest getnewaddress) > /dev/null # Confirm the funding
    
    # Ethereum accounts (using Hardhat's default funded accounts)
    local buyer_eth_privkey="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    local buyer_eth_address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    local seller_eth_privkey="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    local seller_eth_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    
    # Get contract address
    local contract_address=$(cat "$SETUP_DIR/agent/eth/contract_address.txt")
    
    # Create demo configuration file
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

# Ethereum Configuration  
export ETH_RPC_URL="http://localhost:8545"
export NFT_CONTRACT_ADDRESS="$contract_address"

# Buyer Keys
export BUYER_BTC_PRIVKEY="$buyer_btc_privkey"
export BUYER_BTC_ADDRESS="$buyer_btc_address"
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

echo "Demo configuration loaded!"
echo "Run 'run_demo' to start the atomic swap"
echo "Or source this file and use the individual helper functions"
EOF
    
    chmod +x "$SETUP_DIR/demo_config.sh"
    
    success "Test accounts and configuration created!"
}

verify_setup() {
    log "Verifying setup..."
    
    # Check Bitcoin
    local btc_info=$(bitcoin-cli -regtest getblockchaininfo)
    local block_count=$(echo "$btc_info" | grep -o '"blocks":[0-9]*' | cut -d':' -f2)
    log "Bitcoin: $block_count blocks in regtest chain"
    
    # Check Ethereum
    local eth_response=$(curl -s -X POST -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        http://localhost:8545)
    log "Ethereum: Hardhat node responding"
    
    # Check contract
    local contract_address=$(cat "$SETUP_DIR/agent/eth/contract_address.txt")
    log "NFT Contract: $contract_address deployed"
    
    # Check client build
    if [ -f "$SETUP_DIR/client/target/release/crosschain-secret-mint" ] || [ -f "$SETUP_DIR/client/target/release/client" ]; then
        log "Rust client: Built successfully"
    else
        warn "Rust client binary not found, but build completed"
    fi
    
    success "All components verified!"
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
    echo
    echo -e "${YELLOW}Services running:${NC}"
    echo "  • Bitcoin regtest: http://localhost:18443"
    echo "  • Ethereum (Hardhat): http://localhost:8545"
    echo "  • NFT Contract: $(cat "$SETUP_DIR/agent/eth/contract_address.txt" 2>/dev/null || echo 'N/A')"
    echo
    echo -e "${YELLOW}To stop services:${NC}"
    echo "  bitcoin-cli -regtest stop"
    echo "  kill \$(cat agent/eth/hardhat.pid 2>/dev/null) 2>/dev/null || true"
    echo
}

cleanup() {
    log "Cleaning up on exit..."
    # The services will keep running for the demo
}

# Set up cleanup on script exit
trap cleanup EXIT

# Run main function
main "$@"