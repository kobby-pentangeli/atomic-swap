#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SETUP_DIR="/app"
BITCOIN_DATA_DIR="$SETUP_DIR/.bitcoin"
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

wait_for_bitcoin() {
    local max_attempts=30
    local attempt=1
    log "Waiting for Bitcoin to start..."
    while [ $attempt -le $max_attempts ]; do
        if bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getnetworkinfo &>/dev/null; then
            success "Bitcoin is ready!"
            return 0
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done
    error "Bitcoin failed to start within $((max_attempts * 2)) seconds"
    return 1
}

wait_for_ethereum() {
    local max_attempts=30
    local attempt=1
    log "Waiting for Ethereum node to start..."
    while [ $attempt -le $max_attempts ]; do
        if curl -s -X POST -H 'Content-Type: application/json' \
            --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
            http://ethereum:8545 &>/dev/null; then
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

wait_for_solana() {
    local max_attempts=60
    local attempt=1
    log "Waiting for Solana test validator to start..."
    
    while [ $attempt -le 10 ]; do
        if nc -z solana 8899 2>/dev/null; then
            log "Solana port 8899 is open"
            break
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -s -X POST http://solana:8899 \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","id":1,"method":"getVersion"}' 2>/dev/null | grep -q "result"; then
            success "Solana RPC is responding!"
            
            sleep 5
            
            if solana cluster-version --url http://solana:8899 2>/dev/null; then
                success "Solana test validator is fully ready!"
                return 0
            fi
        fi
        
        if curl -s http://solana:8899/health 2>/dev/null | grep -q "ok"; then
            log "Solana health check passed"
            sleep 3
            if solana cluster-version --url http://solana:8899 2>/dev/null; then
                success "Solana test validator is ready!"
                return 0
            fi
        fi
        
        echo -n "."
        sleep 3
        ((attempt++))
    done
    
    log "Debug: Attempting direct curl to Solana RPC..."
    curl -v http://solana:8899 2>&1 | head -20
    
    error "Solana test validator failed to start within $((max_attempts * 3)) seconds"
    return 1
}

setup_bitcoin() {
    log "Setting up Bitcoin wallet..."
    if ! bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest listwallets | grep -q "testwallet"; then
        bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest createwallet "testwallet"
    fi
    log "Generating initial blocks..."
    address=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getnewaddress "initial")
    bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest generatetoaddress 101 "$address"
}

setup_ethereum() {
    log "Setting up Ethereum development environment..."
    
    cd "$SETUP_DIR/agent/eth"

    # Clean and reinstall dependencies
    log "Ensuring correct dependencies..."
    rm -rf node_modules
    npm install --silent
    
    log "Compiling smart contracts..."
    npx hardhat compile
    
    log "Deploying NFT contract with Ignition..."
    # npx hardhat ignition deploy ignition/modules/NFTSecretMint.ts --network localhost
    npx hardhat ignition deploy ignition/modules/NFTSecretMint.ts

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

setup_solana() {
    # Ensure Solana tools are available
    export PATH="/root/.local/share/solana/install/active_release/bin:$PATH"

    DEFAULT_SIGNER="/root/.config/solana/id.json"

    log "Generating Solana keypairs..."

    if [ ! -f "$DEFAULT_SIGNER" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile $DEFAULT_SIGNER
    fi

    if [ ! -f "$SETUP_DIR/buyer-keypair.json" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile $SETUP_DIR/buyer-keypair.json
    fi
    
    if [ ! -f "$SETUP_DIR/seller-keypair.json" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile $SETUP_DIR/seller-keypair.json
    fi
    
    local default_signer=$(solana-keygen pubkey $DEFAULT_SIGNER)
    local buyer_pubkey=$(solana-keygen pubkey $SETUP_DIR/buyer-keypair.json)
    local seller_pubkey=$(solana-keygen pubkey $SETUP_DIR/seller-keypair.json)
    
    log "Funding Solana accounts..."
    solana airdrop 20 "$default_signer" --url http://solana:8899
    solana airdrop 10 "$buyer_pubkey" --url http://solana:8899
    solana airdrop 10 "$seller_pubkey" --url http://solana:8899
    
    log "Buyer Solana address: $buyer_pubkey"
    log "Seller Solana address: $seller_pubkey"

    if [ -d "$SETUP_DIR/agent/sol" ]; then
        log "Building and deploying Solana program..."
        cd "$SETUP_DIR/agent/sol"
        
        log "Syncing Anchor keys..."
        anchor keys sync
        
        log "Building Anchor program..."
        anchor build
        
        log "Deploying program to local validator..."
        anchor deploy --provider.cluster http://solana:8899
        
        # Extract program ID
        if [ -f "target/deploy/sol_htlc-keypair.json" ]; then
            local program_id=$(solana-keygen pubkey target/deploy/sol_htlc-keypair.json)
            echo "$program_id" > program_id.txt
            log "Program deployed with ID: $program_id"
        else
            warn "Program keypair not found, checking Anchor.toml..."
            local program_id=$(grep -o 'sol_htlc = "[^"]*"' Anchor.toml | cut -d'"' -f2)
            if [ -n "$program_id" ]; then
                echo "$program_id" > program_id.txt
                log "Program ID from Anchor.toml: $program_id"
            else
                error "Could not determine program ID. Check anchor build output."
            fi
        fi
        
        cd "$SETUP_DIR"
    else
        warn "Solana agent directory not found at $SETUP_DIR/agent/sol, skipping program deployment"
        echo "11111111111111111111111111111112" > program_id.txt
        warn "Using placeholder program ID. Deploy your actual program and update SOL_PROGRAM_ID"
    fi
    
    success "Solana environment ready!"
}

generate_test_accounts() {
    log "Generating test accounts and keys..."
    log "Generating Bitcoin test accounts..."

    # Build the xpriv derivation binary if needed
    local derive_binary="$SETUP_DIR/target/release/derive_privkey"
    
    if [ ! -f "$derive_binary" ]; then
        log "Building key derivation helper..."
        cd "$SETUP_DIR"
        if ! cargo build --release --bin derive_privkey 2>&1 | tee -a "$LOG_FILE"; then
            error "Failed to build derive_privkey binary"
            return 1
        fi
    fi

    if [ ! -x "$derive_binary" ]; then
        log "Making derive_privkey binary executable..."
        chmod +x "$derive_binary" || error "Failed to make derive_privkey executable"
    fi
    
    # Test the binary works
    log "Testing derive_privkey binary..."
    if "$derive_binary" 2>/dev/null; then
        log "derive_privkey binary shows expected usage message"
    fi

    local buyer_btc_address seller_btc_address
    local buyer_btc_privkey seller_btc_privkey
    local buyer_btc_pubkey seller_btc_pubkey

    if buyer_btc_address=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getnewaddress "buyer" 2>/dev/null); then
        if addr_info=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getaddressinfo "$buyer_btc_address" 2>/dev/null); then
            buyer_btc_pubkey=$(echo "$addr_info" | jq -r .pubkey)
            
            # Get derivation path
            local hdkeypath=$(echo "$addr_info" | jq -r .hdkeypath)
            
            # Get the wallet's master private key directly
            local wallet_info=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getwalletinfo)
            local wallet_name=$(echo "$wallet_info" | jq -r .walletname)
            
            # Get descriptors with private keys
            local descriptors=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest listdescriptors true)
            
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

            local desc=$(echo "$descriptors" | jq -r --arg prefix "$path_prefix" '.descriptors[] | select(.desc | contains($prefix)) | select(.desc | test("/0/\\*")) | .desc' | head -1)
            
            if [[ -n "$desc" ]]; then
                log "Found descriptor for buyer: $desc"
                local base_xpriv=""
                
                base_xpriv=$(echo "$desc" | sed -n 's/.*(\[.*\]\([a-zA-Z0-9]*\)\/.*/\1/p')
                
                if [[ -z "$base_xpriv" ]]; then
                    base_xpriv=$(echo "$desc" | grep -oE 'tprv[a-zA-Z0-9]+')
                fi
                
                if [[ -z "$base_xpriv" ]]; then
                    base_xpriv=$(echo "$desc" | sed -n 's/.*]\([^/]*\)\/.*/\1/p')
                fi
                
                log "Extracted base_xpriv: ${base_xpriv:0:10}... hdkeypath: $hdkeypath"
                
                if [[ -n "$base_xpriv" && -n "$hdkeypath" ]]; then
                    log "Attempting to derive buyer private key..."
                    if buyer_btc_privkey=$("$derive_binary" "$base_xpriv" "$hdkeypath" 2>&1); then
                        log "Buyer private key derived successfully"
                    else
                        log "derive_privkey output: $buyer_btc_privkey"
                        error "Failed to derive buyer private key"
                    fi
                else
                    error "Failed to extract xpriv ($base_xpriv) or hdkeypath ($hdkeypath) for buyer"
                fi
            else
                error "Failed to find appropriate descriptor for buyer. Available descriptors: $(echo "$descriptors" | jq -c '.descriptors[].desc')"
            fi
        else
            error "Failed to get buyer address info"
        fi
    else
        error "Failed to generate buyer Bitcoin address"
    fi

    if seller_btc_address=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getnewaddress "seller" 2>/dev/null); then
        if addr_info=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getaddressinfo "$seller_btc_address" 2>/dev/null); then
            seller_btc_pubkey=$(echo "$addr_info" | jq -r .pubkey)
            
            local hdkeypath=$(echo "$addr_info" | jq -r .hdkeypath)
            
            local descriptors=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest listdescriptors true)
            
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
            
            local desc=$(echo "$descriptors" | jq -r --arg prefix "$path_prefix" '.descriptors[] | select(.desc | contains($prefix)) | select(.desc | test("/0/\\*")) | .desc' | head -1)
            
            if [[ -n "$desc" ]]; then
                log "Found descriptor for seller: $desc"
                local base_xpriv=""
                base_xpriv=$(echo "$desc" | grep -oE 'tprv[a-zA-Z0-9]+')
                
                if [[ -z "$base_xpriv" ]]; then
                    base_xpriv=$(echo "$desc" | sed -n 's/.*(\([^)]*\)).*/\1/p' | grep -oE 'tprv[a-zA-Z0-9]+')
                fi
                
                log "Extracted base_xpriv: ${base_xpriv:0:10}... hdkeypath: $hdkeypath"
                
                if [[ -n "$base_xpriv" && -n "$hdkeypath" ]]; then
                    log "Attempting to derive seller private key..."
                    if seller_btc_privkey=$("$derive_binary" "$base_xpriv" "$hdkeypath" 2>&1); then
                        log "Seller private key derived successfully"
                    else
                        log "derive_privkey output: $seller_btc_privkey"
                        error "Failed to derive seller private key"
                    fi
                else
                    error "Failed to extract xpriv ($base_xpriv) or hdkeypath ($hdkeypath) for seller"
                fi
            else
                error "Failed to find appropriate descriptor for seller. Available descriptors: $(echo "$descriptors" | jq -c '.descriptors[].desc')"
            fi
        else
            error "Failed to get seller address info"
        fi
    else
        error "Failed to generate seller Bitcoin address"
    fi
    
    log "Funding buyer Bitcoin address..."
    bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest generatetoaddress 5 "$buyer_btc_address" > /dev/null
    bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest generatetoaddress 1 "$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getnewaddress)" > /dev/null
    
    local buyer_eth_privkey="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    local buyer_eth_address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    local seller_eth_privkey="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    local seller_eth_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    
    local contract_address="N/A"
    if [ -f "$SETUP_DIR/agent/eth/contract_address.txt" ]; then
        contract_address=$(cat "$SETUP_DIR/agent/eth/contract_address.txt")
    fi
    
    log "Creating demo configuration..."

    local program_id="11111111111111111111111111111112"
    if [ -f "$SETUP_DIR/agent/sol/program_id.txt" ]; then
        program_id=$(cat "$SETUP_DIR/agent/sol/program_id.txt")
    elif [ -f "$SETUP_DIR/program_id.txt" ]; then
        program_id=$(cat "$SETUP_DIR/program_id.txt")
    fi

    cat > "$SETUP_DIR/atomic_swap.sh" << EOF
#!/bin/bash

# Cross-Chain Secret Mint Demo Configuration
# Generated by setup.sh on $(date)

# Bitcoin Configuration
export BTC_RPC_URL="http://bitcoin:18443"
export BTC_RPC_USER="user"
export BTC_RPC_PASSWORD="password"
export BTC_NETWORK="regtest"
export BTC_DATA_DIR="$BITCOIN_DATA_DIR"

# Ethereum Configuration  
export ETH_RPC_URL="http://ethereum:8545"
export NFT_CONTRACT_ADDRESS="$contract_address"

# Solana Configuration
export SOL_RPC_URL="http://solana:8899"
export SOL_WS_URL="ws://solana:8900"
export SOL_PROGRAM_ID="$program_id"

# Buyer Keys
export BUYER_BTC_PRIVKEY="$buyer_btc_privkey"
export BUYER_BTC_ADDRESS="$buyer_btc_address"
export BUYER_BTC_PUBKEY="$buyer_btc_pubkey"
export BUYER_ETH_PRIVKEY="$buyer_eth_privkey"
export BUYER_ETH_ADDRESS="$buyer_eth_address"
export BUYER_SOL_KEYPAIR="buyer-keypair.json"

# Seller Keys
export SELLER_BTC_PRIVKEY="$seller_btc_privkey"
export SELLER_BTC_PUBKEY="$seller_btc_pubkey"
export SELLER_BTC_ADDRESS="$seller_btc_address"
export SELLER_ETH_PRIVKEY="$seller_eth_privkey"
export SELLER_ETH_ADDRESS="$seller_eth_address"
export SELLER_SOL_KEYPAIR="seller-keypair.json"

# Demo Parameters
export BTC_AMOUNT="100000"  # 0.001 BTC in satoshis
export ETH_NFT_PRICE="1000000000000000000"  # 1 ETH in wei
export SOL_NFT_PRICE="1000000000"  # 1 SOL in lamports
export TOKEN_ID="1"
export METADATA_URI="https://example.com/nft/1.json"
export NFT_NAME="Demo NFT"
export NFT_SYMBOL="DEMO"
export HTLC_TIMEOUT="144"  # blocks

# Step 1: Lock bitcoin
lock_btc() {
    echo "Starting Cross-Chain Atomic Swap..."
    echo "Generating initial blocks and funding the buyer address..."

    bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest generatetoaddress 101 "$buyer_btc_address"
    
    RUST_LOG=info ./target/release/client lock-btc \\
        --btc-rpc "\$BTC_RPC_URL" \\
        --btc-user "\$BTC_RPC_USER" \\
        --btc-pass "\$BTC_RPC_PASSWORD" \\
        --btc-network "\$BTC_NETWORK" \\
        --buyer-btc-key "\$BUYER_BTC_PRIVKEY" \\
        --seller-btc-pubkey "\$SELLER_BTC_PUBKEY" \\
        --btc-amount "\$BTC_AMOUNT" \\
        --timeout "\$HTLC_TIMEOUT"
}

# Commit NFT with shared secret
commit_for_mint() {
    local chain="\$1"
    local secret_hash="\$2"
    
    if [ -z "\$chain" ] || [ -z "\$secret_hash" ]; then
        echo "Usage: commit_for_mint --chain <eth|sol> <SECRET_HASH>"
        echo "  or:  commit_for_mint <SECRET_HASH> --chain <eth|sol>"
        return 1
    fi
    
    # Handle argument order flexibility
    if [ "\$chain" = "--chain" ]; then
        chain="\$2"
        secret_hash="\$3"
    elif [ "\$secret_hash" = "--chain" ]; then
        secret_hash="\$1"
        chain="\$3"
    fi
    
    case "\$chain" in
        "eth")
            RUST_LOG=info ./target/release/client commit-for-mint \\
                --chain "eth" \\
                --eth-rpc "\$ETH_RPC_URL" \\
                --seller-eth-key "\$SELLER_ETH_PRIVKEY" \\
                --nft-contract "\$NFT_CONTRACT_ADDRESS" \\
                --secret-hash "\$secret_hash" \\
                --token-id "\$TOKEN_ID" \\
                --nft-price "\$ETH_NFT_PRICE" \\
                --buyer-address "\$BUYER_ETH_ADDRESS" \\
                --metadata-uri "\$METADATA_URI"
            ;;
        "sol")
            RUST_LOG=info ./target/release/client commit-for-mint \\
                --chain "sol" \\
                --sol-rpc "\$SOL_RPC_URL" \\
                --sol-ws "\$SOL_WS_URL" \\
                --seller-sol-keypair "\$SELLER_SOL_KEYPAIR" \\
                --program-id "\$SOL_PROGRAM_ID" \\
                --name "\$NFT_NAME" \\
                --symbol "\$NFT_SYMBOL" \\
                --secret-hash "\$secret_hash" \\
                --token-id "\$TOKEN_ID" \\
                --nft-price "\$SOL_NFT_PRICE" \\
                --metadata-uri "\$METADATA_URI"
            ;;
        *)
            echo "Error: Invalid chain '\$chain'. Use 'eth' or 'sol'"
            return 1
            ;;
    esac
}

# Mint the NFT with shared secret
mint_with_secret() {
    local chain="\$1"
    local secret="\$2"
    
    if [ -z "\$chain" ] || [ -z "\$secret" ]; then
        echo "Usage: mint_with_secret --chain <eth|sol> <SECRET>"
        echo "  or:  mint_with_secret <SECRET> --chain <eth|sol>"
        return 1
    fi
    
    # Handle argument order flexibility
    if [ "\$chain" = "--chain" ]; then
        chain="\$2"
        secret="\$3"
    elif [ "\$secret" = "--chain" ]; then
        secret="\$1"
        chain="\$3"
    fi
    
    case "\$chain" in
        "eth")
            RUST_LOG=info ./target/release/client mint-with-secret \\
                --chain "eth" \\
                --eth-rpc "\$ETH_RPC_URL" \\
                --buyer-eth-key "\$BUYER_ETH_PRIVKEY" \\
                --nft-contract "\$NFT_CONTRACT_ADDRESS" \\
                --secret "\$secret" \\
                --token-id "\$TOKEN_ID"
            ;;
        "sol")
            RUST_LOG=info ./target/release/client mint-with-secret \\
                --chain "sol" \\
                --sol-rpc "\$SOL_RPC_URL" \\
                --sol-ws "\$SOL_WS_URL" \\
                --buyer-sol-keypair "\$BUYER_SOL_KEYPAIR" \\
                --program-id "\$SOL_PROGRAM_ID" \\
                --secret "\$secret" \\
                --token-id "\$TOKEN_ID"
            ;;
        *)
            echo "Error: Invalid chain '\$chain'. Use 'eth' or 'sol'"
            return 1
            ;;
    esac
}

# Claim bitcoin after secret reveal
claim_btc() {
    local secret="\$1"
    local secret_hash="\$2"
    local lock_txid="\$3"
    
    if [ -z "\$secret" ] || [ -z "\$secret_hash" ] || [ -z "\$lock_txid" ]; then
        echo "Usage: claim_btc <SECRET> <SECRET_HASH> <LOCK_TXID>"
        return 1
    fi
    
    RUST_LOG=info ./target/release/client claim-btc \\
        --seller-btc-key "\$SELLER_BTC_PRIVKEY" \\
        --buyer-btc-pubkey "\$BUYER_BTC_PUBKEY" \\
        --secret "\$secret" \\
        --secret-hash "\$secret_hash" \\
        --lock-txid "\$lock_txid" \\
        --lock-vout 0 \\
        --timeout "\$HTLC_TIMEOUT"
}

echo "Demo configuration loaded!"
echo "Available commands:"
echo "  lock_btc           - Lock up Bitcoin in the HTLC"
echo "  commit_for_mint    - Seller commits to mint (requires secret hash)"
echo "  mint_with_secret   - Buyer mints the NFT with secret reveal"
echo "  claim_btc          - Seller claims Bitcoin (requires secret, hash, txid)"
echo ""
echo "Bitcoin RPC: \$BTC_RPC_URL"
echo "Ethereum RPC: \$ETH_RPC_URL"
echo "NFT Contract: \$NFT_CONTRACT_ADDRESS"
EOF
    
    chmod +x "$SETUP_DIR/atomic_swap.sh"
    
    success "Test accounts and configuration created!"
}

verify_setup() {
    log "Verifying setup..."

    if btc_info=$(bitcoin-cli -rpcconnect=bitcoin -rpcport=18443 -rpcuser=user -rpcpassword=password -regtest getblockchaininfo 2>/dev/null); then
        local block_count=$(echo "$btc_info" | jq -r .blocks)
        log "Bitcoin: $block_count blocks in regtest chain"
    else
        warn "Bitcoin verification failed"
    fi
    
    if curl -s -X POST -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        http://ethereum:8545 &>/dev/null; then
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

    if solana cluster-version --url http://solana:8899 &>/dev/null; then
        log "Solana: Test validator responding"
    else
        warn "Solana test validator not responding"
    fi
    
    if [ -f "buyer-keypair.json" ] && [ -f "seller-keypair.json" ]; then
        log "Solana keypairs: Generated successfully"
    else
        warn "Solana keypair files not found"
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
    echo -e "${GREEN}  Setup Complete! ${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo
    echo -e "${BLUE}To run the demo:${NC}"
    echo
    echo -e "1. ${YELLOW}Source the demo configuration:${NC}"
    echo "   source ./atomic_swap.sh"
    echo
    echo -e "2. ${YELLOW}Follow the rest of the demo guide${NC}"
    echo
    echo -e "${BLUE}Configuration saved to:${NC} atomic_swap.sh"
    echo -e "${BLUE}Setup log saved to:${NC} setup.log"
    echo -e "${BLUE}Bitcoin data directory:${NC} $BITCOIN_DATA_DIR"
    echo
    echo -e "${YELLOW}Services running:${NC}"
    echo "  > Bitcoin regtest: http://bitcoin:18443"
    echo "  > Ethereum (Hardhat): http://ethereum:8545"
    echo "  > Solana test validator: http://solana:8899"
    if [ -f "$SETUP_DIR/agent/eth/contract_address.txt" ]; then
        echo "   Ethereum NFT contract addr: $(cat "$SETUP_DIR/agent/eth/contract_address.txt")"
    fi
    if [ -f "$SETUP_DIR/agent/sol/program_id.txt" ]; then
        echo "   Solana NFT program ID: $(cat "$SETUP_DIR/agent/sol/program_id.txt")"
    fi
    echo
}

main() {
    log "Starting Cross-Chain Atomic Swap setup..."

    wait_for_bitcoin
    wait_for_ethereum
    wait_for_solana

    setup_bitcoin
    setup_ethereum
    setup_solana

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