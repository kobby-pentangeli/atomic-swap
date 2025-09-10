#!/bin/bash

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
    echo "  > Bitcoin regtest: http://localhost:18443"
    echo "  > Ethereum (Hardhat): http://localhost:8545"
    echo "  > Solana test validator: http://localhost:8899"
    if [ -f "$SETUP_DIR/agent/eth/contract_address.txt" ]; then
        echo "   Ethereum NFT contract addr: $(cat "$SETUP_DIR/agent/eth/contract_address.txt")"
    fi
    if [ -f "$SETUP_DIR/agent/sol/program_id.txt" ]; then
        echo "   Solana NFT program ID: $(cat "$SETUP_DIR/agent/sol/program_id.txt")"
    fi
    echo
    echo -e "${YELLOW}To stop services:${NC}"
    echo "  stop_services  # (after sourcing atomic_swap.sh)"
    echo "  # Or manually:"
    echo "  bitcoin-cli -regtest -datadir=\"$BITCOIN_DATA_DIR\" stop"
    echo "  kill \$(cat agent/eth/hardhat.pid 2>/dev/null) 2>/dev/null || true"
    echo "  kill \$(cat agent/sol/solana.pid 2>/dev/null) 2>/dev/null || true"
    echo
    echo -e "${YELLOW}Note:${NC} Bitcoin data is stored in project directory: $BITCOIN_DATA_DIR"
    echo
}