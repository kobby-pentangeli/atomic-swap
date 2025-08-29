#!/bin/bash

export PATH="/root/.local/share/solana/install/active_release/bin:$PATH"

exec solana-test-validator --reset --bind-address 0.0.0.0 --rpc-port 8899 --ledger /app/.solana-ledger --log --clone metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s --clone-upgradeable-program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s --url https://api.mainnet-beta.solana.com