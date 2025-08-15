# Crosschain Secret Mint

A cross-chain system where a Bitcoin payment unlocks NFT minting on Ethereum or Solana through shared secrets.

## High-Level Flow (BTC<->ETH)

### Step 1: Buyer Locks Bitcoin

- Buyer generates secret and creates hash
- Buyer creates Bitcoin script: funds claimable by seller if seller knows secret
- Bitcoin is locked in this script

### Step 2: Seller Commits on Ethereum  

- Seller sees Bitcoin commitment with hash
- Seller calls `commitForMint(hash, tokenId, price)` on NFT contract
- NFT is reserved for this hash

### Step 3: Buyer Reveals and Mints

- Buyer calls `mintWithSecret(secret, tokenId)` on Ethereum
- Contract verifies secret matches hash and mints NFT
- Secret is now revealed on Ethereum

### Step 4: Seller Claims Bitcoin

- Seller sees revealed secret from Ethereum transaction
- Seller uses secret to claim Bitcoin from the script
