# Security Policy

> This project is experimental and **not audited**. Do not use it with real funds, and do not deploy it to a production network, without thorough testing and an independent security audit.

## Reporting a Vulnerability

Please report security issues privately, **not** through public issues or pull requests. Use GitHub's [private vulnerability reporting](https://github.com/kobby-pentangeli/atomic-swap/security/advisories/new) ("Report a vulnerability" under the repository's *Security* tab). Include a description, the affected components, and a reproduction or proof of concept where possible. You will receive an acknowledgement, and we ask that you allow a reasonable window for a fix before any public disclosure.

## Threat Model

The protocol binds a Bitcoin payment and an NFT mint to a single 32-byte secret `s`. The buyer locks Bitcoin in a P2WSH HTLC behind `H = SHA256(s)`; the seller commits the NFT behind the same `H`; the buyer mints by revealing `s`; the seller reuses the now-public `s` to claim the Bitcoin. The same preimage satisfies `OP_SHA256` in the Bitcoin script, `sha256(abi.encodePacked(secret))` in the Ethereum contract, and `Sha256::digest(secret)` in the Solana program, so the hash is consistent across all three chains. The notes below state what the construction guarantees and what it does not.

### The two-timelock safety invariant

Atomicity rests on the ordering of two independent timelocks: the Bitcoin refund deadline (a block height) and the NFT-chain reveal deadline (a wall-clock window). The party who acts second must always hold the strictly longer window---once the buyer reveals `s` to mint the NFT, the seller must be able to claim the Bitcoin before the buyer's refund opens, otherwise a buyer could reveal-and-refund and walk away with both assets.

The client enforces this rather than trusting the operator. Valued at an assumed ten-minute Bitcoin block interval, the Bitcoin refund window must be at least **twice** the NFT reveal window: `MIN_BTC_WINDOW_BLOCKS = 288` (2 × 24h ÷ 10min). The first reveal-window's worth of time absorbs the delay between the lock and the seller's commit; the second guarantees the seller can confirm a Bitcoin claim after the latest possible reveal and before the refund unlocks. `lock-btc` refuses any window below the safe minimum with an actionable error, and `commit-for-mint` optionally re-validates against the buyer's refund deadline in the wall-clock domain (defense in depth, needing no Bitcoin RPC).

The reveal deadline is enforced on-chain on both NFT chains: Ethereum's `COMMITMENT_TIMEOUT` and Solana's `COMMITMENT_TIMEOUT_SECS` are both 24 hours, so the preimage can only become public within a bounded window, which is exactly what lets the Bitcoin refund be ordered safely after it.

**Assumption.** The conversion between block height and wall-clock time assumes Bitcoin's block interval stays near its ten-minute target over the roughly two-day swap. A sustained, severe slowdown in block production would stretch the real time the refund height represents; the 2× margin is sized to tolerate ordinary variance, not an adversarial reorg of the difficulty schedule.

### What the revealed secret exposes

The secret is private only until step (3). Minting the NFT publishes `s` in plaintext on the NFT chain---that publication is the whole mechanism, since it is what lets the seller claim the Bitcoin. Before the reveal, `s` is the one value the swap's safety depends on, and the client never logs it or any private key. After the reveal, `s` is public by design and carries no further secrecy. Replaying a once-public `s` does not break the swap: Ethereum permanently records revealed secrets (`revealedSecrets`) and bars a hash from backing two live commitments at once (`hashCommitted`); Solana's persistent mint PDA bars re-minting the same `token_id`. On Solana a once-revealed `s` could still back a *different* `token_id`, but doing so only mints that committer's own asset and pays that committer---it steals nothing from the original swap parties and does not affect Bitcoin atomicity.

### Front-running / MEV on open mints

The mint reveals `s` in plaintext calldata. When a commitment fixes no buyer (`buyer == address(0)` on Ethereum, `buyer == None` on Solana) the mint is open to anyone, so a searcher can observe the pending mint transaction and front-run it to capture the NFT; the minimum-commitment-time gate does not prevent this. For production swaps, bind a specific buyer in the commitment (`--buyer-address` on Ethereum, `--sol-buyer` on Solana) so that only that address can then mint, which closes the exposure. The interactive demo and the end-to-end tests exercise both open and bound mints.

### Residual griefing (inherent to HTLC swaps)

Some griefing is intrinsic and not a soundness hole: a seller may commit and then cancel before the buyer reveals, or a buyer may lock Bitcoin and never reveal. Neither lets a counterparty take both assets. The deadlines guarantee recovery: if the buyer never reveals, the seller cancels the (now-unmintable) commitment and the buyer refunds the Bitcoin after the locktime height; if the buyer reveals, they do so within the bounded window and the seller claims with margin. What such behavior can cost the counterparty is time and on-chain fees, the standard liveness/griefing trade-off of atomic swaps.

### Privileged operator (Ethereum)

The Ethereum contract is `Ownable2Step` and `Pausable`: the owner can pause commits and mints and uses two-step ownership transfer. Pausing is an availability control, not a way to seize a settled position, so it cannot redirect a payment or a minted token. The Solana program has no owner. Counterparties to a swap should be aware that an Ethereum collection owner can halt new activity on that contract.

### Contract-address and program-id pinning

Both legs of a swap must target the same deployment. The seller's commitment and the buyer's mint operate on a specific Ethereum contract address (`NFT_CONTRACT_ADDRESS`) or Solana program id (`SOL_PROGRAM_ID`); a mismatch means the buyer would be minting from a different contract than the one the seller committed to. The Solana program id is reconciled across `declare_id!` and `Anchor.toml`, and the deployed id must match the one the client is configured with. Verify the pinned address/id out of band before locking Bitcoin against it.

## Out of Scope

The following are the operator's responsibility and are not mitigated by the protocol:

- **Key management.** A leaked Bitcoin, Ethereum, or Solana key compromises that party's funds. Use a keystore or hardware signer (`forge`'s `--account`/`--ledger` for deployment); never hard-code keys or commit them.
- **RPC endpoint trust.** Use a trusted node. A malicious or faulty RPC can withhold or misreport chain state, including the block height the Bitcoin locktime is derived from and the reveal the seller watches for.
- **Mainnet deployment.** The contract and program are unaudited; the timelock margins are tuned for the documented assumptions, not adversarial mainnet conditions. Treat any mainnet use as experimental.
- **Mempool ordering / MEV.** Transaction ordering at the mempool level is outside the protocol's control; bind a buyer to remove the open-mint front-running exposure (see above).
