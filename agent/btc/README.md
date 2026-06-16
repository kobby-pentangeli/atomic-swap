# btc-htlc

The Bitcoin side of the [Atomic Swap](../../README.md): a Hash Time Locked Contract (HTLC) as a Pay-to-Witness-Script-Hash (P2WSH) output. It is a small, dependency-light library. The `client` builds the funding, claim, and refund transactions around it.

## The script

A single witness script with two spend paths:

```text
OP_IF
    OP_SHA256 <secret_hash> OP_EQUALVERIFY <seller_pubkey> OP_CHECKSIG
OP_ELSE
    <timeout_height> OP_CHECKLOCKTIMEVERIFY OP_DROP <buyer_pubkey> OP_CHECKSIG
OP_ENDIF
```

- **Reveal path** (seller): spend by presenting the 32-byte secret whose `SHA256` equals `secret_hash`, plus the seller's signature.
- **Timeout path** (buyer): after the absolute block height `timeout_height` (`OP_CHECKLOCKTIMEVERIFY`), the buyer reclaims with their signature. The spending input must keep `nSequence` non-final for `OP_CLTV` to apply.

The timeout is an **absolute** block height. The client derives it from the chain tip at lock time and persists it, so the lock, claim, and refund all reconstruct one identical script.

## API

- `Contract` — the built HTLC: its `script`, P2WSH `address()`, `verify_secret()`, `create_witness()` for either spend path, `predict_input_weight()` for fee estimation, and `script_hash()`.
- `HtlcParams` / `HtlcCondition` — the inputs to `Contract::new`, and the `Reveal { secret }` / `Timeout` spend selector.
- `generate_random_secret()` / `generate_random_secret_hex()`, `hash_secret()`, `hex_to_secret()` — secret generation and `SHA256` hashing helpers. The secret is 32 bytes throughout.

```rust
use btc_htlc::{Contract, HtlcParams, generate_random_secret, hash_secret};
use bitcoin::{Network, PublicKey};

fn build(seller: PublicKey, buyer: PublicKey, timeout_height: u32) -> Contract {
    let secret = generate_random_secret();
    Contract::new(HtlcParams {
        secret_hash: hash_secret(&secret),
        seller,
        buyer,
        timeout: timeout_height,
        network: Network::Regtest,
    })
}
```

The spend paths are covered by tests that run the locking script through the consensus interpreter (`bitcoinconsensus`), including the reveal and timeout paths and their failure modes (wrong secret, premature timeout, tampered witness).

## License

Licensed under either [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT) at your option.
