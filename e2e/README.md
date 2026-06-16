# e2e

The end-to-end harness for the [Atomic Swap](../README.md), and the interactive demo built on it. It spins up real local chains and drives the real `client` binary through a complete swap.

## What it does

The harness spawns ephemeral local chains as child processes---`bitcoind -regtest`, `anvil`, and `solana-test-validator`---and tears them down on drop. It deploys the Foundry contract with `forge create` and loads the prebuilt Solana program (plus a vendored Metaplex fixture) into the validator at genesis, then runs every swap step by shelling out to the client with `-o json` and asserting on the structured result. Because each step goes through the real CLI boundary, the suite catches the integration faults that per-component tests behind a mock cannot.

A single `AtomicSwap` holds the lifecycle primitives, shared by the tests and the demo so they cannot drift, and a process-wide lock serializes swaps (independent of `--test-threads`).

## Running

The live tests are `#[ignore]`d, so `cargo test --workspace` compiles them but skips them. Run the matrix explicitly:

```bash
cargo test -p e2e -- --ignored
```

It sweeps both NFT chains × {successful swaps, refund-after-timeout, cancel-then-refund} × {open, bound} mints, plus the defection paths (unsafe timelock, premature refund, wrong secret, unauthorized mint, replay).

The same primitives back the interactive demo, which narrates the lifecycle and pauses between steps:

```bash
cargo run -p e2e --bin demo -- --chain eth   # or: --chain sol; add --bound or --yes
```

Both expect `bitcoind`, `anvil`, and `solana-test-validator` on `PATH`, and the program and contract built first. See the [Development Guide](../docs/development.md) for the full setup.

## License

Licensed under either [Apache-2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT) at your option.
