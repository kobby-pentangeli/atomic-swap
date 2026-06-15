//! Interactive walk through the full atomic-swap lifecycle.
//!
//! Brings up local chains, then steps through buyer-locks-BTC -> seller-commits
//! -> buyer-reveals-and-mints -> seller-claims-BTC, narrating each step and
//! pausing between them so the swap can be observed end to end. It drives the
//! same [`AtomicSwap`] the integration tests use, so the demo and the gate stay
//! in lockstep.
//!
//! Usage:
//!   cargo run -p e2e --bin demo -- [--chain eth|sol] [--bound] [--yes]
//!
//!   --chain   NFT chain to settle on (default: eth)
//!   --bound   restrict the mint to the buyer (authorized-buyer binding)
//!   --yes     run without pausing between steps (non-interactive)

use std::io::{Write, stdin, stdout};

use anyhow::{Result, bail};
use e2e::{AtomicSwap, NftChain, SAFE_TIMEOUT};

struct Options {
    chain: NftChain,
    bound: bool,
    interactive: bool,
}

fn parse_options() -> Result<Options> {
    let mut chain = NftChain::Ethereum;
    let mut bound = false;
    let mut interactive = true;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chain" => {
                chain = match args.next().as_deref() {
                    Some("eth" | "ethereum") => NftChain::Ethereum,
                    Some("sol" | "solana") => NftChain::Solana,
                    other => bail!("invalid --chain value: {other:?} (use eth or sol)"),
                };
            }
            "--bound" => bound = true,
            "--yes" | "-y" => interactive = false,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(Options {
        chain,
        bound,
        interactive,
    })
}

fn print_help() {
    println!("cargo run -p e2e --bin demo -- [--chain eth|sol] [--bound] [--yes]");
    println!("  --chain   NFT chain to settle on (default: eth)");
    println!("  --bound   restrict the mint to the buyer (authorized-buyer binding)");
    println!("  --yes     run without pausing between steps (non-interactive)");
}

fn pause(interactive: bool) {
    if !interactive {
        return;
    }
    print!("\n  [press Enter to continue]");
    let _ = stdout().flush();
    let mut line = String::new();
    let _ = stdin().read_line(&mut line);
}

fn chain_label(chain: NftChain) -> &'static str {
    match chain {
        NftChain::Ethereum => "ethereum",
        NftChain::Solana => "solana",
    }
}

fn main() -> Result<()> {
    let opts = parse_options()?;
    let label = chain_label(opts.chain);

    println!("== Cross-chain atomic swap demo (NFT chain: {label}) ==\n");
    println!(
        "Bringing up local chains (bitcoind regtest, {} validator) and deploying.",
        if opts.chain == NftChain::Ethereum {
            "anvil"
        } else {
            "solana"
        }
    );
    println!("First run also builds the client and the SBF program; this can take a while.\n");

    let swap = AtomicSwap::setup(opts.chain)?;
    println!("[ready]");

    let seller_btc_before = swap.seller_btc_sats()?;
    pause(opts.interactive);

    println!("\nStep 1/4  Buyer locks Bitcoin in the HTLC");
    let lock = swap.lock_btc(SAFE_TIMEOUT)?;
    println!("  funding txid     {}", lock.txid);
    println!("  secret hash      {}", lock.secret_hash);
    println!("  refund height    {}", lock.timeout_height);
    println!(
        "  refund deadline  {} (unix; shared with the seller)",
        lock.btc_refund_deadline
    );
    pause(opts.interactive);

    println!("\nStep 2/4  Seller commits the NFT to the same secret hash");
    if opts.bound {
        println!("  (mint restricted to the authorized buyer)");
    }
    let commit = swap.commit(&lock.secret_hash, opts.bound)?;
    println!("  commit tx        {}", commit.tx_id);
    pause(opts.interactive);

    println!("\nStep 3/4  Buyer reveals the secret to mint the NFT");
    swap.advance_for_mint()?;
    let mint = swap.mint()?;
    println!("  mint tx          {}", mint.tx_id);
    println!("  secret revealed  {}", mint.secret_revealed);
    if let Some(owner) = swap.eth_token_owner()? {
        println!("  nft owner        {owner}");
    }
    pause(opts.interactive);

    println!("\nStep 4/4  Seller claims the Bitcoin using the revealed secret");
    let claim = swap.claim_btc(&mint.secret_revealed, &lock)?;
    println!("  claim tx         {}", claim.txid);

    let seller_btc_after = swap.seller_btc_sats()?;
    println!(
        "  seller BTC       {} -> {} sats",
        seller_btc_before, seller_btc_after
    );

    println!("\n== Swap complete ==");
    println!("The secret revealed on {label} unlocked the Bitcoin HTLC: the buyer holds the NFT");
    println!("and the seller holds the Bitcoin. The swap was atomic.");
    Ok(())
}
