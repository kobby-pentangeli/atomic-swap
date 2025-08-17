use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{Amount, Network, PublicKey};
use bitcoincore_rpc::Auth;
use btc_htlc::{Contract as BtcContract, HtlcParams, generate_secret};
use clap::Parser;
use ethers::types::U256;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub mod btc;
pub mod cmd;
pub mod eth;
pub mod types;

use btc::BtcClient;
use cmd::Commands;
use eth::EthClient;
use types::{AtomicSwapConfig, ClaimBtcConfig, CommitForMintConfig, MonitorConfig, SwapEvent};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let cli = cmd::Cli::parse();

    match cli.command {
        Commands::AtomicSwap {
            btc_rpc,
            btc_user,
            btc_pass,
            btc_network,
            buyer_btc_key,
            seller_btc_pubkey,
            eth_rpc,
            buyer_eth_key,
            nft_contract,
            btc_amount,
            nft_price,
            token_id,
            metadata_uri,
            timeout,
        } => {
            run_atomic_swap(AtomicSwapConfig {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: parse_network(&btc_network)?,
                buyer_btc_key,
                seller_btc_pubkey,
                eth_rpc,
                buyer_eth_key,
                nft_contract: nft_contract.parse()?,
                btc_amount,
                nft_price,
                token_id,
                metadata_uri,
                timeout,
            })
            .await
        }
        Commands::CommitForMint {
            eth_rpc,
            seller_eth_key,
            nft_contract,
            secret_hash,
            token_id,
            nft_price,
            buyer_address,
            metadata_uri,
        } => {
            run_commit_for_mint(CommitForMintConfig {
                eth_rpc,
                seller_eth_key,
                nft_contract: nft_contract.parse()?,
                secret_hash: hex::decode(&secret_hash)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid secret hash length"))?,
                token_id,
                nft_price,
                buyer_address: buyer_address.map(|s| s.parse()).transpose()?,
                metadata_uri,
            })
            .await
        }
        Commands::ClaimBtc {
            btc_rpc,
            btc_user,
            btc_pass,
            btc_network,
            seller_btc_key,
            buyer_btc_pubkey,
            secret,
            secret_hash,
            lock_txid,
            lock_vout,
            timeout,
            destination,
        } => {
            let network = parse_network(&btc_network)?;

            run_claim_bitcoin(ClaimBtcConfig {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: network,
                seller_btc_key,
                buyer_btc_pubkey,
                secret: hex::decode(&secret)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid secret length"))?,
                secret_hash: hex::decode(&secret_hash)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid secret hash length"))?,
                lock_txid: lock_txid.parse()?,
                lock_vout,
                timeout,
                destination: destination
                    .map(|s| parse_btc_address(&s, network))
                    .transpose()?,
            })
            .await
        }
        Commands::Monitor {
            btc_rpc,
            btc_user,
            btc_pass,
            btc_network,
            eth_rpc,
            eth_key,
            nft_contract,
        } => {
            run_monitor(MonitorConfig {
                btc_rpc,
                btc_user,
                btc_pass,
                btc_network: parse_network(&btc_network)?,
                eth_rpc,
                eth_key,
                nft_contract: nft_contract.parse()?,
            })
            .await
        }
    }
}

async fn run_atomic_swap(config: AtomicSwapConfig) -> Result<()> {
    info!("Starting Cross-Chain Secret Mint Demo");
    info!("==========================================");

    let buyer_keypair = config.buyer_btc_key.parse::<Keypair>()?;
    let seller_pubkey: PublicKey = config.seller_btc_pubkey.parse()?;
    let buyer_pubkey = PublicKey::from(buyer_keypair.public_key());

    let (secret, secret_hash) = generate_secret();
    info!("Generated secret pair");
    info!("Secret: {}", hex::encode(secret));
    info!("Hash: {}", hex::encode(secret_hash.as_byte_array()));

    let contract_params = HtlcParams {
        secret_hash,
        seller: seller_pubkey,
        buyer: buyer_pubkey,
        timeout: config.timeout,
        network: config.btc_network,
    };
    let btc_contract = BtcContract::new(contract_params);
    let htlc_address = btc_contract.address();

    info!("HTLC Contract Created");
    info!("Address: {}", htlc_address);
    info!("Seller: {}", seller_pubkey);
    info!("Buyer: {}", buyer_pubkey);
    info!("Timeout: {} blocks", config.timeout);

    let auth = Auth::UserPass(config.btc_user, config.btc_pass);
    let btc_client = BtcClient::new(&config.btc_rpc, auth, config.btc_network, buyer_keypair)?;

    info!("Connected to Bitcoin {}", config.btc_network);

    let eth_client =
        EthClient::new(&config.eth_rpc, &config.buyer_eth_key, config.nft_contract).await?;

    info!("Connected to Ethereum");
    info!("Contract: {:?}", config.nft_contract);
    info!("Buyer: {:?}", eth_client.get_address());

    info!("\nStep 1: Locking Bitcoin in HTLC");
    info!("=====================================");

    let btc_amount = Amount::from_sat(config.btc_amount);
    let lock_txid = btc_client
        .lock_funds(&btc_contract, btc_amount)
        .await
        .context("Failed to lock Bitcoin funds")?;

    info!("Bitcoin locked successfully!");
    info!("Amount: {} BTC", btc_amount.to_btc());
    info!("TxID: {}", lock_txid);
    info!("HTLC: {}", htlc_address);

    info!("Waiting for Bitcoin confirmation...");
    let mut btc_confirmed = false;
    for i in 0..30 {
        // Wait up to 5 minutes
        tokio::time::sleep(Duration::from_secs(10)).await;

        let tx_info = btc_client.get_transaction_info(&lock_txid)?;
        if tx_info.confirmations > 0 {
            info!(
                "Bitcoin transaction confirmed ({} confirmations)",
                tx_info.confirmations
            );
            btc_confirmed = true;
            break;
        }

        if i % 6 == 0 {
            // Every minute
            info!("Still waiting... ({}/30 attempts)", i + 1);
        }
    }

    if !btc_confirmed {
        warn!("Bitcoin transaction not confirmed yet, continuing anyway...");
    }

    info!("\nStep 2: Information for Seller");
    info!("==================================");
    info!("The seller should now commit the NFT on Ethereum using:");
    info!("Secret Hash: {}", hex::encode(secret_hash.as_byte_array()));
    info!("Token ID: {}", config.token_id);
    info!("Price: {} wei", config.nft_price);
    info!("Metadata: {}", config.metadata_uri);
    info!("");
    info!("Seller command:");
    info!("cargo run -- commit-for-mint \\");
    info!("     --seller-eth-key <SELLER_ETH_KEY> \\");
    info!("     --nft-contract {} \\", config.nft_contract);
    info!(
        "     --secret-hash {} \\",
        hex::encode(secret_hash.as_byte_array())
    );
    info!("     --token-id {} \\", config.token_id);
    info!("     --nft-price {} \\", config.nft_price);
    info!("     --buyer-address {:?} \\", eth_client.get_address());
    info!("     --metadata-uri '{}'", config.metadata_uri);

    info!("\nWaiting for seller to commit NFT...");
    let mut commitment_found = false;
    for i in 0..60 {
        // Wait up to 10 minutes
        tokio::time::sleep(Duration::from_secs(10)).await;

        match eth_client.get_commitment(U256::from(config.token_id)).await {
            Ok(commitment) => {
                if commitment.is_active && commitment.secret_hash == *secret_hash.as_byte_array() {
                    info!("Seller commitment found!");
                    info!("Seller: {:?}", commitment.seller);
                    info!("Price: {} wei", commitment.price);
                    info!("Commit Time: {}", commitment.commit_time);
                    commitment_found = true;
                    break;
                }
            }
            Err(_) => {
                // No commitment yet, continue waiting
            }
        }

        if i % 6 == 0 {
            // Every minute
            info!("Still waiting for seller... ({}/60 attempts)", i + 1);
        }
    }

    if !commitment_found {
        error!("Seller commitment not found within timeout period");
        info!("The seller needs to commit the NFT first. Run the seller command above.");
        return Ok(());
    }

    info!("\nStep 3: Revealing Secret and Minting NFT");
    info!("===========================================");

    let can_mint = eth_client.can_mint_now(U256::from(config.token_id)).await?;
    if !can_mint {
        warn!("Cannot mint yet, waiting for minimum commitment time...");

        // Wait up to 5 minutes for the timing constraint
        for i in 0..30 {
            tokio::time::sleep(Duration::from_secs(10)).await;

            if eth_client.can_mint_now(U256::from(config.token_id)).await? {
                info!("Minimum commitment time has passed, can mint now!");
                break;
            }

            if i == 29 {
                return Err(anyhow::anyhow!("Timeout waiting for mint availability"));
            }
        }
    }

    let mint_tx = eth_client
        .mint_with_secret(secret, U256::from(config.token_id))
        .await
        .context("Failed to mint NFT")?;

    info!("NFT minted successfully!");
    info!("Transaction: {mint_tx:?}");
    info!("Secret revealed on Ethereum");

    info!("Waiting for Ethereum confirmation...");
    for i in 0..30 {
        // Wait up to 5 minutes
        tokio::time::sleep(Duration::from_secs(10)).await;

        let tx_info = eth_client.get_transaction_info(mint_tx).await?;
        if let Some(c) = tx_info.confirmations
            && c > 0
        {
            info!("Ethereum transaction confirmed ({c} confirmations)");
            break;
        }

        if i % 6 == 0 {
            // Every minute
            info!("Still waiting... ({}/30 attempts)", i + 1);
        }
    }

    info!("\nStep 4: Information for Seller to Claim Bitcoin");
    info!("=================================================");
    info!("The seller can now claim Bitcoin using the revealed secret:");
    info!("Secret:  {}", hex::encode(secret));
    info!("Secret Hash: {}", hex::encode(secret_hash.as_byte_array()));
    info!("Lock TxID: {lock_txid}");
    info!("Lock Vout: 0");
    info!("");
    info!("Seller command:");
    info!("   cargo run -- claim-btc \\");
    info!("     --seller-btc-key <SELLER_BTC_KEY> \\");
    info!("     --buyer-btc-pubkey {} \\", buyer_pubkey);
    info!("     --secret {} \\", hex::encode(secret));
    info!(
        "     --secret-hash {} \\",
        hex::encode(secret_hash.as_byte_array())
    );
    info!("     --lock-txid {} \\", lock_txid);
    info!("     --lock-vout 0 \\");
    info!("     --timeout {}", config.timeout);

    info!("\nDemo completed successfully!");
    info!("================================");

    Ok(())
}

async fn run_commit_for_mint(config: CommitForMintConfig) -> Result<()> {
    info!("Seller: Committing NFT for minting");
    info!("=====================================");

    let eth_client =
        EthClient::new(&config.eth_rpc, &config.seller_eth_key, config.nft_contract).await?;

    info!("Connected to Ethereum");
    info!("Contract: {:?}", config.nft_contract);
    info!("Seller: {:?}", eth_client.get_address());

    match eth_client.get_commitment(U256::from(config.token_id)).await {
        Ok(commitment) => {
            if commitment.is_active {
                error!("Token {} already has an active commitment", config.token_id);
                return Err(anyhow::anyhow!("Token already committed"));
            }
        }
        Err(_) => {
            // No existing commitment, proceed
        }
    }

    let tx_hash = eth_client
        .commit_for_mint(
            config.secret_hash,
            U256::from(config.token_id),
            U256::from(config.nft_price),
            config.buyer_address,
            config.metadata_uri.clone(),
        )
        .await?;

    info!("NFT commitment created successfully!");
    info!("Transaction: {tx_hash:?}");
    info!("Token ID: {}", config.token_id);
    info!("Secret Hash: {}", hex::encode(config.secret_hash));
    info!("Price: {} wei", config.nft_price);
    info!(
        "Buyer: {:?}",
        config
            .buyer_address
            .unwrap_or_else(|| "Any".parse().unwrap())
    );
    info!("Metadata: {}", config.metadata_uri);

    info!("Waiting for confirmation...");
    for i in 0..30 {
        tokio::time::sleep(Duration::from_secs(10)).await;

        let tx_info = eth_client.get_transaction_info(tx_hash).await?;
        if let Some(c) = tx_info.confirmations
            && c > 0
        {
            info!("Transaction confirmed ({c} confirmations)");
            break;
        }
        if i == 29 {
            warn!("Transaction not confirmed within timeout, but likely successful");
        }
    }
    info!("Commitment completed! The buyer can now reveal the secret to mint the NFT.");

    Ok(())
}

async fn run_claim_bitcoin(config: ClaimBtcConfig) -> Result<()> {
    info!("Seller: Claiming Bitcoin with revealed secret");
    info!("===============================================");

    let computed_hash = sha256::Hash::hash(&config.secret);
    if computed_hash.as_byte_array() != &config.secret_hash {
        return Err(anyhow::anyhow!("Secret does not match provided hash"));
    }

    info!("Secret verification passed");
    info!("Secret: {}", hex::encode(config.secret));
    info!("Hash: {}", hex::encode(config.secret_hash));

    let seller_keypair = config.seller_btc_key.parse::<Keypair>()?;
    let buyer_pubkey: PublicKey = config.buyer_btc_pubkey.parse()?;
    let seller_pubkey = PublicKey::from(seller_keypair.public_key());

    let contract_params = HtlcParams {
        secret_hash: sha256::Hash::from_byte_array(config.secret_hash),
        seller: seller_pubkey,
        buyer: buyer_pubkey,
        timeout: config.timeout,
        network: config.btc_network,
    };
    let btc_contract = BtcContract::new(contract_params);

    info!("HTLC Contract Details");
    info!("Address: {}", btc_contract.address());
    info!("Seller: {}", seller_pubkey);
    info!("Buyer: {}", buyer_pubkey);

    let auth = Auth::UserPass(config.btc_user, config.btc_pass);
    let btc_client = BtcClient::new(&config.btc_rpc, auth, config.btc_network, seller_keypair)?;

    info!("Connected to Bitcoin {}", config.btc_network);

    let claim_tx = btc_client
        .claim_funds(
            &btc_contract,
            &config.secret,
            config.lock_txid,
            config.lock_vout,
            config.destination.clone(),
        )
        .await?;

    info!("Bitcoin claimed successfully!");
    info!("Claim TxID: {}", claim_tx);
    info!("From HTLC: {}:{}", config.lock_txid, config.lock_vout);

    if let Some(dest) = config.destination {
        info!("To Address: {dest}");
    } else {
        info!("To Address: <seller's wallet>");
    }
    info!("Bitcoin claim completed! The cross-chain atomic swap is now fully complete.");

    Ok(())
}

async fn run_monitor(config: MonitorConfig) -> Result<()> {
    info!("Starting Cross-Chain Event Monitor");
    info!("====================================");

    let auth = Auth::UserPass(config.btc_user, config.btc_pass);
    // TODO: Use actual keypair
    let dummy_keypair = Keypair::new(&Secp256k1::new(), &mut rand::thread_rng());

    let btc_client = Arc::new(BtcClient::new(
        &config.btc_rpc,
        auth,
        config.btc_network,
        dummy_keypair,
    )?);
    let eth_client =
        Arc::new(EthClient::new(&config.eth_rpc, &config.eth_key, config.nft_contract).await?);

    info!("Connected to Bitcoin {}", config.btc_network);
    info!("Connected to Ethereum");
    info!("Contract: {:?}", config.nft_contract);

    let (tx, mut rx) = mpsc::channel::<String>(100);

    let btc_client_clone = btc_client.clone();
    let tx_btc = tx.clone();
    let btc_monitor = tokio::spawn(async move {
        if let Err(e) = btc_client_clone
            .monitor_blocks(move |height| {
                let _ = tx_btc.try_send(format!("New Bitcoin block: {height}"));
                Ok(())
            })
            .await
        {
            error!("Bitcoin monitoring error: {e}");
        }
    });

    let eth_client_clone = eth_client.clone();
    let tx_eth = tx.clone();
    let eth_monitor = tokio::spawn(async move {
        if let Err(e) = eth_client_clone
            .monitor_events(move |event| {
                let event_str = match event {
                    SwapEvent::EthCommitted {
                        tx_hash,
                        token_id,
                        secret_hash,
                    } => {
                        format!(
                            "NFT Committed - Token: {token_id}, Hash: {}, Tx: {tx_hash}",
                            hex::encode(secret_hash)
                        )
                    }
                    SwapEvent::SecretRevealed {
                        tx_hash,
                        secret,
                        token_id,
                    } => {
                        format!(
                            "Secret Revealed - Token: {token_id}, Secret: {}, Tx: {tx_hash}",
                            hex::encode(secret)
                        )
                    }
                    SwapEvent::NFTMinted {
                        tx_hash,
                        token_id,
                        owner,
                    } => {
                        format!("NFT Minted - Token: {token_id}, Owner: {owner:?}, Tx: {tx_hash}")
                    }
                    _ => format!("Other event: {event:?}"),
                };
                let _ = tx_eth.try_send(event_str);
                Ok(())
            })
            .await
        {
            error!("Ethereum monitoring error: {e}");
        }
    });

    info!("Monitoring started! Press Ctrl+C to stop.");
    info!("Events will be displayed as they occur...");

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                info!("{event}");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Monitoring stopped by user");
                break;
            }
        }
    }

    btc_monitor.abort();
    eth_monitor.abort();

    Ok(())
}

fn parse_btc_address(addr: &str, network: Network) -> Result<bitcoin::Address> {
    let addr = addr
        .parse::<bitcoin::Address<NetworkUnchecked>>()?
        .require_network(network)?;
    Ok(addr)
}

fn parse_network(network: &str) -> Result<Network> {
    match network.to_lowercase().as_str() {
        "mainnet" | "main" => Ok(Network::Bitcoin),
        "testnet" | "test" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" | "reg" => Ok(Network::Regtest),
        _ => Err(anyhow::anyhow!("Invalid network: {network}")),
    }
}
