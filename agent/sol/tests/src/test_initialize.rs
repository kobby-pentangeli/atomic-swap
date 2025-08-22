use std::str::FromStr;

use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_sdk::pubkey::Pubkey;
use anchor_client::solana_sdk::signature::read_keypair_file;
use anchor_client::{Client, Cluster};

#[test]
#[ignore] // Ignore during `cargo test`
fn test_initialize() {
    let program_id = "Dut9qhBMYA4nGejGPD2hb9ine7dR2z7LqYrZvrz6zENR";
    let anchor_wallet = std::env::var("ANCHOR_WALLET").unwrap();
    let payer = read_keypair_file(&anchor_wallet).unwrap();

    let client = Client::new_with_options(Cluster::Localnet, &payer, CommitmentConfig::confirmed());
    let program_id = Pubkey::from_str(program_id).unwrap();
    let program = client.program(program_id).unwrap();

    let tx = program
        .request()
        .accounts(sol_htlc::accounts::Initialize {})
        .args(sol_htlc::instruction::Initialize {})
        .send()
        .expect("");

    println!("Your transaction signature {}", tx);
}
