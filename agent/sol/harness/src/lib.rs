//! Host-side test harness for the sol-htlc Solana program.
//!
//! Lives outside the Anchor (SBF) workspace so the SBF toolchain never parses its
//! host-only dependencies. It loads the compiled program and a Metaplex Token
//! Metadata binary into `litesvm` to exercise the full instruction surface---
//! including the mint's CPI chain into SPL Token and Metaplex---without a
//! validator. Build the SBF artifact with `anchor build` in the parent workspace
//! before running: the tests load `../target/deploy/sol_htlc.so`.

#![cfg(test)]
// LiteSVM's `FailedTransactionMetadata` carries full transaction logs, so the
// `Err` variant of these test helpers is unavoidably large.
#![allow(clippy::result_large_err)]

use anchor_lang::{system_program, AccountDeserialize, InstructionData, ToAccountMetas};
use anchor_spl::{associated_token, metadata, token};
use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use sol_htlc::{Commitment, ProgramState};
use solana_sdk::instruction::{Instruction, InstructionError};
use solana_sdk::native_token::LAMPORTS_PER_SOL;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::{Transaction, TransactionError};

const SOL_HTLC_SO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/sol_htlc.so");
const MPL_SO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/mpl_token_metadata.so"
);

const NAME: &str = "CrossChain NFT";
const SYMBOL: &str = "CCN";
const URI: &str = "ipfs://token-metadata";
const PRICE: u64 = LAMPORTS_PER_SOL / 10;
const TOKEN_ID: u64 = 7;

/// Anchor maps custom errors to `6000 + variant index`.
mod err {
    pub const INVALID_SECRET: u32 = 6000;
    pub const UNAUTHORIZED: u32 = 6001;
    pub const UNAUTHORIZED_BUYER: u32 = 6002;
    pub const INVALID_PRICE: u32 = 6003;
    pub const URI_TOO_LONG: u32 = 6006;
}

struct Env {
    svm: LiteSVM,
    seller: Keypair,
    buyer: Keypair,
}

fn setup() -> Env {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(sol_htlc::ID, SOL_HTLC_SO)
        .expect("load sol-htlc program");
    svm.add_program_from_file(metadata::ID, MPL_SO)
        .expect("load metaplex program");

    let seller = Keypair::new();
    let buyer = Keypair::new();
    svm.airdrop(&seller.pubkey(), 100 * LAMPORTS_PER_SOL)
        .unwrap();
    svm.airdrop(&buyer.pubkey(), 100 * LAMPORTS_PER_SOL)
        .unwrap();

    Env { svm, seller, buyer }
}

fn program_state_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"program_state"], &sol_htlc::ID).0
}

fn commitment_pda(token_id: u64) -> Pubkey {
    Pubkey::find_program_address(&[b"commitment", &token_id.to_le_bytes()], &sol_htlc::ID).0
}

fn mint_pda(token_id: u64) -> Pubkey {
    Pubkey::find_program_address(&[b"mint", &token_id.to_le_bytes()], &sol_htlc::ID).0
}

fn metadata_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[b"metadata", metadata::ID.as_ref(), mint.as_ref()],
        &metadata::ID,
    )
    .0
}

fn edition_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"metadata",
            metadata::ID.as_ref(),
            mint.as_ref(),
            b"edition",
        ],
        &metadata::ID,
    )
    .0
}

fn hash(secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

fn send(
    env: &mut Env,
    ixs: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) -> Result<TransactionMetadata, FailedTransactionMetadata> {
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        signers,
        env.svm.latest_blockhash(),
    );
    env.svm.send_transaction(tx)
}

fn custom_error(res: &Result<TransactionMetadata, FailedTransactionMetadata>) -> Option<u32> {
    match res {
        Err(meta) => match meta.err {
            TransactionError::InstructionError(_, InstructionError::Custom(code)) => Some(code),
            _ => None,
        },
        Ok(_) => None,
    }
}

fn ix_initialize(authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: sol_htlc::ID,
        accounts: sol_htlc::accounts::Initialize {
            program_state: program_state_pda(),
            authority: *authority,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: sol_htlc::instruction::Initialize {}.data(),
    }
}

#[allow(clippy::too_many_arguments)]
fn ix_commit(
    seller: &Pubkey,
    hash: [u8; 32],
    token_id: u64,
    price: u64,
    name: &str,
    symbol: &str,
    uri: &str,
    buyer: Option<Pubkey>,
) -> Instruction {
    Instruction {
        program_id: sol_htlc::ID,
        accounts: sol_htlc::accounts::CommitForMint {
            commitment: commitment_pda(token_id),
            seller: *seller,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: sol_htlc::instruction::CommitForMint {
            hash,
            token_id,
            price,
            name: name.to_string(),
            symbol: symbol.to_string(),
            uri: uri.to_string(),
            buyer,
        }
        .data(),
    }
}

fn ix_mint(buyer: &Pubkey, seller: &Pubkey, secret: [u8; 32], token_id: u64) -> Instruction {
    let mint = mint_pda(token_id);
    Instruction {
        program_id: sol_htlc::ID,
        accounts: sol_htlc::accounts::MintWithSecret {
            commitment: commitment_pda(token_id),
            mint,
            token_account: associated_token::get_associated_token_address(buyer, &mint),
            metadata: metadata_pda(&mint),
            master_edition: edition_pda(&mint),
            program_state: program_state_pda(),
            seller_info: *seller,
            buyer: *buyer,
            token_program: token::ID,
            associated_token_program: associated_token::ID,
            metadata_program: metadata::ID,
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
        data: sol_htlc::instruction::MintWithSecret { secret, token_id }.data(),
    }
}

fn ix_cancel(seller: &Pubkey, token_id: u64) -> Instruction {
    Instruction {
        program_id: sol_htlc::ID,
        accounts: sol_htlc::accounts::CancelCommitment {
            commitment: commitment_pda(token_id),
            seller: *seller,
        }
        .to_account_metas(None),
        data: sol_htlc::instruction::CancelCommitment {}.data(),
    }
}

fn initialize(env: &mut Env) {
    let authority = env.seller.insecure_clone();
    send(
        env,
        &[ix_initialize(&authority.pubkey())],
        &authority,
        &[&authority],
    )
    .expect("initialize");
}

fn program_state(env: &Env) -> ProgramState {
    let acc = env.svm.get_account(&program_state_pda()).unwrap();
    ProgramState::try_deserialize(&mut acc.data.as_slice()).unwrap()
}

fn commitment(env: &Env, token_id: u64) -> Option<Commitment> {
    env.svm
        .get_account(&commitment_pda(token_id))
        .filter(|a| !a.data.is_empty())
        .map(|a| Commitment::try_deserialize(&mut a.data.as_slice()).unwrap())
}

#[test]
fn initialize_sets_authority() {
    let mut env = setup();
    initialize(&mut env);
    let state = program_state(&env);
    assert_eq!(state.authority, env.seller.pubkey());
    assert_eq!(state.total_minted, 0);
}

#[test]
fn initialize_twice_fails() {
    let mut env = setup();
    initialize(&mut env);
    let authority = env.seller.insecure_clone();
    let res = send(
        &mut env,
        &[ix_initialize(&authority.pubkey())],
        &authority,
        &[&authority],
    );
    assert!(res.is_err());
}

#[test]
fn commit_stores_fields() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let secret = [9u8; 32];

    send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&secret),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            URI,
            None,
        )],
        &seller,
        &[&seller],
    )
    .expect("commit");

    let c = commitment(&env, TOKEN_ID).expect("commitment exists");
    assert_eq!(c.hash, hash(&secret));
    assert_eq!(c.token_id, TOKEN_ID);
    assert_eq!(c.price, PRICE);
    assert_eq!(c.seller, seller.pubkey());
    assert_eq!(c.buyer, None);
    assert_eq!(c.name, NAME);
}

#[test]
fn commit_rejects_low_price() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let res = send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&[1u8; 32]),
            TOKEN_ID,
            0,
            NAME,
            SYMBOL,
            URI,
            None,
        )],
        &seller,
        &[&seller],
    );
    assert_eq!(custom_error(&res), Some(err::INVALID_PRICE));
}

#[test]
fn commit_rejects_oversized_uri() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let long_uri = "x".repeat(201);
    let res = send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&[1u8; 32]),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            &long_uri,
            None,
        )],
        &seller,
        &[&seller],
    );
    assert_eq!(custom_error(&res), Some(err::URI_TOO_LONG));
}

#[test]
fn commit_duplicate_token_id_fails() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let ix = ix_commit(
        &seller.pubkey(),
        hash(&[1u8; 32]),
        TOKEN_ID,
        PRICE,
        NAME,
        SYMBOL,
        URI,
        None,
    );
    send(&mut env, &[ix], &seller, &[&seller]).expect("first commit");
    let ix2 = ix_commit(
        &seller.pubkey(),
        hash(&[2u8; 32]),
        TOKEN_ID,
        PRICE,
        NAME,
        SYMBOL,
        URI,
        None,
    );
    let res = send(&mut env, &[ix2], &seller, &[&seller]);
    assert!(res.is_err());
}

#[test]
fn cancel_returns_rent_and_closes() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&[3u8; 32]),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            URI,
            None,
        )],
        &seller,
        &[&seller],
    )
    .expect("commit");

    let before = env.svm.get_account(&seller.pubkey()).unwrap().lamports;
    send(
        &mut env,
        &[ix_cancel(&seller.pubkey(), TOKEN_ID)],
        &seller,
        &[&seller],
    )
    .expect("cancel");

    assert!(commitment(&env, TOKEN_ID).is_none());
    let after = env.svm.get_account(&seller.pubkey()).unwrap().lamports;
    assert!(after > before, "rent should be returned to the seller");
}

#[test]
fn cancel_rejects_non_seller() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let attacker = env.buyer.insecure_clone();
    send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&[3u8; 32]),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            URI,
            None,
        )],
        &seller,
        &[&seller],
    )
    .expect("commit");

    let res = send(
        &mut env,
        &[ix_cancel(&attacker.pubkey(), TOKEN_ID)],
        &attacker,
        &[&attacker],
    );
    assert_eq!(custom_error(&res), Some(err::UNAUTHORIZED));
}

#[test]
fn mint_rejects_wrong_secret() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let buyer = env.buyer.insecure_clone();
    send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&[5u8; 32]),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            URI,
            None,
        )],
        &seller,
        &[&seller],
    )
    .expect("commit");

    let res = send(
        &mut env,
        &[ix_mint(
            &buyer.pubkey(),
            &seller.pubkey(),
            [0u8; 32],
            TOKEN_ID,
        )],
        &buyer,
        &[&buyer],
    );
    assert_eq!(custom_error(&res), Some(err::INVALID_SECRET));
}

#[test]
fn mint_rejects_unauthorized_buyer() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let buyer = env.buyer.insecure_clone();
    let bound = Keypair::new();
    let secret = [6u8; 32];
    send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&secret),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            URI,
            Some(bound.pubkey()),
        )],
        &seller,
        &[&seller],
    )
    .expect("commit");

    let res = send(
        &mut env,
        &[ix_mint(&buyer.pubkey(), &seller.pubkey(), secret, TOKEN_ID)],
        &buyer,
        &[&buyer],
    );
    assert_eq!(custom_error(&res), Some(err::UNAUTHORIZED_BUYER));
}

#[test]
fn mint_happy_path() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let buyer = env.buyer.insecure_clone();
    let secret = [7u8; 32];
    send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&secret),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            URI,
            Some(buyer.pubkey()),
        )],
        &seller,
        &[&seller],
    )
    .expect("commit");

    let seller_before = env.svm.get_account(&seller.pubkey()).unwrap().lamports;
    send(
        &mut env,
        &[ix_mint(&buyer.pubkey(), &seller.pubkey(), secret, TOKEN_ID)],
        &buyer,
        &[&buyer],
    )
    .expect("mint");

    // Commitment closed, supply counted, edition account materialized.
    assert!(commitment(&env, TOKEN_ID).is_none());
    assert_eq!(program_state(&env).total_minted, 1);
    assert!(env
        .svm
        .get_account(&edition_pda(&mint_pda(TOKEN_ID)))
        .is_some());
    let seller_after = env.svm.get_account(&seller.pubkey()).unwrap().lamports;
    assert!(
        seller_after >= seller_before + PRICE,
        "seller received the price"
    );
}

#[test]
fn mint_then_remint_fails() {
    let mut env = setup();
    initialize(&mut env);
    let seller = env.seller.insecure_clone();
    let buyer = env.buyer.insecure_clone();
    let secret = [8u8; 32];
    send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&secret),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            URI,
            None,
        )],
        &seller,
        &[&seller],
    )
    .expect("commit");
    send(
        &mut env,
        &[ix_mint(&buyer.pubkey(), &seller.pubkey(), secret, TOKEN_ID)],
        &buyer,
        &[&buyer],
    )
    .expect("mint");

    // The mint PDA persists, so re-committing and re-minting the same token id
    // fails. A fresh blockhash distinguishes the re-commit from the first commit,
    // which is otherwise byte-identical and rejected as a duplicate.
    env.svm.expire_blockhash();
    send(
        &mut env,
        &[ix_commit(
            &seller.pubkey(),
            hash(&secret),
            TOKEN_ID,
            PRICE,
            NAME,
            SYMBOL,
            URI,
            None,
        )],
        &seller,
        &[&seller],
    )
    .expect("re-commit closed token id");
    let res = send(
        &mut env,
        &[ix_mint(&buyer.pubkey(), &seller.pubkey(), secret, TOKEN_ID)],
        &buyer,
        &[&buyer],
    );
    assert!(res.is_err());
}
