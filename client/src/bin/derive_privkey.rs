//! Derives a child private key from a BIP-32 extended private key and a
//! derivation path, printing it in hex. Hex is the form the swap CLI's Bitcoin
//! key flags (`--buyer-btc-key`/`--seller-btc-key`) accept, so a deployment
//! whose key lives in an HD wallet can turn its xpriv into the exact child key
//! the client consumes.

use std::str::FromStr;

use anyhow::{Context, Result, bail};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    let [_, xpriv_str, path_str] = args.as_slice() else {
        bail!("Usage: derive_privkey <xpriv> <derivation_path>");
    };

    let secp = Secp256k1::new();
    let xpriv = Xpriv::from_str(xpriv_str).context("Failed to parse xpriv")?;
    let path = DerivationPath::from_str(path_str).context("Invalid derivation path")?;

    let child = xpriv
        .derive_priv(&secp, &path)
        .context("Key derivation failed")?;
    println!("{}", child.private_key.display_secret());

    Ok(())
}
