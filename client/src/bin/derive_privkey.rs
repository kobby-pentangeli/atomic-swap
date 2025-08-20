use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;

fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 3 {
        eprintln!("Usage: derive_privkey <xpriv> <derivation_path>");
        std::process::exit(1);
    }

    let xpriv_str = &args[1];
    let path_str = &args[2];
    let secp = Secp256k1::new();

    let xpriv = Xpriv::from_str(xpriv_str).expect("Failed to parse xpriv");
    let path = DerivationPath::from_str(path_str).expect("Invalid derivation path");

    let child_xpriv = xpriv.derive_priv(&secp, &path).expect("Derivation failed");
    println!("{}", child_xpriv.private_key.display_secret());
}
