//! Locating and, when missing, building the artifacts the harness drives.
//!
//! The harness needs three on-disk artifacts: the compiled `client` binary, the
//! SBF program `.so`, and the vendored Metaplex fixture. The first two are built
//! on demand, once per process if absent; the fixture is committed with the
//! Solana harness. CI builds all of them as explicit steps, so [`ensure_built`]
//! is a no-op there.

use std::path::{Path, PathBuf};
use std::sync::Once;

use anyhow::{Context, Result, bail};

use crate::process::{run, run_in};

/// Workspace root, derived from this crate's location at compile time.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the e2e crate always has a parent workspace directory")
        .to_path_buf()
}

/// The Foundry project directory (`agent/eth`).
pub fn eth_dir() -> PathBuf {
    workspace_root().join("agent/eth")
}

/// The Anchor workspace directory (`agent/sol`).
pub fn sol_dir() -> PathBuf {
    workspace_root().join("agent/sol")
}

/// The compiled SBF program (`agent/sol/target/deploy/sol_htlc.so`).
pub fn program_so() -> PathBuf {
    sol_dir().join("target/deploy/sol_htlc.so")
}

/// The vendored Metaplex Token Metadata program loaded into the validator.
pub fn metaplex_fixture() -> PathBuf {
    sol_dir().join("harness/fixtures/mpl_token_metadata.so")
}

/// Locate the built `client` binary next to the running test or demo binary.
///
/// Test binaries live in `target/<profile>/deps`, the demo in `target/<profile>`,
/// so the `client` binary is one or two directories up.
pub fn client_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("Failed to resolve the current executable")?;
    let dir = exe
        .parent()
        .context("The current executable has no parent directory")?;
    [dir.join("client"), dir.join("../client")]
        .into_iter()
        .map(|p| p.with_extension(std::env::consts::EXE_EXTENSION))
        .find(|p| p.exists())
        .with_context(|| {
            format!(
                "client binary not found near {}; run `cargo build -p client` first",
                dir.display()
            )
        })
}

/// Build the `client` binary and SBF program if they are not already present.
///
/// Idempotent and run at most once per process. The release/debug profile is
/// inferred from the running executable's path so the built `client` lands where
/// [`client_binary`] looks for it.
pub fn ensure_built() -> Result<()> {
    static ONCE: Once = Once::new();
    let mut result = Ok(());
    ONCE.call_once(|| result = build_artifacts());
    // `Once` runs the body once; later callers see a fresh Ok and rely on the
    // first run having produced the artifacts (or the located-path checks below).
    result?;

    if !metaplex_fixture().exists() {
        bail!(
            "Metaplex fixture missing at {}",
            metaplex_fixture().display()
        );
    }
    Ok(())
}

fn build_artifacts() -> Result<()> {
    let release = std::env::current_exe()
        .ok()
        .map(|p| p.components().any(|c| c.as_os_str() == "release"))
        .unwrap_or(false);

    if client_binary().is_err() {
        let mut args = vec!["build", "-p", "client"];
        if release {
            args.push("--release");
        }
        run("cargo", &args).context("Failed to build the client binary")?;
    }

    if !program_so().exists() {
        run_in(&sol_dir(), "cargo", &["build-sbf"]).context("Failed to build the SBF program")?;
    }

    Ok(())
}
