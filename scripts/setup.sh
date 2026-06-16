#!/usr/bin/env bash
#
# Atomic-swap developer toolchain setup.
#
# Installs (idempotently) the toolchains the project builds, tests, and runs the
# end-to-end harness against, pinned to the versions the workspace targets, so a
# contributor's machine and CI converge on the same setup:
#
#   - Rust         stable (build) + nightly (the `cargo +nightly fmt` formatter)
#   - Foundry      forge/cast/anvil (Ethereum contract build, tests, local node)
#   - Solana       the Agave CLI (program build/deploy, local validator, keypairs)
#   - Anchor       via avm, pinned to the version in the Cargo manifests
#   - Bitcoin Core bitcoind/bitcoin-cli (regtest node for the swap and harness)
#
# Usage:
#   scripts/setup.sh [--all] [--rust] [--foundry] [--solana] [--anchor] [--bitcoin]
#   scripts/setup.sh --verify        # print installed versions, install nothing
#   scripts/setup.sh --help
#
# Version pins (override via environment):
#   ANCHOR_VERSION   matches anchor-lang / anchor-client in the Cargo manifests
#   SOLANA_VERSION   Agave release tag the Anchor crates target
#   BITCOIN_VERSION  Bitcoin Core release used for the regtest node
#
# Network access is required. Installers append to shell rc files; open a new
# shell (or `source` the noted env files) afterwards so PATH updates take effect.

set -euo pipefail

# --- Version pins -------------------------------------------------------------
# These track the committed manifests so the installer never provisions a
# toolchain the repository cannot build against.
ANCHOR_VERSION="${ANCHOR_VERSION:-1.0.2}"
SOLANA_VERSION="${SOLANA_VERSION:-v3.1.10}"
BITCOIN_VERSION="${BITCOIN_VERSION:-31.0}"

# --- Helpers ------------------------------------------------------------------
log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup]\033[0m %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

ensure_rustup() {
  if ! have rustup; then
    log "Installing rustup (Rust toolchain manager)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # shellcheck disable=SC1091
    source "${CARGO_HOME:-$HOME/.cargo}/env"
  fi
}

install_rust() {
  ensure_rustup
  log "Installing Rust stable + nightly with rustfmt/clippy..."
  rustup toolchain install stable --component rustfmt clippy
  rustup toolchain install nightly --component rustfmt
}

install_foundry() {
  if ! have foundryup; then
    log "Installing foundryup (Foundry installer)..."
    curl -L https://foundry.paradigm.xyz | bash
    export PATH="$HOME/.foundry/bin:$PATH"
  fi
  log "Installing Foundry (forge/cast/anvil)..."
  foundryup ${FOUNDRY_VERSION:+--install "$FOUNDRY_VERSION"}
}

install_solana() {
  if ! have solana; then
    log "Installing the Agave (Solana) CLI (${SOLANA_VERSION})..."
    sh -c "$(curl -sSfL "https://release.anza.xyz/${SOLANA_VERSION}/install")"
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
  else
    log "Solana CLI already present; skipping (re-run in a fresh shell to upgrade)."
  fi
}

install_anchor() {
  ensure_rustup
  if ! have avm; then
    log "Installing avm (Anchor version manager)..."
    cargo install --git https://github.com/solana-foundation/anchor avm --force
  fi
  log "Installing and selecting Anchor ${ANCHOR_VERSION}..."
  avm install "${ANCHOR_VERSION}"
  avm use "${ANCHOR_VERSION}"
}

install_bitcoin() {
  if have bitcoind; then
    log "Bitcoin Core already present; skipping."
    return
  fi
  case "$(uname -s)" in
    Darwin)
      if have brew; then
        log "Installing Bitcoin Core via Homebrew..."
        brew install bitcoin
      else
        warn "Homebrew not found; install Bitcoin Core ${BITCOIN_VERSION} manually:"
        warn "  https://bitcoincore.org/en/download/"
      fi
      ;;
    Linux)
      local arch tag dir tarball
      case "$(uname -m)" in
        x86_64)  arch="x86_64-linux-gnu" ;;
        aarch64) arch="aarch64-linux-gnu" ;;
        *) warn "Unsupported Linux arch $(uname -m); install Bitcoin Core manually."; return ;;
      esac
      tag="bitcoin-${BITCOIN_VERSION}-${arch}"
      tarball="${tag}.tar.gz"
      dir="$(mktemp -d)"
      log "Installing Bitcoin Core ${BITCOIN_VERSION} (${arch})..."
      curl -sSfL "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/${tarball}" -o "${dir}/${tarball}"
      curl -sSfL "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS" -o "${dir}/SHA256SUMS"
      (cd "$dir" && grep "$tarball" SHA256SUMS | sha256sum -c -)
      tar -xzf "${dir}/${tarball}" -C "$dir"
      sudo install -m 0755 -t /usr/local/bin "${dir}/bitcoin-${BITCOIN_VERSION}/bin/"*
      rm -rf "$dir"
      ;;
    *)
      warn "Unsupported OS $(uname -s); install Bitcoin Core manually."
      ;;
  esac
}

verify() {
  log "Installed toolchain versions:"
  for tool in "rustc --version" "cargo --version" "forge --version" "anvil --version" \
              "cast --version" "solana --version" "cargo-build-sbf --version" \
              "avm --version" "anchor --version" "bitcoind --version"; do
    name="${tool%% *}"
    if have "$name"; then
      printf '  %-18s %s\n' "$name" "$($tool 2>/dev/null | head -1)"
    else
      printf '  %-18s %s\n' "$name" "NOT INSTALLED"
    fi
  done
}

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

main() {
  if [[ $# -eq 0 ]]; then set -- --all; fi

  local do_rust=0 do_foundry=0 do_solana=0 do_anchor=0 do_bitcoin=0 do_verify=0
  for arg in "$@"; do
    case "$arg" in
      --all)     do_rust=1; do_foundry=1; do_solana=1; do_anchor=1; do_bitcoin=1 ;;
      --rust)    do_rust=1 ;;
      --foundry) do_foundry=1 ;;
      --solana)  do_solana=1 ;;
      --anchor)  do_anchor=1 ;;
      --bitcoin) do_bitcoin=1 ;;
      --verify)  do_verify=1 ;;
      -h|--help) usage; exit 0 ;;
      *) warn "unknown option: $arg"; usage; exit 1 ;;
    esac
  done

  if [[ $do_verify -eq 1 ]]; then verify; exit 0; fi

  [[ $do_rust    -eq 1 ]] && install_rust
  [[ $do_foundry -eq 1 ]] && install_foundry
  [[ $do_solana  -eq 1 ]] && install_solana
  [[ $do_anchor  -eq 1 ]] && install_anchor
  [[ $do_bitcoin -eq 1 ]] && install_bitcoin

  echo ""
  verify
  echo ""
  log "Done. Open a new shell so all PATH updates take effect."
}

main "$@"
