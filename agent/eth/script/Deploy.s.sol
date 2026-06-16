// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {NFTSecretMint} from "../src/NFTSecretMint.sol";

/// @title NFTSecretMint deployment script.
/// @notice Deploys the collection. The signing key is supplied by the `forge`
///         CLI (`--ledger`, `--account`, or `--private-key`), never read here,
///         so no secret enters the script. Configuration comes from the
///         environment:
///         - `NFT_NAME`: collection name.
///         - `NFT_SYMBOL`: collection symbol.
///         - `NFT_INITIAL_OWNER`: contract owner; defaults to the broadcaster.
contract Deploy is Script {
    function run() external returns (NFTSecretMint nft) {
        string memory name = vm.envOr("NFT_NAME", string("CrossChain Secret NFT"));
        string memory symbol = vm.envOr("NFT_SYMBOL", string("CCSNFT"));
        address initialOwner = vm.envOr("NFT_INITIAL_OWNER", msg.sender);

        vm.startBroadcast();
        nft = new NFTSecretMint(name, symbol, initialOwner);
        vm.stopBroadcast();
    }
}
