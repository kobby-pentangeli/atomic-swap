// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {NFTSecretMint} from "../src/NFTSecretMint.sol";

/// Exercises the contract through bounded, always-valid operations so that, under
/// `fail_on_revert = true`, any reverting call signals a real invariant breach
/// rather than an expected guard. Tracks ghost state to assert system invariants.
contract NFTSecretMintHandler is Test {
    NFTSecretMint internal immutable NFT;

    uint256 internal constant URI_PRICE_CAP = 100 ether;
    string internal constant URI = "ipfs://handler-metadata";

    uint256[] internal activeTokens;
    mapping(uint256 => bool) internal isActiveToken;
    mapping(uint256 => bytes32) internal tokenSecret;
    mapping(uint256 => uint256) internal tokenPrice;

    uint256[] public mintedTokens;
    mapping(uint256 => bool) public isMinted;

    uint256 internal secretNonce;

    constructor(NFTSecretMint nft) {
        NFT = nft;
        vm.deal(address(this), 1_000_000 ether);
    }

    /// The handler is the seller, so it must accept the pull payment routed back
    /// to it on mint.
    receive() external payable {}

    function _hash(bytes32 secret) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(secret));
    }

    /// Commit a fresh, collision-free secret to an unused token slot.
    function commit(uint256 tokenId, uint256 price, bool open) external {
        tokenId = bound(tokenId, 0, 1000);
        if (isActiveToken[tokenId] || isMinted[tokenId]) return;

        secretNonce++;
        bytes32 secret = keccak256(abi.encodePacked("handler-secret", secretNonce));
        bytes32 h = _hash(secret);
        if (NFT.hashCommitted(h) || NFT.revealedSecrets(secret)) return;

        price = bound(price, 0, URI_PRICE_CAP);
        // Bind the buyer to this handler so it can always mint; an open mint
        // (zero address) is also mintable by the handler.
        address buyer = open ? address(0) : address(this);
        NFT.commitForMint(h, tokenId, price, buyer, URI);

        activeTokens.push(tokenId);
        isActiveToken[tokenId] = true;
        tokenSecret[tokenId] = secret;
        tokenPrice[tokenId] = price;
    }

    /// Mint a currently-committed token, advancing time into its mintable window.
    function mint(uint256 seed) external {
        if (activeTokens.length == 0) return;
        uint256 idx = seed % activeTokens.length;
        uint256 tokenId = activeTokens[idx];

        skip(NFT.MIN_COMMITMENT_TIME() + 1);
        NFT.mintWithSecret{value: tokenPrice[tokenId]}(tokenSecret[tokenId], tokenId);

        _deactivate(idx);
        isMinted[tokenId] = true;
        mintedTokens.push(tokenId);
    }

    /// Cancel a currently-committed token as its seller (this handler).
    function cancel(uint256 seed) external {
        if (activeTokens.length == 0) return;
        uint256 idx = seed % activeTokens.length;
        uint256 tokenId = activeTokens[idx];

        NFT.cancelCommitment(tokenId);
        _deactivate(idx);
    }

    function _deactivate(uint256 idx) internal {
        uint256 tokenId = activeTokens[idx];
        isActiveToken[tokenId] = false;
        activeTokens[idx] = activeTokens[activeTokens.length - 1];
        activeTokens.pop();
    }

    function mintedCount() external view returns (uint256) {
        return mintedTokens.length;
    }

    /// Accept safe transfers so the handler can custody the NFTs it mints.
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC721Received.selector;
    }
}

contract NFTSecretMintInvariant is Test {
    NFTSecretMint internal nft;
    NFTSecretMintHandler internal handler;

    function setUp() public {
        nft = new NFTSecretMint("CrossChain Secret NFT", "CCSNFT", address(this));
        handler = new NFTSecretMintHandler(nft);

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = handler.commit.selector;
        selectors[1] = handler.mint.selector;
        selectors[2] = handler.cancel.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function invariant_ContractHoldsNoEth() public view {
        assertEq(address(nft).balance, 0);
    }

    function invariant_MintedTokensAreClosed() public view {
        uint256 count = handler.mintedCount();
        for (uint256 i = 0; i < count; i++) {
            uint256 tokenId = handler.mintedTokens(i);
            assertEq(nft.ownerOf(tokenId), address(handler));
            assertFalse(nft.getCommitment(tokenId).isActive);
        }
    }

    function invariant_SupplyMatchesMints() public view {
        uint256 count = handler.mintedCount();
        for (uint256 i = 0; i < count; i++) {
            assertTrue(nft.ownerOf(handler.mintedTokens(i)) != address(0));
        }
    }
}
