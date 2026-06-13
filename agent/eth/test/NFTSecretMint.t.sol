// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {NFTSecretMint} from "../src/NFTSecretMint.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract NFTSecretMintTest is Test {
    NFTSecretMint internal nft;

    address internal owner;
    address internal seller;
    address internal buyer;
    address internal attacker;

    uint256 internal constant TOKEN_ID = 7;
    uint256 internal constant PRICE = 1 ether;
    string internal constant URI = "ipfs://token-metadata";
    bytes32 internal constant SECRET = keccak256("preimage");

    uint256 internal timeout;
    uint256 internal minTime;

    function setUp() public {
        owner = makeAddr("owner");
        seller = makeAddr("seller");
        buyer = makeAddr("buyer");
        attacker = makeAddr("attacker");

        nft = new NFTSecretMint("CrossChain Secret NFT", "CCSNFT", owner);
        timeout = nft.COMMITMENT_TIMEOUT();
        minTime = nft.MIN_COMMITMENT_TIME();

        vm.deal(buyer, 100 ether);
        vm.deal(attacker, 100 ether);
    }

    function _hash(bytes32 secret) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(secret));
    }

    function _commit(uint256 tokenId, uint256 price, address boundBuyer, bytes32 secret) internal {
        // Precompute the hash: `sha256` is a precompile staticcall, which would
        // otherwise consume the `vm.prank` before `commitForMint` is invoked.
        bytes32 h = _hash(secret);
        vm.prank(seller);
        nft.commitForMint(h, tokenId, price, boundBuyer, URI);
    }

    function test_CommitForMint_StoresCommitment() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);

        NFTSecretMint.MintCommitment memory c = nft.getCommitment(TOKEN_ID);
        assertEq(c.secretHash, _hash(SECRET));
        assertEq(c.seller, seller);
        assertEq(c.buyer, buyer);
        assertEq(c.price, PRICE);
        assertEq(c.commitTime, block.timestamp);
        assertTrue(c.isActive);
        assertEq(c.tokenURI, URI);
        assertTrue(nft.hashCommitted(_hash(SECRET)));
        assertTrue(nft.isCommitmentValid(TOKEN_ID));
    }

    function test_CommitForMint_RevertsOnZeroHash() public {
        vm.prank(seller);
        vm.expectRevert(NFTSecretMint.InvalidSecret.selector);
        nft.commitForMint(bytes32(0), TOKEN_ID, PRICE, buyer, URI);
    }

    function test_CommitForMint_RevertsOnEmptyURI() public {
        bytes32 h = _hash(SECRET);
        vm.prank(seller);
        vm.expectRevert(NFTSecretMint.InvalidCommitment.selector);
        nft.commitForMint(h, TOKEN_ID, PRICE, buyer, "");
    }

    function test_CommitForMint_RevertsOnActiveToken() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        bytes32 h = _hash(keccak256("other"));
        vm.prank(seller);
        vm.expectRevert(NFTSecretMint.TokenAlreadyCommitted.selector);
        nft.commitForMint(h, TOKEN_ID, PRICE, buyer, URI);
    }

    function test_CommitForMint_RevertsOnReusedHash() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        bytes32 h = _hash(SECRET);
        vm.prank(seller);
        vm.expectRevert(NFTSecretMint.HashAlreadyUsed.selector);
        nft.commitForMint(h, TOKEN_ID + 1, PRICE, buyer, URI);
    }

    function test_CommitForMint_TokenIdZero_BlocksHashReuse() public {
        _commit(0, PRICE, buyer, SECRET);
        assertTrue(nft.hashCommitted(_hash(SECRET)));

        bytes32 h = _hash(SECRET);
        vm.prank(seller);
        vm.expectRevert(NFTSecretMint.HashAlreadyUsed.selector);
        nft.commitForMint(h, 1, PRICE, buyer, URI);
    }

    function test_CommitForMint_RevertsWhenPaused() public {
        vm.prank(owner);
        nft.pause();
        bytes32 h = _hash(SECRET);
        vm.prank(seller);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        nft.commitForMint(h, TOKEN_ID, PRICE, buyer, URI);
    }

    function test_MintWithSecret_MintsAndPaysSeller() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        skip(minTime + 1);

        uint256 sellerBefore = seller.balance;
        vm.prank(buyer);
        nft.mintWithSecret{value: PRICE}(SECRET, TOKEN_ID);

        assertEq(nft.ownerOf(TOKEN_ID), buyer);
        assertEq(nft.tokenURI(TOKEN_ID), URI);
        assertEq(seller.balance, sellerBefore + PRICE);
        assertEq(address(nft).balance, 0);
        assertTrue(nft.revealedSecrets(SECRET));
        assertFalse(nft.getCommitment(TOKEN_ID).isActive);
        assertFalse(nft.hashCommitted(_hash(SECRET)));
    }

    function test_MintWithSecret_OpenMintAllowsAnyone() public {
        _commit(TOKEN_ID, PRICE, address(0), SECRET);
        skip(minTime + 1);

        vm.prank(attacker);
        nft.mintWithSecret{value: PRICE}(SECRET, TOKEN_ID);
        assertEq(nft.ownerOf(TOKEN_ID), attacker);
    }

    function test_MintWithSecret_FreeMint() public {
        _commit(TOKEN_ID, 0, buyer, SECRET);
        skip(minTime + 1);

        vm.prank(buyer);
        nft.mintWithSecret(SECRET, TOKEN_ID);
        assertEq(nft.ownerOf(TOKEN_ID), buyer);
    }

    function test_MintWithSecret_RevertsOnInactive() public {
        skip(minTime + 1);
        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.InvalidCommitment.selector);
        nft.mintWithSecret{value: PRICE}(SECRET, TOKEN_ID);
    }

    function test_MintWithSecret_RevertsOnUnauthorizedBuyer() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        skip(minTime + 1);
        vm.prank(attacker);
        vm.expectRevert(NFTSecretMint.UnauthorizedCaller.selector);
        nft.mintWithSecret{value: PRICE}(SECRET, TOKEN_ID);
    }

    function test_MintWithSecret_RevertsBeforeMinTime() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.CommitmentTooEarly.selector);
        nft.mintWithSecret{value: PRICE}(SECRET, TOKEN_ID);
    }

    function test_MintWithSecret_RevertsAfterTimeout() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        skip(timeout + 1);
        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.CommitmentExpired.selector);
        nft.mintWithSecret{value: PRICE}(SECRET, TOKEN_ID);
    }

    function test_MintWithSecret_RevertsOnWrongPrice() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        skip(minTime + 1);
        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.InvalidPrice.selector);
        nft.mintWithSecret{value: PRICE - 1}(SECRET, TOKEN_ID);
    }

    function test_MintWithSecret_RevertsOnWrongSecret() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        skip(minTime + 1);
        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.InvalidSecret.selector);
        nft.mintWithSecret{value: PRICE}(keccak256("wrong"), TOKEN_ID);
    }

    function test_MintWithSecret_RevertsOnRevealedSecretReplay() public {
        _commit(TOKEN_ID, 0, buyer, SECRET);
        skip(minTime + 1);
        vm.prank(buyer);
        nft.mintWithSecret(SECRET, TOKEN_ID);

        _commit(TOKEN_ID + 1, 0, buyer, SECRET);
        skip(minTime + 1);
        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.SecretAlreadyRevealed.selector);
        nft.mintWithSecret(SECRET, TOKEN_ID + 1);
    }

    function test_MintWithSecret_RevertsOnDoubleMint() public {
        _commit(TOKEN_ID, 0, buyer, SECRET);
        skip(minTime + 1);
        vm.prank(buyer);
        nft.mintWithSecret(SECRET, TOKEN_ID);

        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.InvalidCommitment.selector);
        nft.mintWithSecret(SECRET, TOKEN_ID);
    }

    function test_CancelCommitment_BySeller() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        vm.prank(seller);
        nft.cancelCommitment(TOKEN_ID);

        assertFalse(nft.getCommitment(TOKEN_ID).isActive);
        assertFalse(nft.hashCommitted(_hash(SECRET)));
    }

    function test_CancelCommitment_ByAnyoneAfterTimeout() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        skip(timeout + 1);
        vm.prank(attacker);
        nft.cancelCommitment(TOKEN_ID);
        assertFalse(nft.getCommitment(TOKEN_ID).isActive);
    }

    function test_CancelCommitment_RevertsForNonSellerBeforeTimeout() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        vm.prank(attacker);
        vm.expectRevert(NFTSecretMint.UnauthorizedCaller.selector);
        nft.cancelCommitment(TOKEN_ID);
    }

    function test_CancelCommitment_RevertsOnInactive() public {
        vm.prank(seller);
        vm.expectRevert(NFTSecretMint.InvalidCommitment.selector);
        nft.cancelCommitment(TOKEN_ID);
    }

    function test_CancelCommitment_ReleasesHashForReuse() public {
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        vm.prank(seller);
        nft.cancelCommitment(TOKEN_ID);

        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        assertTrue(nft.isCommitmentValid(TOKEN_ID));
    }

    function test_Pause_RevertsForNonOwner() public {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker)
        );
        nft.pause();
    }

    function test_Withdraw_RevertsForNonOwner() public {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker)
        );
        nft.withdraw();
    }

    function test_Withdraw_SweepsForceFedBalance() public {
        vm.deal(address(nft), 3 ether);
        uint256 ownerBefore = owner.balance;
        vm.prank(owner);
        nft.withdraw();
        assertEq(owner.balance, ownerBefore + 3 ether);
        assertEq(address(nft).balance, 0);
    }

    function test_OwnershipTransferIsTwoStep() public {
        vm.prank(owner);
        nft.transferOwnership(buyer);
        // Ownership does not move until accepted.
        assertEq(nft.owner(), owner);
        assertEq(nft.pendingOwner(), buyer);

        vm.prank(buyer);
        nft.acceptOwnership();
        assertEq(nft.owner(), buyer);
    }

    function testFuzz_CommitForMint_StoresFields(uint256 tokenId, uint256 price, bytes32 secret)
        public
    {
        vm.assume(secret != bytes32(0));
        price = bound(price, 0, 1000 ether);

        bytes32 h = _hash(secret);
        vm.prank(seller);
        nft.commitForMint(h, tokenId, price, buyer, URI);

        NFTSecretMint.MintCommitment memory c = nft.getCommitment(tokenId);
        assertEq(c.price, price);
        assertEq(c.secretHash, _hash(secret));
        assertTrue(c.isActive);
    }

    function testFuzz_MintWithSecret_PaysSeller(uint256 price, bytes32 secret) public {
        vm.assume(secret != bytes32(0));
        price = bound(price, 0, 50 ether);

        _commit(TOKEN_ID, price, buyer, secret);
        skip(minTime + 1);

        uint256 sellerBefore = seller.balance;
        vm.prank(buyer);
        nft.mintWithSecret{value: price}(secret, TOKEN_ID);

        assertEq(nft.ownerOf(TOKEN_ID), buyer);
        assertEq(seller.balance, sellerBefore + price);
        assertEq(address(nft).balance, 0);
    }

    function testFuzz_MintWithSecret_RejectsWrongPrice(uint256 price, uint256 paid) public {
        price = bound(price, 1, 50 ether);
        paid = bound(paid, 0, 50 ether);
        vm.assume(paid != price);

        _commit(TOKEN_ID, price, buyer, SECRET);
        skip(minTime + 1);

        vm.deal(buyer, 200 ether);
        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.InvalidPrice.selector);
        nft.mintWithSecret{value: paid}(SECRET, TOKEN_ID);
    }

    function testFuzz_MintWithSecret_RejectsWrongSecret(bytes32 secret, bytes32 wrong) public {
        vm.assume(secret != bytes32(0));
        vm.assume(_hash(secret) != _hash(wrong));

        _commit(TOKEN_ID, 0, buyer, secret);
        skip(minTime + 1);

        vm.prank(buyer);
        vm.expectRevert(NFTSecretMint.InvalidSecret.selector);
        nft.mintWithSecret(wrong, TOKEN_ID);
    }

    function testFuzz_CancelCommitment_AnyoneAfterTimeout(address caller, uint256 wait) public {
        wait = bound(wait, timeout + 1, 3650 days);
        _commit(TOKEN_ID, PRICE, buyer, SECRET);
        skip(wait);

        vm.prank(caller);
        nft.cancelCommitment(TOKEN_ID);
        assertFalse(nft.getCommitment(TOKEN_ID).isActive);
    }
}
