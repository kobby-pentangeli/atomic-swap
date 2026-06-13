// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {
    ERC721URIStorage
} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title NFTSecretMint
/// @notice NFT-chain side of a cross-chain atomic swap. A seller commits to mint
///         a specific token behind the SHA-256 hash of a secret; the buyer mints
///         it by revealing the secret preimage (after locking Bitcoin in the
///         matching HTLC); the seller then reuses that now-public secret to claim
///         the Bitcoin. The reveal is the cross-chain hinge: the same preimage
///         satisfies `OP_SHA256` in the Bitcoin script.
/// @dev    The preimage is revealed in plaintext calldata at mint time. When a
///         commitment fixes no buyer (`buyer == address(0)`) the mint is open to
///         anyone, so a searcher can observe the pending transaction and
///         front-run it to capture the NFT; `MIN_COMMITMENT_TIME` does not
///         prevent this. Bind a specific `buyer` for production swaps---only that
///         address can then mint. See `SECURITY.md` for the full threat model.
contract NFTSecretMint is ERC721, ERC721URIStorage, Ownable2Step, ReentrancyGuard, Pausable {
    /// @notice A seller's pending commitment to mint a token behind a secret hash.
    /// @param secretHash SHA-256 hash of the secret preimage required to mint.
    /// @param seller Address that created the commitment and receives the price.
    /// @param buyer Address allowed to mint, or the zero address for an open mint.
    /// @param price Amount in wei the minter must pay the seller.
    /// @param commitTime Block timestamp at which the commitment was created.
    /// @param isActive Whether the commitment is still open (not minted/cancelled).
    /// @param tokenURI Metadata URI assigned to the token on mint.
    struct MintCommitment {
        bytes32 secretHash;
        address seller;
        address buyer;
        uint256 price;
        uint256 commitTime;
        bool isActive;
        string tokenURI;
    }

    /// @notice Commitment state keyed by token ID.
    mapping(uint256 => MintCommitment) public commitments;

    /// @notice Whether a secret hash backs a live commitment, preventing the same
    ///         hash from backing two commitments at once. Cleared when the
    ///         commitment terminates (mint or cancel).
    /// @dev    A dedicated existence flag rather than a hash-to-token-ID mapping:
    ///         the latter could not distinguish "no commitment" from "a commitment
    ///         for token ID 0", which would let a hash be reused in that case.
    mapping(bytes32 => bool) public hashCommitted;

    /// @notice Whether a secret preimage has already been revealed, permanently
    ///         barring replay of a once-public secret across new commitments.
    mapping(bytes32 => bool) public revealedSecrets;

    /// @notice Window after commitment within which the secret may be revealed.
    uint256 public constant COMMITMENT_TIMEOUT = 24 hours;

    /// @notice Minimum delay after commitment before a mint is allowed, bounding
    ///         the trivial commit-and-mint-in-one-block race.
    uint256 public constant MIN_COMMITMENT_TIME = 1 minutes;

    /// @notice Emitted when a seller creates a commitment.
    /// @param tokenId Token ID reserved for minting.
    /// @param secretHash SHA-256 hash of the secret required to mint.
    /// @param seller Address that created the commitment.
    /// @param buyer Designated buyer, or the zero address for an open mint.
    /// @param price Price in wei required to mint.
    /// @param metadataURI Metadata URI for the token.
    event CommitmentCreated(
        uint256 indexed tokenId,
        bytes32 indexed secretHash,
        address indexed seller,
        address buyer,
        uint256 price,
        string metadataURI
    );

    /// @notice Emitted when a secret preimage is revealed during minting.
    /// @param tokenId Token ID being minted.
    /// @param secretHash Committed hash that the secret satisfies.
    /// @param secret Revealed preimage (now public, usable on the Bitcoin side).
    /// @param revealer Address that revealed the secret.
    event SecretRevealed(
        uint256 indexed tokenId,
        bytes32 indexed secretHash,
        bytes32 secret,
        address indexed revealer
    );

    /// @notice Emitted when a token is minted.
    /// @param tokenId Token ID that was minted.
    /// @param to Address that received the token.
    /// @param secret Secret used to mint.
    event NFTMinted(uint256 indexed tokenId, address indexed to, bytes32 secret);

    /// @notice Emitted when a commitment is cancelled and its hash released.
    /// @param tokenId Token ID whose commitment was cancelled.
    /// @param secretHash Secret hash released for potential reuse.
    /// @param seller Seller that created the original commitment.
    event CommitmentCancelled(
        uint256 indexed tokenId, bytes32 indexed secretHash, address indexed seller
    );

    /// @notice Thrown when committing a token ID that already has a live commitment.
    error TokenAlreadyCommitted();
    /// @notice Thrown when referencing a commitment that is absent or inactive.
    error InvalidCommitment();
    /// @notice Thrown when minting after the commitment window has elapsed.
    error CommitmentExpired();
    /// @notice Thrown when minting before `MIN_COMMITMENT_TIME` has elapsed.
    error CommitmentTooEarly();
    /// @notice Thrown when the provided secret does not hash to the committed value.
    error InvalidSecret();
    /// @notice Thrown when reusing a secret that has already been revealed.
    error SecretAlreadyRevealed();
    /// @notice Thrown when committing a secret hash already bound to a commitment.
    error HashAlreadyUsed();
    /// @notice Thrown when the caller is not authorized for the requested action.
    error UnauthorizedCaller();
    /// @notice Thrown when the supplied value does not equal the commitment price.
    error InvalidPrice();
    /// @notice Thrown when an ETH transfer fails.
    error TransferFailed();

    /// @notice Deploys the collection with two-step ownership.
    /// @param name Collection name.
    /// @param symbol Collection symbol.
    /// @param initialOwner Address granted ownership (pause/unpause, sweep).
    constructor(string memory name, string memory symbol, address initialOwner)
        ERC721(name, symbol)
        Ownable(initialOwner)
    {}

    /// @notice Commits to minting `tokenId` behind `secretHash`.
    /// @dev    Leaving `buyer` as the zero address opens the mint to anyone and
    ///         exposes it to front-running once the secret is revealed; bind a
    ///         specific buyer for production swaps.
    /// @param secretHash SHA-256 hash of the secret (must be non-zero).
    /// @param tokenId Token ID to reserve.
    /// @param price Price in wei the minter pays the seller (zero for free).
    /// @param buyer Address allowed to mint, or the zero address for an open mint.
    /// @param metadataURI Metadata URI for the token (must be non-empty).
    function commitForMint(
        bytes32 secretHash,
        uint256 tokenId,
        uint256 price,
        address buyer,
        string calldata metadataURI
    ) external nonReentrant whenNotPaused {
        if (secretHash == bytes32(0)) revert InvalidSecret();
        if (commitments[tokenId].isActive) revert TokenAlreadyCommitted();
        if (hashCommitted[secretHash]) revert HashAlreadyUsed();
        if (bytes(metadataURI).length == 0) revert InvalidCommitment();

        commitments[tokenId] = MintCommitment({
            secretHash: secretHash,
            seller: msg.sender,
            buyer: buyer,
            price: price,
            commitTime: block.timestamp,
            isActive: true,
            tokenURI: metadataURI
        });
        hashCommitted[secretHash] = true;

        emit CommitmentCreated(tokenId, secretHash, msg.sender, buyer, price, metadataURI);
    }

    /// @notice Reveals the secret and mints the committed token to the caller.
    /// @dev    Follows checks-effects-interactions and is `nonReentrant`: the
    ///         commitment is closed and the secret marked revealed before the
    ///         token is minted and the price forwarded to the seller.
    /// @param secret Preimage that hashes to the committed `secretHash`.
    /// @param tokenId Token ID to mint.
    function mintWithSecret(bytes32 secret, uint256 tokenId)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        MintCommitment storage commitment = commitments[tokenId];

        if (!commitment.isActive) revert InvalidCommitment();
        if (commitment.buyer != address(0) && msg.sender != commitment.buyer) {
            revert UnauthorizedCaller();
        }
        if (block.timestamp > commitment.commitTime + COMMITMENT_TIMEOUT) {
            revert CommitmentExpired();
        }
        if (block.timestamp < commitment.commitTime + MIN_COMMITMENT_TIME) {
            revert CommitmentTooEarly();
        }
        if (msg.value != commitment.price) revert InvalidPrice();
        if (sha256(abi.encodePacked(secret)) != commitment.secretHash) {
            revert InvalidSecret();
        }
        if (revealedSecrets[secret]) revert SecretAlreadyRevealed();

        address seller = commitment.seller;
        uint256 price = commitment.price;
        bytes32 secretHash = commitment.secretHash;

        // The commitment terminates here, freeing its token-ID-level hash
        // reservation; `revealedSecrets` is the permanent guard that bars the
        // now-public preimage from ever minting again.
        revealedSecrets[secret] = true;
        commitment.isActive = false;
        delete hashCommitted[secretHash];

        _safeMint(msg.sender, tokenId);
        _setTokenURI(tokenId, commitment.tokenURI);

        if (price > 0) {
            (bool success,) = payable(seller).call{value: price}("");
            if (!success) revert TransferFailed();
        }

        emit SecretRevealed(tokenId, secretHash, secret, msg.sender);
        emit NFTMinted(tokenId, msg.sender, secret);
    }

    /// @notice Cancels a live commitment, releasing its token ID and secret hash.
    /// @dev    The seller may cancel at any time before mint; anyone may cancel
    ///         once the commitment window has elapsed, guaranteeing a stranded
    ///         commitment is always recoverable.
    /// @param tokenId Token ID whose commitment to cancel.
    function cancelCommitment(uint256 tokenId) external nonReentrant {
        MintCommitment storage commitment = commitments[tokenId];

        if (!commitment.isActive) revert InvalidCommitment();

        bool canCancel = (msg.sender == commitment.seller)
            || (block.timestamp > commitment.commitTime + COMMITMENT_TIMEOUT);
        if (!canCancel) revert UnauthorizedCaller();

        bytes32 secretHash = commitment.secretHash;
        address seller = commitment.seller;
        delete commitments[tokenId];
        delete hashCommitted[secretHash];

        emit CommitmentCancelled(tokenId, secretHash, seller);
    }

    /// @notice Returns the full commitment record for `tokenId`.
    /// @param tokenId Token ID to query.
    /// @return The stored commitment (zero-valued if none exists).
    function getCommitment(uint256 tokenId) external view returns (MintCommitment memory) {
        return commitments[tokenId];
    }

    /// @notice Reports whether `tokenId` has an active, unexpired commitment.
    /// @param tokenId Token ID to query.
    /// @return True if the commitment is active and within its window.
    function isCommitmentValid(uint256 tokenId) external view returns (bool) {
        MintCommitment storage commitment = commitments[tokenId];
        return
            commitment.isActive && (block.timestamp <= commitment.commitTime + COMMITMENT_TIMEOUT);
    }

    /// @notice Reports whether `tokenId` can be minted at the current timestamp.
    /// @param tokenId Token ID to query.
    /// @return True if the commitment is active and within the mintable window.
    function canMintNow(uint256 tokenId) external view returns (bool) {
        MintCommitment storage commitment = commitments[tokenId];
        return commitment.isActive
            && (block.timestamp >= commitment.commitTime + MIN_COMMITMENT_TIME)
            && (block.timestamp <= commitment.commitTime + COMMITMENT_TIMEOUT);
    }

    /// @notice Pauses commitment creation and minting.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Resumes commitment creation and minting.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Sweeps any ETH held by the contract to the owner.
    /// @dev    Pull-style payment routes the price directly to the seller, so the
    ///         contract should never custody ETH; this recovers force-fed balance.
    function withdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool success,) = payable(owner()).call{value: balance}("");
            if (!success) revert TransferFailed();
        }
    }

    /// @inheritdoc ERC721
    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    /// @inheritdoc ERC721
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
