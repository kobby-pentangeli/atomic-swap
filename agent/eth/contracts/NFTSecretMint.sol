// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title NFTSecretMint
 * @dev Cross-chain NFT minting contract that uses secret reveal mechanism
 *
 * Flow:
 * 1. Seller commits to mint an NFT by providing a hash and reserving the token
 * 2. Buyer reveals the secret (after locking Bitcoin) to mint the NFT
 * 3. Seller can then use the revealed secret to claim Bitcoin
 */
contract NFTSecretMint is
    ERC721,
    ERC721URIStorage,
    Ownable,
    ReentrancyGuard,
    Pausable
{
    /// @dev Represents a commitment to mint
    struct MintCommitment {
        bytes32 secretHash; // Hash of the secret
        address seller; // Address that made the commitment
        address buyer; // Intended buyer
        uint256 price; // Price in wei
        uint256 commitTime; // When the commitment was made
        bool isActive; // Whether commitment is still valid
        string tokenURI; // Metadata URI for the NFT
    }

    /// @dev Mapping from token ID to mint commitment
    mapping(uint256 => MintCommitment) public commitments;

    /// @dev Mapping from secret hash to token ID (prevents hash reuse)
    mapping(bytes32 => uint256) public hashToTokenId;

    /// @dev Mapping to track revealed secrets (prevents replay attacks)
    mapping(bytes32 => bool) public revealedSecrets;

    /// @dev Time window for commitments (24 hours)
    uint256 public constant COMMITMENT_TIMEOUT = 24 hours;

    /// @dev Minimum commitment time before reveal (prevents front-running and MEV attacks)
    uint256 public constant MIN_COMMITMENT_TIME = 1 minutes;

    /// @dev Emitted when a seller creates a new commitment for NFT minting
    /// @param tokenId The token ID reserved for minting
    /// @param secretHash The SHA256 hash of the secret required for minting
    /// @param seller The address that created the commitment
    /// @param buyer The designated buyer address (zero address if open to anyone)
    /// @param price The price in wei required to mint
    /// @param metadataURI The metadata URI for the NFT
    event CommitmentCreated(
        uint256 indexed tokenId,
        bytes32 indexed secretHash,
        address indexed seller,
        address buyer,
        uint256 price,
        string metadataURI
    );

    /// @dev Emitted when a secret is revealed during the minting process
    /// @param tokenId The token ID being minted
    /// @param secretHash The hash that was committed
    /// @param secret The revealed secret (preimage)
    /// @param revealer The address that revealed the secret
    event SecretRevealed(
        uint256 indexed tokenId,
        bytes32 indexed secretHash,
        bytes32 secret,
        address indexed revealer
    );

    /// @dev Emitted when an NFT is successfully minted
    /// @param tokenId The token ID that was minted
    /// @param to The address that received the NFT
    /// @param secret The secret used for minting
    event NFTMinted(
        uint256 indexed tokenId,
        address indexed to,
        bytes32 secret
    );

    /// @dev Emitted when a commitment is cancelled
    /// @param tokenId The token ID whose commitment was cancelled
    /// @param secretHash The secret hash that was released
    /// @param seller The seller who created the original commitment
    event CommitmentCancelled(
        uint256 indexed tokenId,
        bytes32 indexed secretHash,
        address indexed seller
    );

    /// @dev Thrown when attempting to commit a token ID that already has an active commitment
    error TokenAlreadyCommitted();
    /// @dev Thrown when referencing a commitment that does not exist or is inactive
    error InvalidCommitment();
    /// @dev Thrown when attempting to mint after the commitment timeout has passed
    error CommitmentExpired();
    /// @dev Thrown when attempting to mint before the minimum commitment time has elapsed
    error CommitmentTooEarly();
    /// @dev Thrown when the provided secret does not hash to the expected value
    error InvalidSecret();
    /// @dev Thrown when attempting to use a secret that has already been revealed
    error SecretAlreadyRevealed();
    /// @dev Thrown when attempting to use a secret hash that is already associated with a token
    error HashAlreadyUsed();
    /// @dev Thrown when a caller is not authorized to perform the requested action
    error UnauthorizedCaller();
    /// @dev Thrown when the payment amount does not match the commitment price
    error InvalidPrice();
    /// @dev Thrown when the ETH transfer to the seller fails
    error PaymentFailed();
    /// @dev Thrown when querying a token that does not exist
    error TokenDoesNotExist();

    /**
     * @dev Initializes the NFTSecretMint contract
     * @param name The name of the NFT collection
     * @param symbol The symbol of the NFT collection
     * @param initialOwner The address that will own the contract
     */
    constructor(
        string memory name,
        string memory symbol,
        address initialOwner
    ) ERC721(name, symbol) Ownable(initialOwner) {}

    /**
     * @dev Commit to minting an NFT with a secret hash
     * @param secretHash Hash of the secret (SHA256)
     * @param tokenId Desired token ID to mint
     * @param price Price in wei (0 for free)
     * @param buyer Specific buyer address (zero address for open)
     * @param metadataURI Metadata URI for the NFT
     */
    function commitForMint(
        bytes32 secretHash,
        uint256 tokenId,
        uint256 price,
        address buyer,
        string calldata metadataURI
    ) external nonReentrant whenNotPaused {
        if (secretHash == bytes32(0)) revert InvalidSecret();
        if (commitments[tokenId].isActive) revert TokenAlreadyCommitted();
        if (hashToTokenId[secretHash] != 0) revert HashAlreadyUsed();
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

        hashToTokenId[secretHash] = tokenId;

        emit CommitmentCreated(
            tokenId,
            secretHash,
            msg.sender,
            buyer,
            price,
            metadataURI
        );
    }

    /**
     * @dev Reveal secret and mint NFT
     * @param secret The secret that hashes to the committed hash
     * @param tokenId Token ID to mint
     */
    function mintWithSecret(
        bytes32 secret,
        uint256 tokenId
    ) external payable nonReentrant whenNotPaused {
        MintCommitment storage commitment = commitments[tokenId];

        if (!commitment.isActive) revert InvalidCommitment();

        if (block.timestamp > commitment.commitTime + COMMITMENT_TIMEOUT) {
            revert CommitmentExpired();
        }
        if (block.timestamp < commitment.commitTime + MIN_COMMITMENT_TIME) {
            revert CommitmentTooEarly();
        }

        bytes32 computedHash = sha256(abi.encodePacked(secret));
        if (computedHash != commitment.secretHash) revert InvalidSecret();
        if (revealedSecrets[secret]) revert SecretAlreadyRevealed();
        if (commitment.buyer != address(0) && msg.sender != commitment.buyer) {
            revert UnauthorizedCaller();
        }
        if (msg.value != commitment.price) revert InvalidPrice();

        revealedSecrets[secret] = true;
        commitment.isActive = false;

        _safeMint(msg.sender, tokenId);
        _setTokenURI(tokenId, commitment.tokenURI);

        if (commitment.price > 0) {
            (bool success, ) = payable(commitment.seller).call{
                value: msg.value
            }("");
            if (!success) revert PaymentFailed();
        }

        emit SecretRevealed(tokenId, commitment.secretHash, secret, msg.sender);
        emit NFTMinted(tokenId, msg.sender, secret);
    }

    /**
     * @dev Cancel an expired or unwanted commitment
     * @param tokenId Token ID commitment to cancel
     */
    function cancelCommitment(uint256 tokenId) external nonReentrant {
        MintCommitment storage commitment = commitments[tokenId];

        if (!commitment.isActive) revert InvalidCommitment();

        // Only seller can cancel, or anyone after timeout
        bool canCancel = (msg.sender == commitment.seller) ||
            (block.timestamp > commitment.commitTime + COMMITMENT_TIMEOUT);

        if (!canCancel) revert UnauthorizedCaller();

        bytes32 secretHash = commitment.secretHash;
        delete commitments[tokenId];
        delete hashToTokenId[secretHash];

        emit CommitmentCancelled(tokenId, secretHash, commitment.seller);
    }

    /**
     * @dev Get commitment details for a token
     * @param tokenId Token ID to query
     * @return commitment details
     */
    function getCommitment(
        uint256 tokenId
    ) external view returns (MintCommitment memory) {
        return commitments[tokenId];
    }

    /**
     * @dev Check if a commitment is still valid (not expired)
     * @param tokenId Token ID to check
     * @return true if commitment is active and not expired
     */
    function isCommitmentValid(uint256 tokenId) external view returns (bool) {
        MintCommitment storage commitment = commitments[tokenId];
        return
            commitment.isActive &&
            (block.timestamp <= commitment.commitTime + COMMITMENT_TIMEOUT);
    }

    /**
     * @dev Check if enough time has passed since commitment for minting
     * @param tokenId Token ID to check
     * @return true if minimum commitment time has passed
     */
    function canMintNow(uint256 tokenId) external view returns (bool) {
        MintCommitment storage commitment = commitments[tokenId];
        return
            commitment.isActive &&
            (block.timestamp >= commitment.commitTime + MIN_COMMITMENT_TIME) &&
            (block.timestamp <= commitment.commitTime + COMMITMENT_TIMEOUT);
    }

    /**
     * @dev Emergency pause function (only owner)
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause function (only owner)
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Override required by Solidity for multiple inheritance
     */
    function tokenURI(
        uint256 tokenId
    ) public view override(ERC721, ERC721URIStorage) returns (string memory) {
        return super.tokenURI(tokenId);
    }

    /**
     * @dev Override required by Solidity for multiple inheritance
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721, ERC721URIStorage) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /**
     * @dev Withdraw contract balance (only owner, emergency function)
     */
    function withdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool success, ) = payable(owner()).call{value: balance}("");
            require(success, "Withdrawal failed");
        }
    }
}
