import * as anchor from "@coral-xyz/anchor";
import type { Program } from "@coral-xyz/anchor";
import type { SolHtlc } from "../target/types/sol_htlc.ts";
import {
    Keypair,
    PublicKey,
    SystemProgram,
    LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { assert } from "chai";
import { BN } from "bn.js";
import { createHash } from "crypto";
import {
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

const TOKEN_METADATA_PROGRAM_ID = new PublicKey(
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
);

describe("sol-htlc", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const program = anchor.workspace.SolHtlc as Program<SolHtlc>;

    const PRICE = new BN(LAMPORTS_PER_SOL / 10);

    function deriveProgramStatePda(): [PublicKey, number] {
        return PublicKey.findProgramAddressSync(
            [Buffer.from("program_state")],
            program.programId
        );
    }

    function deriveCommitmentPda(tokenId: BN): [PublicKey, number] {
        return PublicKey.findProgramAddressSync(
            [Buffer.from("commitment"), tokenId.toArrayLike(Buffer, "le", 8)],
            program.programId
        );
    }

    function deriveMintPda(tokenId: BN): [PublicKey, number] {
        return PublicKey.findProgramAddressSync(
            [Buffer.from("mint"), tokenId.toArrayLike(Buffer, "le", 8)],
            program.programId
        );
    }

    function deriveMetadataPda(mint: PublicKey): [PublicKey, number] {
        return PublicKey.findProgramAddressSync(
            [
                Buffer.from("metadata"),
                TOKEN_METADATA_PROGRAM_ID.toBuffer(),
                mint.toBuffer(),
            ],
            TOKEN_METADATA_PROGRAM_ID
        );
    }

    function computeSecretHash(secret: Buffer): number[] {
        const hash = createHash("sha256").update(secret).digest();
        return Array.from(hash);
    }

    function generateSecret(): Buffer {
        return Buffer.from(Keypair.generate().secretKey.slice(0, 32));
    }

    let programStatePda: PublicKey;
    let authority: Keypair;
    let seller: Keypair;
    let buyer: Keypair;
    let tokenIdCounter = new BN(0);

    function nextTokenId(): BN {
        tokenIdCounter = tokenIdCounter.add(new BN(1));
        return tokenIdCounter;
    }

    before(async () => {
        authority = Keypair.generate();
        seller = Keypair.generate();
        buyer = Keypair.generate();
        [programStatePda] = deriveProgramStatePda();

        await airdrop(authority.publicKey, LAMPORTS_PER_SOL * 2);
        await airdrop(seller.publicKey, LAMPORTS_PER_SOL * 2);
        await airdrop(buyer.publicKey, LAMPORTS_PER_SOL * 2);

        await program.methods
            .initialize()
            .accounts({
                programState: programStatePda,
                authority: authority.publicKey,
                systemProgram: SystemProgram.programId,
            })
            .signers([authority])
            .rpc();
    });

    it("should initialize program state", async () => {
        const state = await program.account.programState.fetch(programStatePda);
        assert.ok(
            state.authority.equals(authority.publicKey),
            "authority should match"
        );
        assert.equal(
            state.totalMinted.toNumber(),
            0,
            "total minted should be 0"
        );
    });

    it("should create a commitment", async () => {
        const tokenId = nextTokenId();
        const secret = generateSecret();
        const hash = computeSecretHash(secret);

        const [commitmentPda] = deriveCommitmentPda(tokenId);
        const [mintPda] = deriveMintPda(tokenId);

        await program.methods
            .commitForMint(hash, tokenId, PRICE, "Test NFT", "TEST", "https://example.com/nft.json")
            .accounts({
                commitment: commitmentPda,
                mint: mintPda,
                programState: programStatePda,
                seller: seller.publicKey,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            })
            .signers([seller])
            .rpc();

        const commitment = await program.account.commitment.fetch(commitmentPda);
        assert.deepEqual(Array.from(commitment.hash), hash, "hash should match");
        assert.equal(
            commitment.tokenId.toNumber(),
            tokenId.toNumber(),
            "token ID should match"
        );
        assert.equal(
            commitment.price.toNumber(),
            PRICE.toNumber(),
            "price should match"
        );
        assert.ok(
            commitment.seller.equals(seller.publicKey),
            "seller should match"
        );
        assert.equal(commitment.name, "Test NFT", "name should match");
        assert.equal(commitment.symbol, "TEST", "symbol should match");
        assert.equal(
            commitment.uri,
            "https://example.com/nft.json",
            "uri should match"
        );
        assert.equal(commitment.isUsed, false, "should not be used");
    });

    it("should mint NFT with valid secret", async () => {
        const tokenId = nextTokenId();
        const secret = generateSecret();
        const hash = computeSecretHash(secret);

        const [commitmentPda] = deriveCommitmentPda(tokenId);
        const [mintPda] = deriveMintPda(tokenId);
        const [metadataPda] = deriveMetadataPda(mintPda);

        await program.methods
            .commitForMint(hash, tokenId, PRICE, "Mintable NFT", "MINT", "https://example.com/mint.json")
            .accounts({
                commitment: commitmentPda,
                mint: mintPda,
                programState: programStatePda,
                seller: seller.publicKey,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            })
            .signers([seller])
            .rpc();

        const buyerAta = await anchor.utils.token.associatedAddress({
            mint: mintPda,
            owner: buyer.publicKey,
        });

        const sellerBalanceBefore = await provider.connection.getBalance(
            seller.publicKey
        );

        await program.methods
            .mintWithSecret(Array.from(secret), tokenId)
            .accounts({
                commitment: commitmentPda,
                mint: mintPda,
                tokenAccount: buyerAta,
                metadata: metadataPda,
                programState: programStatePda,
                sellerInfo: seller.publicKey,
                buyer: buyer.publicKey,
                tokenProgram: TOKEN_PROGRAM_ID,
                associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
                metadataProgram: TOKEN_METADATA_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            })
            .signers([buyer])
            .rpc();

        const commitment = await program.account.commitment.fetch(commitmentPda);
        assert.equal(commitment.isUsed, true, "commitment should be used");

        const sellerBalanceAfter = await provider.connection.getBalance(
            seller.publicKey
        );
        assert.ok(
            sellerBalanceAfter - sellerBalanceBefore >= PRICE.toNumber(),
            "seller should receive payment"
        );

        const state = await program.account.programState.fetch(programStatePda);
        assert.equal(
            state.totalMinted.toNumber(),
            1,
            "total minted should be 1"
        );
    });

    it("should reject mint with invalid secret", async () => {
        const tokenId = nextTokenId();
        const secret = generateSecret();
        const hash = computeSecretHash(secret);
        const wrongSecret = generateSecret();

        const [commitmentPda] = deriveCommitmentPda(tokenId);
        const [mintPda] = deriveMintPda(tokenId);
        const [metadataPda] = deriveMetadataPda(mintPda);

        await program.methods
            .commitForMint(hash, tokenId, PRICE, "Secret Test", "SEC", "https://example.com/sec.json")
            .accounts({
                commitment: commitmentPda,
                mint: mintPda,
                programState: programStatePda,
                seller: seller.publicKey,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            })
            .signers([seller])
            .rpc();

        const buyerAta = await anchor.utils.token.associatedAddress({
            mint: mintPda,
            owner: buyer.publicKey,
        });

        try {
            await program.methods
                .mintWithSecret(Array.from(wrongSecret), tokenId)
                .accounts({
                    commitment: commitmentPda,
                    mint: mintPda,
                    tokenAccount: buyerAta,
                    metadata: metadataPda,
                    programState: programStatePda,
                    sellerInfo: seller.publicKey,
                    buyer: buyer.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                    associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
                    metadataProgram: TOKEN_METADATA_PROGRAM_ID,
                    systemProgram: SystemProgram.programId,
                    rent: anchor.web3.SYSVAR_RENT_PUBKEY,
                })
                .signers([buyer])
                .rpc();
            assert.fail("Expected error for invalid secret");
        } catch (err: unknown) {
            assert.match(String(err), /Invalid secret/, "should reject invalid secret");
        }
    });

    it("should cancel unused commitment", async () => {
        const tokenId = nextTokenId();
        const secret = generateSecret();
        const hash = computeSecretHash(secret);

        const [commitmentPda] = deriveCommitmentPda(tokenId);
        const [mintPda] = deriveMintPda(tokenId);

        await program.methods
            .commitForMint(hash, tokenId, PRICE, "Cancel Test", "CAN", "https://example.com/can.json")
            .accounts({
                commitment: commitmentPda,
                mint: mintPda,
                programState: programStatePda,
                seller: seller.publicKey,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            })
            .signers([seller])
            .rpc();

        const sellerBalanceBefore = await provider.connection.getBalance(
            seller.publicKey
        );

        await program.methods
            .cancelCommitment()
            .accounts({
                commitment: commitmentPda,
                seller: seller.publicKey,
            })
            .signers([seller])
            .rpc();

        const sellerBalanceAfter = await provider.connection.getBalance(
            seller.publicKey
        );
        assert.ok(
            sellerBalanceAfter > sellerBalanceBefore,
            "seller should receive rent back"
        );

        try {
            await program.account.commitment.fetch(commitmentPda);
            assert.fail("Expected commitment to be closed");
        } catch (err: unknown) {
            assert.match(
                String(err),
                /Account does not exist/,
                "commitment should be closed"
            );
        }
    });

    it("should reject cancel from non-seller", async () => {
        const tokenId = nextTokenId();
        const secret = generateSecret();
        const hash = computeSecretHash(secret);

        const [commitmentPda] = deriveCommitmentPda(tokenId);
        const [mintPda] = deriveMintPda(tokenId);

        await program.methods
            .commitForMint(hash, tokenId, PRICE, "Auth Test", "AUTH", "https://example.com/auth.json")
            .accounts({
                commitment: commitmentPda,
                mint: mintPda,
                programState: programStatePda,
                seller: seller.publicKey,
                tokenProgram: TOKEN_PROGRAM_ID,
                systemProgram: SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            })
            .signers([seller])
            .rpc();

        try {
            await program.methods
                .cancelCommitment()
                .accounts({
                    commitment: commitmentPda,
                    seller: buyer.publicKey,
                })
                .signers([buyer])
                .rpc();
            assert.fail("Expected error for unauthorized cancel");
        } catch (err: unknown) {
            assert.ok(
                String(err).includes("has_one") || String(err).includes("constraint"),
                "should reject unauthorized cancel"
            );
        }
    });

    it("should reject commitment with invalid price", async () => {
        const tokenId = nextTokenId();
        const secret = generateSecret();
        const hash = computeSecretHash(secret);

        const [commitmentPda] = deriveCommitmentPda(tokenId);
        const [mintPda] = deriveMintPda(tokenId);

        try {
            await program.methods
                .commitForMint(hash, tokenId, new BN(0), "Zero Price", "ZERO", "https://example.com/zero.json")
                .accounts({
                    commitment: commitmentPda,
                    mint: mintPda,
                    programState: programStatePda,
                    seller: seller.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                    systemProgram: SystemProgram.programId,
                    rent: anchor.web3.SYSVAR_RENT_PUBKEY,
                })
                .signers([seller])
                .rpc();
            assert.fail("Expected error for zero price");
        } catch (err: unknown) {
            assert.match(String(err), /Invalid price/, "should reject zero price");
        }
    });

    it("should reject commitment with name too long", async () => {
        const tokenId = nextTokenId();
        const secret = generateSecret();
        const hash = computeSecretHash(secret);

        const [commitmentPda] = deriveCommitmentPda(tokenId);
        const [mintPda] = deriveMintPda(tokenId);
        const longName = "A".repeat(33);

        try {
            await program.methods
                .commitForMint(hash, tokenId, PRICE, longName, "LONG", "https://example.com/long.json")
                .accounts({
                    commitment: commitmentPda,
                    mint: mintPda,
                    programState: programStatePda,
                    seller: seller.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                    systemProgram: SystemProgram.programId,
                    rent: anchor.web3.SYSVAR_RENT_PUBKEY,
                })
                .signers([seller])
                .rpc();
            assert.fail("Expected error for name too long");
        } catch (err: unknown) {
            assert.match(String(err), /Name too long/, "should reject long name");
        }
    });

    async function airdrop(pubkey: PublicKey, lamports: number): Promise<void> {
        const sig = await provider.connection.requestAirdrop(pubkey, lamports);
        await confirmTransaction(sig);
    }

    async function confirmTransaction(signature: string): Promise<void> {
        const latestBlockhash = await provider.connection.getLatestBlockhash();
        await provider.connection.confirmTransaction(
            { signature, ...latestBlockhash },
            "confirmed"
        );
    }
});
