import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

// Local deployment
export default buildModule("NFTSecretMintModule", (m) => {
  // Deploy parameters - these can be overridden during deployment
  const name = m.getParameter("name", "CrossChain Secret NFT");
  const symbol = m.getParameter("symbol", "CCSNFT");
  
  // Get the deployer account as initial owner
  const deployer = m.getAccount(0);
  const initialOwner = m.getParameter("initialOwner", deployer);

  // Deploy the NFTSecretMint contract
  const nftContract = m.contract("NFTSecretMint", [
    name,
    symbol,
    initialOwner
  ]);

  return { nftContract };
});

// Testnet deployment
// export const TestnetModule = buildModule("NFTSecretMintTestnet", (m) => {
//   const deployer = m.getAccount(0);
  
//   const nftContract = m.contract("NFTSecretMint", [
//     "CrossChain Secret NFT Testnet",
//     "CCSNFT-TEST", 
//     deployer
//   ]);

//   return { nftContract };
// });
