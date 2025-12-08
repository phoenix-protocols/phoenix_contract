# Phoenix Protocol - Token Contracts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-blue.svg)](https://docs.soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-orange.svg)](https://book.getfoundry.sh/)

Phoenix Protocol's core token contracts - PUSD stablecoin, yPUSD yield token, and NFTManager for staking positions.

## Contracts

| Contract | Description |
|----------|-------------|
| **PUSD** | Phoenix USD - Upgradeable stablecoin with mint/burn controls |
| **yPUSD** | Yield-bearing PUSD wrapper token (ERC4626 vault) |
| **NFTManager** | ERC721 NFT representing staking positions |

## Features

- 🔐 **UUPS Upgradeable** - All contracts support secure upgrades
- 🎯 **Role-based Access Control** - Granular permissions with OpenZeppelin AccessControl
- 💰 **ERC4626 Vault** - yPUSD implements standard tokenized vault interface
- 🖼️ **On-chain Metadata** - NFT stake records stored entirely on-chain

## Installation

```bash
# Clone the repository
git clone https://github.com/phoenix-protocols/phoenix_contract.git
cd phoenix_contract

# Install dependencies
forge install

# Build contracts
forge build

# Run tests
forge test
```

## Contract Architecture

```
src/
├── token/
│   ├── PUSD/
│   │   ├── PUSD.sol          # Main PUSD token contract
│   │   └── PUSDStorage.sol   # Storage layout
│   ├── yPUSD/
│   │   ├── yPUSD.sol         # ERC4626 yield token
│   │   └── yPUSDStorage.sol  # Storage layout
│   └── NFTManager/
│       ├── NFTManager.sol    # Staking position NFTs
│       └── NFTManagerStorage.sol
└── interfaces/
    ├── IPUSD.sol
    ├── IyPUSD.sol
    ├── INFTManager.sol
    └── IFarm.sol
```

## Deployment

```bash
# Set environment variables
export ADMIN=0x...
export SALT=0x...
export PUSD_CAP=1000000000000000  # 1B PUSD (6 decimals)

# Deploy PUSD
forge script script/token/PUSD_Deployer.s.sol --rpc-url $RPC_URL --broadcast

# Deploy yPUSD (requires PUSD address)
export PUSD=0x...
export YPUSD_CAP=1000000000000000
forge script script/token/yPUSD_Deployer.s.sol --rpc-url $RPC_URL --broadcast

# Deploy NFTManager
export NAME="Phoenix Stake NFT"
export SYMBOL="pxNFT"
export FARM=0x...  # Can be address(0) initially
forge script script/token/NFTManager_Deployer.s.sol --rpc-url $RPC_URL --broadcast
```

## Security

- ✅ Audited by [Auditor Name - Coming Soon]
- ✅ UUPS upgrade pattern with role-based authorization
- ✅ Reentrancy protection on sensitive functions
- ✅ Supply cap enforcement

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- 🌐 Website: [phoenix.finance](https://phoenix.finance)
- 📖 Documentation: [docs.phoenix.finance](https://docs.phoenix.finance)
- 🐦 Twitter: [@PhoenixProtocol](https://twitter.com/PhoenixProtocol)
- 💬 Discord: [discord.gg/phoenix](https://discord.gg/phoenix)
