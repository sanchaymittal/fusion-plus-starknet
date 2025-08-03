# Cross-Chain Swap Example

This is an example of the [1inch cross-chain resolver](https://github.com/1inch/cross-chain-swap) running swaps between:
- Ethereum to Binance (EVM to EVM)
- Ethereum to Starknet (EVM to Cairo/Starknet)

## Features

- **EVM to EVM swaps**: Traditional cross-chain atomic swaps between Ethereum and Binance
- **EVM to Starknet swaps**: Cross-chain atomic swaps from Ethereum USDC to Starknet mock tokens
- **Cairo implementation**: Complete Cairo/Starknet implementation of the atomic swap contracts
- **Comprehensive testing**: Jest test suite covering both EVM and cross-chain scenarios

## Installation

Install example deps

```shell
pnpm install
```

Install [foundry](https://book.getfoundry.sh/getting-started/installation)

```shell
curl -L https://foundry.paradigm.xyz | bash
```

Install project deps

```shell
pnpm install
```

Install contract deps

```shell
forge install
```

Install Starknet toolchain

```shell
# Install Scarb (Starknet package manager)
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh

# Install Starknet Foundry
curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh
```

## Configuration

Copy the environment file and fill in your configuration:

```shell
cp .env.example .env
```

Required environment variables:

```shell
# EVM chain configuration
SRC_CHAIN_RPC=https://ethereum-rpc-url
DST_CHAIN_RPC=https://binance-rpc-url

# Starknet configuration (for cross-chain tests)
STARKNET_ACCOUNT_ADDRESS=0x...
STARKNET_ACCOUNT_PRIVATE_KEY=0x...
STARKNET_MOCK_TOKEN_ADDRESS=0x...  # Will be set after deployment
```

## Starknet Setup

### 1. Build Starknet Contracts

```shell
npm run build:starknet
```

### 2. Deploy Starknet Contracts

**Using Starknet Foundry (Recommended)**

First, make sure you have a Starknet account configured:
```shell
# Create account (if you don't have one)
sncast account create --name deploy

# Or add existing account  
sncast account add --name deploy --address 0x7e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f --private-key 0x1c6aaf3f632d99997f145c708e4e83db3a02c87c4dea52e406990841933b361
```

**Option 1: Two-step deployment (Recommended)**
```shell
# Step 1: Declare all contracts and get class hashes
npm run declare:starknet

# Step 2: Deploy contracts using class hashes
npm run deploy:starknet-sncast
```

**Option 2: Full deployment in one command**
```shell
npm run deploy:starknet-full
```

**Option 3: JavaScript deployment (fallback)**
```shell
npm run deploy:starknet
```

The deployment will output contract addresses that you should add to your `.env` file.

## Running Tests

### EVM to EVM Tests

Run traditional cross-chain tests between Ethereum and BSC:

```shell
SRC_CHAIN_RPC=ETH_FORK_URL DST_CHAIN_RPC=BNB_FORK_URL pnpm test
```

### Cross-Chain Tests (EVM to Starknet)

Run cross-chain tests from Ethereum to Starknet:

```shell
npm run test:cross-chain
```

### Public rpc

| Chain    | Url                          |
|----------|------------------------------|
| Ethereum | https://eth.merkle.io        |
| BSC      | wss://bsc-rpc.publicnode.com |

## Test accounts

### Available Accounts

```
(0) 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" Owner of EscrowFactory
(1) 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" User
(2) 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" Resolver
```
