# Individual Declare Commands

Run these from the `starknet/` directory after building with `scarb build`:

## Core Escrow Contracts
```bash
# Escrow Factory
sncast --account sepolia declare --network sepolia --contract-name EscrowFactory

# Source Escrow
sncast --account sepolia declare --network sepolia --contract-name EscrowSrc

# Destination Escrow
sncast --account sepolia declare --network sepolia --contract-name EscrowDst

# Base Escrow
sncast --account sepolia declare --network sepolia --contract-name BaseEscrow
```

## Supporting Contracts
```bash
# Merkle Verifier
sncast --account sepolia declare --network sepolia --contract-name MerkleVerifier

# Merkle Storage Invalidator
sncast --account sepolia declare --network sepolia --contract-name MerkleStorageInvalidator

# Base Extension (interactions)
sncast --account sepolia declare --network sepolia --contract-name BaseExtension
```

## Mock/Test Contracts
```bash
# Mock Token
sncast --account sepolia declare --network sepolia --contract-name MyToken
```

## Quick Commands

Build first:
```bash
cd starknet && scarb build
```

Declare all at once:
```bash
./declare-all.sh
```