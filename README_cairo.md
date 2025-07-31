# Cross-Chain Swap Cairo Implementation

This is a Cairo/Starknet implementation of the cross-chain atomic swap contracts, converted from the original Solidity version.

## Overview

The contracts implement a trustless cross-chain atomic swap mechanism using:

- **Hashlock**: Secret-based validation for atomic operations
- **Timelock**: Multi-stage time-based access control
- **Merkle Validation**: Support for partial fills using merkle proofs
- **Pre/Post Interactions**: Callback system for extensible order processing

## Contract Architecture

### Core Components

1. **Hashlock** (`src/hashlock.cairo`)
   - Validates secrets against pre-committed hashes
   - Uses Keccak256 for hash computation
   - Provides `HashlockValidator` for reusable validation logic

2. **Timelock** (`src/timelock.cairo`)
   - Manages different phases of atomic swap lifecycle
   - Supports 7 distinct stages with packed storage
   - Handles withdrawal and cancellation periods for both chains

3. **Merkle Validator** (`src/merkle_validator.cairo`)
   - Enables partial fills through merkle tree validation
   - Implements `MerkleStorageInvalidator` for leaf tracking
   - Supports both single and multi-proof verification

4. **Interactions** (`src/interactions.cairo`)
   - Pre-interaction: Called before fund transfers
   - Post-interaction: Called after fund transfers  
   - Taker-interaction: Called between maker→taker and taker→maker transfers

### Escrow Contracts

5. **Base Escrow** (`src/escrow_base.cairo`)
   - Abstract base with common atomic swap functionality
   - Implements core withdrawal, cancellation, and rescue logic
   - Uses OpenZeppelin components for ownership and reentrancy protection

6. **Source Escrow** (`src/escrow_src.cairo`)
   - Handles escrow operations on the source chain
   - Supports private/public withdrawal and cancellation modes
   - Multiple timelock stages for flexible access control

7. **Destination Escrow** (`src/escrow_dst.cairo`)
   - Manages escrow operations on destination chain
   - Simpler lifecycle compared to source escrow
   - Public withdrawal and private cancellation

8. **Escrow Factory** (`src/escrow_factory.cairo`)
   - Deploys escrow contracts with deterministic addresses
   - Integrates with limit order protocol through interaction interfaces
   - Handles partial fills via merkle proof validation

## Key Features

### Timelock Stages

The contracts support 7 distinct timelock stages:

- `DstWithdrawal`: Private withdrawal on destination chain
- `DstPublicWithdrawal`: Public withdrawal on destination chain  
- `DstCancellation`: Cancellation period on destination chain
- `SrcWithdrawal`: Private withdrawal on source chain
- `SrcPublicWithdrawal`: Public withdrawal on source chain
- `SrcCancellation`: Private cancellation on source chain
- `SrcPublicCancellation`: Public cancellation on source chain

### Security Features

- **Reentrancy Protection**: All state-changing functions protected
- **Access Control**: Role-based permissions using OpenZeppelin
- **Immutable Validation**: Strict validation of contract parameters
- **Emergency Rescue**: Owner can rescue funds after long delay

### Gas Optimization

- **Packed Storage**: Timelocks stored in single `u256`
- **Efficient Hashing**: Optimized merkle proof verification
- **Minimal Deployments**: Factory pattern for escrow creation

## Usage

### Building

```bash
scarb build
```

### Testing

```bash
snforge test
```

### Deployment

1. Deploy the `MerkleStorageInvalidator`
2. Deploy the `EscrowFactory` with escrow class hashes
3. Configure with limit order protocol integration

## Differences from Solidity Version

1. **Storage**: Uses Starknet's storage system instead of packed structs
2. **Events**: Cairo events with indexed keys for efficient querying
3. **Error Handling**: Uses Cairo's assert system with custom error messages
4. **Components**: Leverages OpenZeppelin Cairo components for standard functionality
5. **Address Calculation**: Uses Starknet's deterministic deployment system

## Security Considerations

- All time-based operations use block timestamps
- Proper validation of immutable parameters across all functions
- Protection against common attack vectors (reentrancy, front-running)
- Emergency mechanisms for fund recovery

## Integration

The contracts are designed to integrate with:

- Starknet limit order protocols
- Cross-chain bridge systems
- DeFi applications requiring atomic swaps
- Multi-chain trading platforms

For detailed function documentation, see the inline comments in each contract file.