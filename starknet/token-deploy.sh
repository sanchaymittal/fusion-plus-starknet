#!/bin/bash

# Token deployment script
# This script deploys a mock token contract

# Constructor parameters:
# 1. initial_supply: The initial supply of tokens (in wei/smallest unit)
#    Example: 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff (max uint256)
#    Example: 1000000000000000000000000 (1M tokens with 18 decimals)
# 2. recipient: The address that will receive the initial supply
#    Example: 0x07e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f

sncast --account sepolia \
    deploy \
    --network sepolia \
    --class-hash 0x0063d951efb0c4280df78820f7c101cf2af5032d20e5b0555f9ac7ce24db53fa \
    --constructor-calldata 1000000000000000000000000 0x07e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f