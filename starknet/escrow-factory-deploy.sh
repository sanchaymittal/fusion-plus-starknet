#!/bin/bash

# Escrow Factory deployment script
# This script deploys an escrow factory contract

# Constructor parameters:
# 1. owner: ContractAddress - The owner of the escrow factory
#    Example: 0x07e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f
# 2. src_escrow_class_hash: ClassHash - The class hash for source escrow contracts
#    Example: 0x0044273607fdd72ffc35abad28cac225d4fbc07b6417b4fe06629d14f375de79 (EscrowSrc)
# 3. dst_escrow_class_hash: ClassHash - The class hash for destination escrow contracts  
#    Example: 0x04a82c5b469093970bf754adc7202975d7913828ff54cbea26d5cb01730bdd7c (EscrowDst)
# 4. limit_order_protocol: ContractAddress - The limit order protocol contract address
#    Example: 0x0000000000000000000000000000000000000000000000000000000000000000 (placeholder)
# 5. merkle_invalidator: ContractAddress - The merkle invalidator contract address
#    Example: 0x052dac7266c56d49ca37921650065b72792be66b997658597128a01469c8ad65 (MerkleStorageInvalidator)

sncast --account sepolia \
    deploy \
    --network sepolia \
    --class-hash 0x000f2638f623326822411da7d58109f332aee09e3514babad7d1fe47c6d4bf28 \
    --constructor-calldata 0x07e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f \
    0x071611a403cf1580f794d254d151625d059c4f86888ec4a769520a707dd25888 \
    0x070f394a770fb3c501d08df507abaf8d15929430bdf8a27b250b1044f5cc63f3 \
    0x0 \
    0x07506c30baa88b55c01818014f5d1da55922221c665fe97521fc082494dd87a5