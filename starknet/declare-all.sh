#!/bin/bash

# Declare all contracts script
# Make sure you have built the contracts first with: scarb build

echo "Declaring all contracts..."

# Declare each contract
echo "Declaring EscrowFactory..."
sncast --account sepolia declare --network sepolia --contract-name EscrowFactory

echo "Declaring EscrowSrc..."
sncast --account sepolia declare --network sepolia --contract-name EscrowSrc

echo "Declaring EscrowDst..."
sncast --account sepolia declare --network sepolia --contract-name EscrowDst

echo "Declaring BaseEscrow..."
sncast --account sepolia declare --network sepolia --contract-name BaseEscrow

echo "Declaring MerkleVerifier..."
sncast --account sepolia declare --network sepolia --contract-name MerkleVerifier

echo "Declaring MerkleStorageInvalidator..."
sncast --account sepolia declare --network sepolia --contract-name MerkleStorageInvalidator

echo "Declaring BaseExtension..."
sncast --account sepolia declare --network sepolia --contract-name BaseExtension

echo "Declaring MyToken (mock)..."
sncast --account sepolia declare --network sepolia --contract-name MyToken

echo "All contracts declared!"