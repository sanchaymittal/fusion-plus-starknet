#!/bin/bash

set -e

echo "Testing single contract declaration..."
echo "Working directory: $(pwd)"

echo "Running: sncast --account sepolia declare --network sepolia --contract-name MerkleStorageInvalidator"

# Run with timeout to avoid hanging
sncast --account sepolia declare --network sepolia --contract-name MerkleStorageInvalidator

echo "Declaration completed!"