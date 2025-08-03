#!/bin/bash

# Starknet contract declaration script using sncast (Starknet Foundry)
# This script only declares contracts - deployments are handled manually

set -e

echo "=== Starknet Contract Declaration ==="
echo "Using account: sepolia"
echo "Network: sepolia"
echo ""

# We're already in the starknet directory
echo "Working directory: $(pwd)"
echo ""

# Create deployment directory if it doesn't exist
mkdir -p deployments

# Initialize deployment log
DEPLOYMENT_FILE="deployments/starknet-sepolia-declared.json"
echo "{" > $DEPLOYMENT_FILE
echo '  "network": "starknet-sepolia",' >> $DEPLOYMENT_FILE
echo '  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",' >> $DEPLOYMENT_FILE
echo '  "declared_contracts": {' >> $DEPLOYMENT_FILE

# Function to declare a contract and save its class hash
declare_contract() {
    local contract_name=$1
    echo "Declaring $contract_name..." >&2
    
    # Declare the contract (redirect debug output to stderr)
    output=$(sncast --account sepolia declare --network sepolia --contract-name $contract_name 2>&1)
    
    # Extract class hash from output
    class_hash=$(echo "$output" | grep "class_hash:" | grep -oE "0x[0-9a-fA-F]+")
    
    # If no class hash found, check if it's already declared
    if [ -z "$class_hash" ]; then
        if echo "$output" | grep -q "is already declared"; then
            # Extract class hash from the "already declared" error message
            class_hash=$(echo "$output" | grep "is already declared" | grep -oE "0x[0-9a-fA-F]+")
            if [ -n "$class_hash" ]; then
                echo "⚠️  $contract_name already declared with class hash: $class_hash" >&2
            else
                echo "Error: Failed to extract class hash from already declared message" >&2
                echo "Output: $output" >&2
                exit 1
            fi
        else
            echo "Error: Failed to declare $contract_name" >&2
            echo "Output: $output" >&2
            exit 1
        fi
    fi
    
    echo "✓ $contract_name declared with class hash: $class_hash" >&2
    # Only output the class hash to stdout for variable capture
    echo "$class_hash"
}

# Declare all contracts
echo "=== Declaring All Contracts ==="

# Declare all contracts needed
MERKLE_CLASS_HASH=$(declare_contract "MerkleStorageInvalidator")
ESCROW_SRC_CLASS_HASH=$(declare_contract "EscrowSrc")
ESCROW_DST_CLASS_HASH=$(declare_contract "EscrowDst")
ESCROW_FACTORY_CLASS_HASH=$(declare_contract "EscrowFactory")
MOCK_TOKEN_CLASS_HASH=$(declare_contract "MockToken")

echo ""
echo "=== All Contracts Declared ==="

# Write declaration info to JSON
cat << EOF >> $DEPLOYMENT_FILE
    "MerkleStorageInvalidator": {
      "classHash": "$MERKLE_CLASS_HASH"
    },
    "EscrowSrc": {
      "classHash": "$ESCROW_SRC_CLASS_HASH"
    },
    "EscrowDst": {
      "classHash": "$ESCROW_DST_CLASS_HASH"
    },
    "EscrowFactory": {
      "classHash": "$ESCROW_FACTORY_CLASS_HASH"
    },
    "MockToken": {
      "classHash": "$MOCK_TOKEN_CLASS_HASH"
    }
  }
}
EOF

echo ""
echo "=== Declaration Complete ==="
echo "MerkleStorageInvalidator class hash: $MERKLE_CLASS_HASH"
echo "EscrowSrc class hash: $ESCROW_SRC_CLASS_HASH"
echo "EscrowDst class hash: $ESCROW_DST_CLASS_HASH"
echo "EscrowFactory class hash: $ESCROW_FACTORY_CLASS_HASH"
echo "MockToken class hash: $MOCK_TOKEN_CLASS_HASH"
echo ""
echo "Declaration config saved to: $DEPLOYMENT_FILE"
echo ""
echo "=== Manual Deployment Commands ==="
echo "You can now deploy specific contracts manually using sncast:"
echo ""
echo "# Deploy MockToken:"
echo "sncast --account sepolia deploy --network sepolia --class-hash $MOCK_TOKEN_CLASS_HASH --constructor-calldata str:TestToken str:TEST 0x152d02c7e14af6800000 0x7e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f 0x7e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f"
echo ""
echo "# Deploy MerkleStorageInvalidator:"
echo "sncast --account sepolia deploy --network sepolia --class-hash $MERKLE_CLASS_HASH"
echo ""
echo "# Deploy EscrowFactory (replace MERKLE_ADDRESS with actual deployed address):"
echo "sncast --account sepolia deploy --network sepolia --class-hash $ESCROW_FACTORY_CLASS_HASH --constructor-calldata 0x7e6062aa6bd572a9e046045d93e52c20b8267bbc9cd89c7156bc9b2853fa20f $ESCROW_SRC_CLASS_HASH $ESCROW_DST_CLASS_HASH 0x0 <MERKLE_ADDRESS>"