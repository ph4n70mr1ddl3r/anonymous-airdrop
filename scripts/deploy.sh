#!/bin/bash
set -euo pipefail

echo "=== Anonymous Airdrop - Deployment Script ==="
echo ""

if [ -z "${PRIVATE_KEY:-}" ]; then
    echo "Error: PRIVATE_KEY environment variable not set"
    exit 1
fi

RPC_URL="${RPC_URL:-https://mainnet.optimism.io}"
CHAIN="${CHAIN:-optimism}"

echo "Network: $CHAIN"
echo "RPC: $RPC_URL"
echo ""

echo "Step 1: Building RISC Zero guest program..."
cd "$(dirname "$0")/.."
RISC0_DEV_MODE=1 cargo build --release
echo ""

echo "Step 2: Installing Foundry dependencies..."
cd contracts
if [ ! -d "lib/risc0-ethereum" ]; then
    forge install risc0/risc0-ethereum --no-commit
fi
if [ ! -d "lib/openzeppelin-contracts" ]; then
    forge install OpenZeppelin/openzeppelin-contracts --no-commit
fi
echo ""

echo "Step 3: Compiling contracts..."
forge build
echo ""

echo "Step 4: Deploying AnonymousAirdrop contract..."

if [ -z "${VERIFIER_ADDRESS:-}" ]; then
    echo "Error: VERIFIER_ADDRESS environment variable not set"
    echo "Deploy the RISC Zero verifier first or use an existing one on Optimism"
    exit 1
fi

if [ -z "${IMAGE_ID:-}" ]; then
    echo "Error: IMAGE_ID environment variable not set"
    echo "Run the guest program to get the image ID"
    exit 1
fi

if [ -z "${TOKEN_ADDRESS:-}" ]; then
    echo "Error: TOKEN_ADDRESS environment variable not set"
    exit 1
fi

if [ -z "${MERKLE_ROOT:-}" ]; then
    echo "Error: MERKLE_ROOT environment variable not set"
    echo "Run the build-tree command first"
    exit 1
fi

AMOUNT_PER_CLAIM="${AMOUNT_PER_CLAIM:-1000000000000000000}"

echo "Verifier: $VERIFIER_ADDRESS"
echo "Image ID: $IMAGE_ID"
echo "Token: $TOKEN_ADDRESS"
echo "Merkle Root: $MERKLE_ROOT"
echo "Amount Per Claim: $AMOUNT_PER_CLAIM"
echo ""

DEPLOY_OUTPUT=$(forge create src/AnonymousAirdrop.sol:AnonymousAirdrop \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --constructor-args \
        "$VERIFIER_ADDRESS" \
        "$IMAGE_ID" \
        "$TOKEN_ADDRESS" \
        "$MERKLE_ROOT" \
        "$AMOUNT_PER_CLAIM" \
    --json)

CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | jq -r '.deployedTo')

echo "Contract deployed to: $CONTRACT_ADDRESS"
echo ""

echo "Step 5: Transferring tokens to airdrop contract..."
TOTAL_TOKENS=$(python3 -c "print($AMOUNT_PER_CLAIM * 32000000)")
echo "Transferring $TOTAL_TOKENS tokens to airdrop contract..."

cast send "$TOKEN_ADDRESS" \
    "transfer(address,uint256)" \
    "$CONTRACT_ADDRESS" \
    "$TOTAL_TOKENS" \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY"

echo ""
echo "=== Deployment Complete ==="
echo "Contract: $CONTRACT_ADDRESS"
echo ""
echo "Next steps:"
echo "1. Verify contract on Etherscan: forge verify-contract $CONTRACT_ADDRESS src/AnonymousAirdrop.sol:AnonymousAirdrop"
echo "2. Start claims: cast send $CONTRACT_ADDRESS 'startClaims()' --rpc-url \$RPC_URL --private-key \$PRIVATE_KEY"
echo "3. Users can now generate proofs and claim tokens"
