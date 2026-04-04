#!/bin/bash
set -euo pipefail

echo "=== Anonymous Airdrop - Build Script ==="
echo ""

cd "$(dirname "$0")/.."

for cmd in cargo forge; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd is not installed"
        exit 1
    fi
done

echo "Step 1: Building RISC Zero guest program..."
echo "This will compile the zkVM guest and generate the ImageID"
echo ""

export RISC0_DEV_MODE=${RISC0_DEV_MODE:-0}

cargo build --release 2>&1 | tee build.log

echo ""
echo "Step 2: Extracting ImageID..."
IMAGE_ID=$(cargo run --release -- image-id 2>/dev/null || echo "Run 'cargo run --release -- image-id' manually to get the ImageID")

echo ""
echo "Build complete!"
echo "ImageID: $IMAGE_ID"
echo ""
echo "Set this in your .env file as IMAGE_ID=$IMAGE_ID"
