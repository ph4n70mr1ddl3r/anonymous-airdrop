# Anonymous ERC20 Airdrop using RISC Zero

A privacy-preserving ERC20 token airdrop system built on Optimism using RISC Zero zkVM. This system allows eligible Ethereum account holders to claim airdropped tokens at a **different address** of their choosing, with **no on-chain link** between the eligible address and the claimant address.

## Architecture

### Privacy Model

- **Eligible addresses** are committed to a Merkle tree (root published on-chain)
- **Claimants** prove knowledge of the private key for an eligible address inside a RISC Zero zkVM
- A **nullifier** is computed as `SHA256("airdrop-nullifier" || private_key || contract_address || chain_id)` to prevent double-claiming
- The zkVM produces a **zero-knowledge proof** that verifies:
  1. The claimant knows the private key for an address in the Merkle tree
  2. The nullifier is correctly computed
  3. The claimant address is the one receiving tokens
- The eligible address is **never revealed** on-chain

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                       CSV File                               │
│              (32M+ eligible addresses)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Merkle Tree Builder                         │
│           (host/src/main.rs - BuildTree command)             │
│                                                              │
│  - Parses CSV, hashes each address with SHA256              │
│  - Builds Merkle tree, outputs root                         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Proof Generator                            │
│          (host/src/main.rs - GenerateProof command)          │
│                                                              │
│  - Takes private key + claimant address                     │
│  - Derives eligible address from private key                │
│  - Gets Merkle proof for eligible address                   │
│  - Runs zkVM guest program                                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    zkVM Guest Program                        │
│              (methods/guest/src/bin/airdrop.rs)              │
│                                                              │
│  1. Derive Ethereum address from private key (keccak256)    │
│  2. Hash address to get Merkle leaf (SHA256)                │
│  3. Verify Merkle proof against published root              │
│  4. Compute nullifier = SHA256(prefix || pk || contract ||  │
│     chain_id)                                                │
│  5. Commit {merkle_root, nullifier, claimant_address}       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               On-Chain Verification                          │
│           (contracts/src/AnonymousAirdrop.sol)               │
│                                                              │
│  1. Verify RISC Zero receipt via IRiscZeroVerifier          │
│  2. Decode journal to get output                            │
│  3. Check merkle_root matches                               │
│  4. Check nullifier not already used                        │
│  5. Transfer tokens to claimant_address                     │
│  6. Mark nullifier as used                                  │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
anonymous-airdrop/
├── Cargo.toml                          # Rust workspace
├── host/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs                     # Host: tree builder + proof generator
├── methods/
│   ├── Cargo.toml
│   ├── build.rs
│   ├── guest/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── bin/
│   │           └── airdrop.rs          # zkVM guest program
│   └── src/
│       └── lib.rs
├── contracts/
│   ├── foundry.toml
│   ├── src/
│   │   └── AnonymousAirdrop.sol        # On-chain airdrop contract
│   └── test/
│       └── AnonymousAirdrop.t.sol      # Foundry tests
├── scripts/
│   ├── build.sh                        # Build script
│   └── deploy.sh                       # Deployment script
├── sample_eligible.csv                 # Example CSV format
└── .env.example                        # Environment variables template
```

## Setup

### Prerequisites

- Rust 1.80+
- RISC Zero toolchain (`cargo install cargo-risczero`)
- Foundry (`curl -L https://foundry.paradigm.xyz | bash`)
- Docker (for deterministic builds)
- Node.js (for some utilities)

### Install Dependencies

```bash
# Install RISC Zero toolchain
cargo risczero install

# Install Foundry dependencies
cd contracts
forge install risc0/risc0-ethereum --no-commit
forge install OpenZeppelin/openzeppelin-contracts --no-commit
cd ..
```

## Usage

### 1. Build the Guest Program

```bash
RISC0_DEV_MODE=1 cargo build --release
```

For production (deterministic build with Docker):
```bash
RISC0_USE_DOCKER=1 cargo build --release
```

Note the **ImageID** from the build output.

### 2. Build Merkle Tree from CSV

Your CSV file should have one Ethereum address per line:

```csv
address
0x1234567890abcdef1234567890abcdef12345678
0xabcdef1234567890abcdef1234567890abcdef12
...
```

Build the tree:
```bash
cargo run --release -- build-tree \
    --csv eligible_addresses.csv \
    --output merkle_tree.json
```

This outputs the Merkle root. Set it in your environment:
```bash
export MERKLE_ROOT=0x<root_from_output>
```

### 3. Deploy the Contract

```bash
source .env

# Deploy
./scripts/deploy.sh

# Or manually:
forge create contracts/src/AnonymousAirdrop.sol:AnonymousAirdrop \
    --rpc-url $OPTIMISM_RPC_URL \
    --private-key $PRIVATE_KEY \
    --constructor-args \
        $VERIFIER_ADDRESS \
        $IMAGE_ID \
        $TOKEN_ADDRESS \
        $MERKLE_ROOT \
        $AMOUNT_PER_CLAIM
```

### 4. Transfer Tokens to Contract

```bash
cast send $TOKEN_ADDRESS \
    "transfer(address,uint256)" \
    $AIRDROP_CONTRACT_ADDRESS \
    $TOTAL_AMOUNT \
    --rpc-url $OPTIMISM_RPC_URL \
    --private-key $PRIVATE_KEY
```

### 5. Start Claims

```bash
cast send $AIRDROP_CONTRACT_ADDRESS \
    "startClaims()" \
    --rpc-url $OPTIMISM_RPC_URL \
    --private-key $PRIVATE_KEY
```

### 6. Generate Claim Proof (User Side)

A user who knows the private key of an eligible address:

```bash
cargo run --release -- generate-proof \
    --tree-file merkle_tree.json \
    --private-key 0x<eligible_account_private_key> \
    --claimant 0x<your_receiving_address> \
    --contract 0x<airdrop_contract_address> \
    --chain-id 10 \
    --output claim_proof.json
```

This generates a proof file containing:
- `nullifier` - unique identifier for this claim
- `claimant_address` - address to receive tokens
- `receipt` - RISC Zero proof (seal + journal)

### 7. Submit Claim On-Chain

```bash
# Extract values from claim_proof.json
NULLIFIER=$(jq -r '.nullifier' claim_proof.json)
SEAL=$(jq -r '.receipt.seal' claim_proof.json)
JOURNAL=$(jq -r '.receipt.journal' claim_proof.json)

# Submit claim
cast send $AIRDROP_CONTRACT_ADDRESS \
    "claim(bytes,bytes,bytes32)" \
    "0x$SEAL" \
    "0x$JOURNAL" \
    "$NULLIFIER" \
    --rpc-url $OPTIMISM_RPC_URL \
    --private-key $CLAIMANT_PRIVATE_KEY
```

### 8. Verify a Proof (Offline)

```bash
cargo run --release -- verify-proof \
    --proof-file claim_proof.json \
    --merkle-root $MERKLE_ROOT
```

## How Privacy Works

### What is Public On-Chain
- Merkle root of eligible addresses
- Nullifier (a hash, not the address)
- Claimant receiving address
- RISC Zero proof

### What is Private
- Eligible address (never revealed)
- Private key of eligible address (never revealed)
- Link between eligible address and claimant address

### Nullifier Design

The nullifier is computed as:
```
nullifier = SHA256("airdrop-nullifier" || private_key || contract_address || chain_id)
```

This ensures:
- **Uniqueness**: Each eligible account can only claim once per contract
- **Non-linkability**: The nullifier reveals nothing about the eligible address
- **Contract-specific**: The same private key can claim on different contracts
- **Chain-specific**: Prevents cross-chain replay

### Zero-Knowledge Proof

The RISC Zero zkVM guest program proves:
1. It knows a 32-byte private key
2. The corresponding Ethereum address is in the Merkle tree (via Merkle proof verification)
3. The nullifier is correctly derived from the private key
4. The claimant address is correctly committed

The on-chain contract verifies the proof and trusts the journal output without learning the eligible address.

## Performance Considerations

### For 32M+ Addresses

- **Merkle tree depth**: 32 levels (supports up to 4 billion leaves)
- **Tree building**: Single-pass CSV parsing, ~few minutes for 32M addresses
- **Proof generation**: ~5-15 minutes with local proving (depends on hardware)
- **On-chain gas**: ~500k-800k gas per claim (Groth16 verification + token transfer)

### Proving Options

| Mode | Speed | Cost | Use Case |
|------|-------|------|----------|
| Dev mode | Instant | Free | Development/testing |
| Local proving | 5-15 min | Free (CPU) | Small scale |
| Bonsai | 1-3 min | Paid | Production |
| Boundless | 1-3 min | Market rate | Production |

## Security Considerations

1. **Private key handling**: The private key is only used in the zkVM guest and never leaves the user's machine
2. **Double-claim prevention**: Nullifier tracking ensures each eligible account claims only once
3. **Merkle root immutability**: The root is set at deployment and cannot be changed
4. **Emergency withdrawal**: Contract owner can withdraw remaining tokens if needed
5. **Pause mechanism**: Claims can be paused in case of issues

## Testing

```bash
# Run Foundry tests
cd contracts
forge test -vvv

# Run Rust tests (dev mode)
RISC0_DEV_MODE=1 cargo test
```

## License

MIT
