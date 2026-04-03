use alloy_primitives::Address;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use k256::SecretKey;
use methods::airdrop::{AIRDROP_ELF, AIRDROP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    str::FromStr,
};

const MERKLE_TREE_DEPTH: usize = 32;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub path: [[u8; 32]; MERKLE_TREE_DEPTH],
    pub index: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GuestInput {
    pub private_key_bytes: [u8; 32],
    pub merkle_root: [u8; 32],
    pub merkle_proof: MerkleProof,
    pub claimant_address: [u8; 20],
    pub airdrop_contract: [u8; 20],
    pub chain_id: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GuestOutput {
    pub merkle_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub claimant_address: [u8; 20],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClaimProof {
    pub receipt: Receipt,
    pub nullifier: [u8; 32],
    pub claimant_address: [u8; 20],
}

fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hash_leaf(address: &[u8; 20]) -> [u8; 32] {
    Sha256::new().chain_update(address).finalize().into()
}

fn hash_empty() -> [u8; 32] {
    let empty = [0u8; 0];
    Sha256::new().chain_update(&empty).finalize().into()
}

pub fn build_merkle_tree(leaves: &[[u8; 32]]) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
    if leaves.is_empty() {
        let empty = hash_empty();
        return (vec![vec![empty]], empty);
    }

    let mut tree: Vec<Vec<[u8; 32]>> = Vec::with_capacity(MERKLE_TREE_DEPTH + 1);
    tree.push(leaves.to_vec());

    let mut current_level = leaves.to_vec();

    for _ in 0..MERKLE_TREE_DEPTH {
        if current_level.len() == 1 {
            break;
        }

        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                current_level[i]
            };
            next_level.push(sha256_pair(&left, &right));
            i += 2;
        }
        tree.push(next_level);
        current_level = tree.last().unwrap().clone();
    }

    while tree.len() <= MERKLE_TREE_DEPTH {
        let last = *tree.last().unwrap().last().unwrap();
        let parent = sha256_pair(&last, &last);
        tree.push(vec![parent]);
    }

    let root = tree.last().unwrap()[0];
    (tree, root)
}

pub fn get_merkle_proof(tree: &[Vec<[u8; 32]>], index: u64) -> MerkleProof {
    let leaf = tree[0][index as usize];
    let mut path = [[0u8; 32]; MERKLE_TREE_DEPTH];
    let mut current_index = index;

    for depth in 0..MERKLE_TREE_DEPTH {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        let sibling = if sibling_index < tree[depth].len() as u64 {
            tree[depth][sibling_index as usize]
        } else {
            tree[depth][current_index as usize]
        };

        path[depth] = sibling;
        current_index /= 2;
    }

    MerkleProof { leaf, path, index }
}

pub fn parse_csv(csv_path: &PathBuf) -> Result<Vec<([u8; 20], u64)>> {
    let file = File::open(csv_path).context("Failed to open CSV file")?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for (line_idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with("address") || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split(',').collect();
        let address_str = parts[0].trim();

        if !address_str.starts_with("0x") || address_str.len() != 42 {
            eprintln!(
                "Skipping invalid address at line {}: {}",
                line_idx + 1,
                address_str
            );
            continue;
        }

        let address_bytes = hex::decode(&address_str[2..])
            .context(format!("Failed to decode hex address: {}", address_str))?;

        if address_bytes.len() != 20 {
            eprintln!("Invalid address length at line {}", line_idx + 1);
            continue;
        }

        let mut address = [0u8; 20];
        address.copy_from_slice(&address_bytes);
        entries.push((address, line_idx as u64));
    }

    Ok(entries)
}

pub fn build_tree_from_csv(
    csv_path: &PathBuf,
) -> Result<(Vec<Vec<[u8; 32]>>, [u8; 32], HashMap<[u8; 20], u64>)> {
    println!("Parsing CSV file...");
    let entries = parse_csv(csv_path)?;
    println!("Parsed {} eligible addresses", entries.len());

    let mut address_to_index: HashMap<[u8; 20], u64> = HashMap::new();
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(entries.len());
    let mut duplicates = 0u64;

    for (address, _line) in &entries {
        if address_to_index.contains_key(address) {
            duplicates += 1;
            continue;
        }
        let leaf = hash_leaf(address);
        address_to_index.insert(*address, leaves.len() as u64);
        leaves.push(leaf);
    }

    println!("Built {} unique leaves for Merkle tree", leaves.len());
    let (tree, root) = build_merkle_tree(&leaves);

    println!("Merkle root: 0x{}", hex::encode(root));

    Ok((tree, root, address_to_index))
}

pub fn generate_proof(
    private_key_hex: &str,
    claimant_address_hex: &str,
    airdrop_contract_hex: &str,
    chain_id: u64,
    tree: &[Vec<[u8; 32]>],
    merkle_root: [u8; 32],
    address_to_index: &HashMap<[u8; 20], u64>,
) -> Result<ClaimProof> {
    let private_key_bytes = hex::decode(
        private_key_hex
            .strip_prefix("0x")
            .unwrap_or(private_key_hex),
    )
    .context("Failed to decode private key hex")?;

    if private_key_bytes.len() != 32 {
        anyhow::bail!("Private key must be 32 bytes");
    }

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&private_key_bytes);

    let secret_key = SecretKey::from_slice(&pk_bytes).context("Invalid private key")?;

    let eligible_address = derive_address_from_secret_key(&secret_key);

    let index = address_to_index
        .get(&eligible_address)
        .context("Eligible address not found in Merkle tree")?;

    let merkle_proof = get_merkle_proof(tree, *index);

    let claimant_address = parse_address(claimant_address_hex)?;
    let airdrop_contract = parse_address(airdrop_contract_hex)?;

    let mut claimant_bytes = [0u8; 20];
    claimant_bytes.copy_from_slice(&claimant_address);

    let mut contract_bytes = [0u8; 20];
    contract_bytes.copy_from_slice(&airdrop_contract);

    let input = GuestInput {
        private_key_bytes: pk_bytes,
        merkle_root,
        merkle_proof,
        claimant_address: claimant_bytes,
        airdrop_contract: contract_bytes,
        chain_id,
    };

    println!("Generating zero-knowledge proof...");
    let env = ExecutorEnv::builder().write(&input)?.build()?;

    let prover = default_prover();
    let receipt = prover.prove(env, AIRDROP_ELF)?.receipt;

    receipt.verify(AIRDROP_ID)?;

    let output: GuestOutput = receipt.journal.decode()?;

    println!("Proof generated successfully!");
    println!("Nullifier: 0x{}", hex::encode(output.nullifier));
    println!("Claimant: 0x{}", hex::encode(output.claimant_address));

    Ok(ClaimProof {
        receipt,
        nullifier: output.nullifier,
        claimant_address: output.claimant_address,
    })
}

fn derive_address_from_secret_key(secret_key: &SecretKey) -> [u8; 20] {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use tiny_keccak::{Hasher, Keccak};

    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let uncompressed = encoded.as_bytes();
    let pubkey_bytes = &uncompressed[1..];

    let mut hasher = Keccak::v256();
    hasher.update(pubkey_bytes);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

fn parse_address(address_hex: &str) -> Result<Address> {
    let hex_str = address_hex.strip_prefix("0x").unwrap_or(address_hex);
    if hex_str.len() != 40 {
        anyhow::bail!("Address must be 20 bytes (40 hex chars)");
    }
    let bytes = hex::decode(hex_str).context("Failed to decode address hex")?;
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(Address::from(addr))
}

#[derive(Parser)]
#[command(name = "anonymous-airdrop")]
#[command(about = "Anonymous ERC20 Airdrop using RISC Zero")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build Merkle tree from CSV file
    BuildTree {
        #[arg(short, long)]
        csv: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate a claim proof
    GenerateProof {
        #[arg(short, long)]
        tree_file: PathBuf,
        #[arg(short, long)]
        csv: PathBuf,
        #[arg(short, long)]
        claimant: String,
        #[arg(short, long)]
        contract: String,
        #[arg(long, default_value = "10")]
        chain_id: u64,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a claim proof (offline check)
    VerifyProof {
        #[arg(short, long)]
        proof_file: PathBuf,
        #[arg(short, long)]
        merkle_root: String,
    },
    /// Print the Image ID of the guest program
    ImageId,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ImageId => {
            println!("0x{}", hex::encode(AIRDROP_ID));
        }

        Commands::BuildTree { csv, output } => {
            let (_tree, root, address_to_index) = build_tree_from_csv(&csv)?;

            let output_file = output.unwrap_or(PathBuf::from("merkle_tree.json"));

            let tree_data = serde_json::json!({
                "merkle_root": format!("0x{}", hex::encode(root)),
                "total_leaves": address_to_index.len(),
                "csv_path": csv.to_string_lossy(),
            });

            let mut file = File::create(&output_file)?;
            file.write_all(serde_json::to_string_pretty(&tree_data)?.as_bytes())?;

            println!("\nMerkle tree info saved to {}", output_file.display());
            println!("Total eligible addresses: {}", address_to_index.len());
        }

        Commands::GenerateProof {
            tree_file,
            csv,
            claimant,
            contract,
            chain_id,
            output,
        } => {
            let tree_data: serde_json::Value = {
                let content = std::fs::read_to_string(&tree_file)?;
                serde_json::from_str(&content)?
            };

            let merkle_root_hex = tree_data["merkle_root"]
                .as_str()
                .context("Missing merkle_root in tree file")?;
            let merkle_root_bytes = hex::decode(
                merkle_root_hex
                    .strip_prefix("0x")
                    .unwrap_or(merkle_root_hex),
            )
            .context("Invalid merkle root hex")?;
            let mut merkle_root = [0u8; 32];
            merkle_root.copy_from_slice(&merkle_root_bytes);

            let (_tree, _root, address_to_index) = build_tree_from_csv(&csv)?;

            let private_key = std::env::var("PRIVATE_KEY").context(
                "PRIVATE_KEY environment variable not set. Set it with: export PRIVATE_KEY=0x...",
            )?;

            let claim_proof = generate_proof(
                &private_key,
                &claimant,
                &contract,
                chain_id,
                &_tree,
                merkle_root,
                &address_to_index,
            )?;

            let output_file = output.unwrap_or(PathBuf::from("claim_proof.json"));

            let proof_data = serde_json::json!({
                "nullifier": format!("0x{}", hex::encode(claim_proof.nullifier)),
                "claimant_address": format!("0x{}", hex::encode(claim_proof.claimant_address)),
                "receipt": {
                    "seal": hex::encode(claim_proof.receipt.seal),
                    "journal": hex::encode(claim_proof.receipt.journal.bytes),
                },
                "chain_id": chain_id,
            });

            let mut file = File::create(&output_file)?;
            file.write_all(serde_json::to_string_pretty(&proof_data)?.as_bytes())?;

            println!("\nClaim proof saved to {}", output_file.display());
        }

        Commands::VerifyProof {
            proof_file,
            merkle_root,
        } => {
            let proof_data: serde_json::Value = {
                let content = std::fs::read_to_string(&proof_file)?;
                serde_json::from_str(&content)?
            };

            let receipt_data = &proof_data["receipt"];
            let seal_hex = receipt_data["seal"].as_str().context("Missing seal")?;
            let journal_hex = receipt_data["journal"]
                .as_str()
                .context("Missing journal")?;

            let seal = hex::decode(seal_hex).context("Invalid seal hex")?;
            let journal_bytes = hex::decode(journal_hex).context("Invalid journal hex")?;

            let receipt = Receipt {
                seal,
                journal: risc0_zkvm::Journal::new(journal_bytes),
            };

            receipt.verify(AIRDROP_ID)?;

            let root_bytes = hex::decode(merkle_root.strip_prefix("0x").unwrap_or(&merkle_root))
                .context("Invalid merkle root hex")?;
            let mut merkle_root_arr = [0u8; 32];
            merkle_root_arr.copy_from_slice(&root_bytes);

            let output: GuestOutput = receipt.journal.decode()?;

            assert_eq!(output.merkle_root, merkle_root_arr, "Merkle root mismatch");

            println!("Proof verified successfully!");
            println!("Nullifier: 0x{}", hex::encode(output.nullifier));
            println!("Claimant: 0x{}", hex::encode(output.claimant_address));
        }
    }

    Ok(())
}
