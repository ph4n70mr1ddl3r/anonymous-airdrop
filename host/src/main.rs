use alloy_primitives::Address;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use k256::SecretKey;
use methods::{AIRDROP_ELF, AIRDROP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
};
use zeroize::Zeroize;

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

fn decode_journal_output(journal_bytes: &[u8]) -> Result<GuestOutput> {
    anyhow::ensure!(
        journal_bytes.len() == 96,
        "Invalid journal: expected 96 bytes, got {}",
        journal_bytes.len()
    );
    anyhow::ensure!(
        journal_bytes[84..96].iter().all(|&b| b == 0),
        "Invalid journal: non-zero padding bytes"
    );
    Ok(GuestOutput {
        merkle_root: journal_bytes[0..32].try_into()?,
        nullifier: journal_bytes[32..64].try_into()?,
        claimant_address: journal_bytes[64..84].try_into()?,
    })
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

pub fn get_merkle_proof(tree: &[Vec<[u8; 32]>], index: u64) -> Result<MerkleProof> {
    if tree.is_empty() || tree[0].is_empty() {
        anyhow::bail!("Cannot generate Merkle proof for empty tree");
    }
    if tree.len() <= MERKLE_TREE_DEPTH {
        anyhow::bail!(
            "Tree has insufficient depth ({} levels, need {})",
            tree.len(),
            MERKLE_TREE_DEPTH + 1
        );
    }
    if index as usize >= tree[0].len() {
        anyhow::bail!(
            "Index {} out of bounds (tree has {} leaves)",
            index,
            tree[0].len()
        );
    }

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

    Ok(MerkleProof { leaf, path, index })
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

        let hex_part = &address_str[2..];
        let lower = hex_part.to_lowercase();
        let checksummed = format!("0x{}", lower);
        let address_bytes = hex::decode(&lower)
            .context(format!("Failed to decode hex address: {}", address_str))?;

        if address_bytes.len() != 20 {
            eprintln!("Invalid address length at line {}", line_idx + 1);
            continue;
        }

        if address_str != checksummed {
            let has_upper = hex_part.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = hex_part.chars().any(|c| c.is_ascii_lowercase());
            if has_upper && has_lower {
                eprintln!(
                    "Warning: Address at line {} may have invalid EIP-55 checksum: {}",
                    line_idx + 1,
                    address_str
                );
            }
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

    if duplicates > 0 {
        println!("Warning: {} duplicate addresses skipped", duplicates);
    }
    println!("Built {} unique leaves for Merkle tree", leaves.len());

    if entries.len() > 1_000_000 {
        eprintln!(
            "Warning: Building tree with {} leaves. This may require significant memory (~2GB per 1M leaves).",
            leaves.len()
        );
    }

    let mut paired: Vec<([u8; 20], [u8; 32])> = address_to_index
        .iter()
        .map(|(&addr, _)| {
            let leaf = hash_leaf(&addr);
            (addr, leaf)
        })
        .collect();
    paired.sort_by(|a, b| a.0.cmp(&b.0));
    leaves = paired.iter().map(|(_, leaf)| *leaf).collect();
    address_to_index.clear();
    for (i, (addr, _)) in paired.iter().enumerate() {
        address_to_index.insert(*addr, i as u64);
    }
    println!("Leaves sorted canonically by address");

    let (tree, root) = build_merkle_tree(&leaves);

    println!("Merkle root: 0x{}", hex::encode(root));

    Ok((tree, root, address_to_index))
}

fn build_tree_from_saved(leaves: &[[u8; 32]]) -> (Vec<Vec<[u8; 32]>>, [u8; 32]) {
    println!(
        "Rebuilding Merkle tree from {} saved leaves...",
        leaves.len()
    );
    let (tree, root) = build_merkle_tree(leaves);
    println!("Merkle root: 0x{}", hex::encode(root));
    (tree, root)
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
    let mut private_key_bytes = hex::decode(
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
    private_key_bytes.zeroize();

    let secret_key = SecretKey::from_slice(&pk_bytes).context("Invalid private key")?;

    let eligible_address = derive_address_from_secret_key(&secret_key);

    let index = address_to_index
        .get(&eligible_address)
        .context("Eligible address not found in Merkle tree")?;

    let merkle_proof = get_merkle_proof(tree, *index)?;

    let claimant_address = parse_address(claimant_address_hex)?;
    let airdrop_contract = parse_address(airdrop_contract_hex)?;

    let mut claimant_bytes = [0u8; 20];
    claimant_bytes.copy_from_slice(claimant_address.as_slice());

    let mut contract_bytes = [0u8; 20];
    contract_bytes.copy_from_slice(airdrop_contract.as_slice());

    let input = GuestInput {
        private_key_bytes: pk_bytes,
        merkle_root,
        merkle_proof,
        claimant_address: claimant_bytes,
        airdrop_contract: contract_bytes,
        chain_id,
    };

    pk_bytes.zeroize();

    println!("Generating zero-knowledge proof...");
    let env = ExecutorEnv::builder().write(&input)?.build()?;

    let prover = default_prover();
    let receipt = prover.prove(env, AIRDROP_ELF)?.receipt;

    receipt
        .verify(AIRDROP_ID)
        .map_err(|e| anyhow::anyhow!("Receipt verification failed: {:?}", e))?;

    let output = decode_journal_output(&receipt.journal.bytes)?;

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
        csv: Option<PathBuf>,
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
            let id_bytes: Vec<u8> = AIRDROP_ID.iter().flat_map(|&w| w.to_be_bytes()).collect();
            println!("0x{}", hex::encode(id_bytes));
        }

        Commands::BuildTree { csv, output } => {
            let (_tree, root, address_to_index) = build_tree_from_csv(&csv)?;

            let output_file = output.unwrap_or(PathBuf::from("merkle_tree.json"));

            let mut leaves_hex = Vec::with_capacity(address_to_index.len());
            let mut addr_entries: Vec<(&[u8; 20], &u64)> = address_to_index.iter().collect();
            addr_entries.sort_by_key(|(_, idx)| *idx);

            for (addr, idx) in &addr_entries {
                let leaf = hash_leaf(addr);
                leaves_hex.push((format!("0x{}", hex::encode(leaf)), *idx));
            }

            let mut addr_map = serde_json::Map::new();
            for (addr, idx) in &addr_entries {
                addr_map.insert(
                    format!("0x{}", hex::encode(addr)),
                    serde_json::Value::Number((**idx).into()),
                );
            }

            let leaves_array: Vec<serde_json::Value> = leaves_hex
                .into_iter()
                .map(|(h, _)| serde_json::Value::String(h))
                .collect();

            let tree_data = serde_json::json!({
                "merkle_root": format!("0x{}", hex::encode(root)),
                "total_leaves": address_to_index.len(),
                "csv_path": csv.to_string_lossy(),
                "leaves": leaves_array,
                "address_to_index": addr_map,
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

            let (tree, _root, address_to_index) = if let Some(leaves_arr) =
                tree_data.get("leaves").and_then(|v| v.as_array())
            {
                if leaves_arr.is_empty() {
                    anyhow::bail!("Tree file contains no leaves");
                }

                let addr_map_obj = tree_data
                    .get("address_to_index")
                    .and_then(|v| v.as_object())
                    .context("Tree file missing address_to_index mapping")?;

                let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(leaves_arr.len());
                for leaf_hex in leaves_arr {
                    let hex_str = leaf_hex
                        .as_str()
                        .context("Invalid leaf entry in tree file")?;
                    let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))?;
                    let mut leaf = [0u8; 32];
                    leaf.copy_from_slice(&bytes);
                    leaves.push(leaf);
                }

                let mut address_to_index: HashMap<[u8; 20], u64> = HashMap::new();
                for (addr_hex, idx_val) in addr_map_obj {
                    let idx = idx_val
                        .as_u64()
                        .context("Invalid index in address_to_index")?;
                    let addr_bytes = hex::decode(addr_hex.strip_prefix("0x").unwrap_or(addr_hex))?;
                    let mut addr = [0u8; 20];
                    addr.copy_from_slice(&addr_bytes);
                    address_to_index.insert(addr, idx);
                }

                let (tree, root) = build_tree_from_saved(&leaves);
                anyhow::ensure!(
                    root == merkle_root,
                    "Rebuilt merkle root does not match stored root"
                );
                (tree, root, address_to_index)
            } else if let Some(csv_path) = csv {
                let (tree, root, address_to_index) = build_tree_from_csv(&csv_path)?;
                anyhow::ensure!(
                    root == merkle_root,
                    "Rebuilt merkle root does not match tree file root"
                );
                (tree, root, address_to_index)
            } else {
                anyhow::bail!(
                    "Tree file does not contain leaf data. Provide --csv to rebuild from CSV."
                );
            };

            let private_key = std::env::var("PRIVATE_KEY").context(
                "PRIVATE_KEY environment variable not set. Set it with: export PRIVATE_KEY=0x...",
            )?;

            let claim_proof = generate_proof(
                &private_key,
                &claimant,
                &contract,
                chain_id,
                &tree,
                merkle_root,
                &address_to_index,
            )?;

            let output_file = output.unwrap_or(PathBuf::from("claim_proof.json"));

            let proof_data = serde_json::json!({
                "nullifier": format!("0x{}", hex::encode(claim_proof.nullifier)),
                "claimant_address": format!("0x{}", hex::encode(claim_proof.claimant_address)),
                "receipt": serde_json::to_value(&claim_proof.receipt)?,
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

            let receipt: Receipt = serde_json::from_value(proof_data["receipt"].clone())
                .context("Failed to deserialize receipt")?;

            receipt
                .verify(AIRDROP_ID)
                .map_err(|e| anyhow::anyhow!("Receipt verification failed: {:?}", e))?;

            let root_bytes = hex::decode(merkle_root.strip_prefix("0x").unwrap_or(&merkle_root))
                .context("Invalid merkle root hex")?;
            let mut merkle_root_arr = [0u8; 32];
            merkle_root_arr.copy_from_slice(&root_bytes);

            let output = decode_journal_output(&receipt.journal.bytes)?;

            assert_eq!(output.merkle_root, merkle_root_arr, "Merkle root mismatch");

            println!("Proof verified successfully!");
            println!("Nullifier: 0x{}", hex::encode(output.nullifier));
            println!("Claimant: 0x{}", hex::encode(output.claimant_address));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sha256_pair_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash1 = sha256_pair(&left, &right);
        let hash2 = sha256_pair(&left, &right);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_pair_order_matters() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        assert_ne!(sha256_pair(&left, &right), sha256_pair(&right, &left));
    }

    #[test]
    fn test_hash_leaf_consistency() {
        let addr = [0x11u8; 20];
        let hash1 = hash_leaf(&addr);
        let hash2 = hash_leaf(&addr);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_leaf_different_addresses() {
        let addr1 = [0x11u8; 20];
        let addr2 = [0x22u8; 20];
        assert_ne!(hash_leaf(&addr1), hash_leaf(&addr2));
    }

    #[test]
    fn test_hash_empty_deterministic() {
        let h1 = hash_empty();
        let h2 = hash_empty();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_build_merkle_tree_empty() {
        let (tree, root) = build_merkle_tree(&[]);
        assert_eq!(tree.len(), 1);
        assert_eq!(root, hash_empty());
    }

    #[test]
    fn test_build_merkle_tree_single_leaf() {
        let leaf = hash_leaf(&[1u8; 20]);
        let (tree, _root) = build_merkle_tree(&[leaf]);
        assert_eq!(tree[0].len(), 1);
        assert_eq!(tree[0][0], leaf);
        assert_eq!(tree.len(), MERKLE_TREE_DEPTH + 1);
    }

    #[test]
    fn test_build_merkle_tree_two_leaves() {
        let leaf1 = hash_leaf(&[1u8; 20]);
        let leaf2 = hash_leaf(&[2u8; 20]);
        let (tree, _root) = build_merkle_tree(&[leaf1, leaf2]);
        assert_eq!(tree[0].len(), 2);
        assert_eq!(tree[1].len(), 1);
        assert_eq!(tree[1][0], sha256_pair(&leaf1, &leaf2));
    }

    #[test]
    fn test_build_merkle_tree_three_leaves() {
        let leaf1 = hash_leaf(&[1u8; 20]);
        let leaf2 = hash_leaf(&[2u8; 20]);
        let leaf3 = hash_leaf(&[3u8; 20]);
        let (tree, _root) = build_merkle_tree(&[leaf1, leaf2, leaf3]);
        assert_eq!(tree[0].len(), 3);
        let level1_0 = sha256_pair(&leaf1, &leaf2);
        let level1_1 = sha256_pair(&leaf3, &leaf3);
        assert_eq!(tree[1][0], level1_0);
        assert_eq!(tree[1][1], level1_1);
    }

    #[test]
    fn test_merkle_proof_single_leaf() {
        let leaf = hash_leaf(&[1u8; 20]);
        let (tree, root) = build_merkle_tree(&[leaf]);
        let proof = get_merkle_proof(&tree, 0).unwrap();
        assert_eq!(proof.leaf, leaf);
        for i in 0..MERKLE_TREE_DEPTH {
            assert_eq!(proof.path[i], tree[i][0]);
        }
        let mut current = proof.leaf;
        let mut index = proof.index;
        for i in 0..MERKLE_TREE_DEPTH {
            if index & 1 == 0 {
                current = sha256_pair(&current, &proof.path[i]);
            } else {
                current = sha256_pair(&proof.path[i], &current);
            }
            index >>= 1;
        }
        assert_eq!(current, root, "Proof verification should produce the root");
    }

    #[test]
    fn test_merkle_proof_two_leaves() {
        let leaf0 = hash_leaf(&[1u8; 20]);
        let leaf1 = hash_leaf(&[2u8; 20]);
        let (tree, root) = build_merkle_tree(&[leaf0, leaf1]);

        let proof0 = get_merkle_proof(&tree, 0).unwrap();
        assert_eq!(proof0.leaf, leaf0);
        assert_eq!(proof0.path[0], leaf1);

        let proof1 = get_merkle_proof(&tree, 1).unwrap();
        assert_eq!(proof1.leaf, leaf1);
        assert_eq!(proof1.path[0], leaf0);

        let mut current = proof0.leaf;
        let mut index = proof0.index;
        for i in 0..MERKLE_TREE_DEPTH {
            if index & 1 == 0 {
                current = sha256_pair(&current, &proof0.path[i]);
            } else {
                current = sha256_pair(&proof0.path[i], &current);
            }
            index >>= 1;
        }
        assert_eq!(current, root, "Proof verification should produce the root");
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let leaf = hash_leaf(&[1u8; 20]);
        let (tree, _) = build_merkle_tree(&[leaf]);
        assert!(get_merkle_proof(&tree, 1).is_err());
    }

    #[test]
    fn test_merkle_proof_empty_tree() {
        let (tree, _) = build_merkle_tree(&[]);
        assert!(get_merkle_proof(&tree, 0).is_err());
    }

    #[test]
    fn test_decode_journal_output_valid() {
        let mut journal = [0u8; 96];
        journal[0..32].copy_from_slice(&[1u8; 32]);
        journal[32..64].copy_from_slice(&[2u8; 32]);
        journal[64..84].copy_from_slice(&[3u8; 20]);
        let output = decode_journal_output(&journal).unwrap();
        assert_eq!(output.merkle_root, [1u8; 32]);
        assert_eq!(output.nullifier, [2u8; 32]);
        assert_eq!(output.claimant_address, [3u8; 20]);
    }

    #[test]
    fn test_decode_journal_output_wrong_length() {
        let journal = [0u8; 95];
        assert!(decode_journal_output(&journal).is_err());
    }

    #[test]
    fn test_decode_journal_output_nonzero_padding() {
        let mut journal = [0u8; 96];
        journal[90] = 1;
        assert!(decode_journal_output(&journal).is_err());
    }

    #[test]
    fn test_parse_csv_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0x1111111111111111111111111111111111111111").unwrap();
        writeln!(file, "0x2222222222222222222222222222222222222222").unwrap();
        file.flush().unwrap();

        let entries = parse_csv(&file.path().to_path_buf()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, [0x11u8; 20]);
        assert_eq!(entries[1].0, [0x22u8; 20]);
    }

    #[test]
    fn test_parse_csv_skips_invalid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0x1111111111111111111111111111111111111111").unwrap();
        writeln!(file, "invalid").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "# comment").unwrap();
        writeln!(file, "address,value").unwrap();
        writeln!(file, "0x2222222222222222222222222222222222222222").unwrap();
        file.flush().unwrap();

        let entries = parse_csv(&file.path().to_path_buf()).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_csv_with_amount_column() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0x1111111111111111111111111111111111111111,1000").unwrap();
        writeln!(file, "0x2222222222222222222222222222222222222222,2000").unwrap();
        file.flush().unwrap();

        let entries = parse_csv(&file.path().to_path_buf()).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_csv_no_file() {
        let result = parse_csv(&PathBuf::from("/nonexistent/file.csv"));
        assert!(result.is_err());
    }

    #[test]
    fn test_canonical_ordering() {
        let addr_high = [0xFFu8; 20];
        let addr_low = [0x01u8; 20];
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0x{}", hex::encode(addr_high)).unwrap();
        writeln!(file, "0x{}", hex::encode(addr_low)).unwrap();
        file.flush().unwrap();

        let root1 = {
            let mut file2 = NamedTempFile::new().unwrap();
            writeln!(file2, "0x{}", hex::encode(addr_low)).unwrap();
            writeln!(file2, "0x{}", hex::encode(addr_high)).unwrap();
            file2.flush().unwrap();
            let (_, root, _) = build_tree_from_csv(&file2.path().to_path_buf()).unwrap();
            root
        };

        let (_, root2, _) = build_tree_from_csv(&file.path().to_path_buf()).unwrap();
        assert_eq!(
            root1, root2,
            "Merkle roots should be identical regardless of CSV order"
        );
    }

    #[test]
    fn test_parse_address_valid() {
        let addr = parse_address("0x1111111111111111111111111111111111111111").unwrap();
        assert_eq!(addr.as_slice(), &[0x11u8; 20]);
    }

    #[test]
    fn test_parse_address_no_prefix() {
        let addr = parse_address("1111111111111111111111111111111111111111").unwrap();
        assert_eq!(addr.as_slice(), &[0x11u8; 20]);
    }

    #[test]
    fn test_parse_address_wrong_length() {
        assert!(parse_address("0x1234").is_err());
    }

    #[test]
    fn test_parse_address_invalid_hex() {
        assert!(parse_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG").is_err());
    }
}
