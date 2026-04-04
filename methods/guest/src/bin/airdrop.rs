use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

const MERKLE_TREE_DEPTH: usize = 32;

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub path: [[u8; 32]; MERKLE_TREE_DEPTH],
    pub index: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy)]
pub struct GuestInput {
    pub private_key_bytes: [u8; 32],
    pub merkle_root: [u8; 32],
    pub merkle_proof: MerkleProof,
    pub claimant_address: [u8; 20],
    pub airdrop_contract: [u8; 20],
    pub chain_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy)]
pub struct GuestOutput {
    pub merkle_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub claimant_address: [u8; 20],
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

fn derive_ethereum_address(secret_key: &SecretKey) -> [u8; 20] {
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let uncompressed = encoded.as_bytes();
    let pubkey_bytes = &uncompressed[1..];
    let hash = keccak256(pubkey_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

fn compute_nullifier(
    secret_key_bytes: &[u8; 32],
    airdrop_contract: &[u8; 20],
    chain_id: u64,
) -> [u8; 32] {
    let hashed_sk: [u8; 32] = Sha256::new()
        .chain_update(secret_key_bytes)
        .finalize()
        .into();
    let mut hasher = Sha256::new();
    hasher.update(b"airdrop-nullifier-v2");
    hasher.update(&hashed_sk);
    hasher.update(airdrop_contract);
    hasher.update(chain_id.to_be_bytes());
    hasher.finalize().into()
}

fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn verify_merkle_proof(proof: &MerkleProof, root: &[u8; 32]) -> bool {
    let mut current = proof.leaf;
    let mut index = proof.index;

    for i in 0..MERKLE_TREE_DEPTH {
        let sibling = proof.path[i];
        if index & 1 == 0 {
            current = sha256_pair(&current, &sibling);
        } else {
            current = sha256_pair(&sibling, &current);
        }
        index >>= 1;
    }

    current == *root
}

fn main() {
    let mut input: GuestInput = env::read();

    assert!(input.private_key_bytes != [0u8; 32], "zero pk");
    assert!(input.airdrop_contract != [0u8; 20], "zero contract");
    assert!(input.chain_id > 0, "zero chain");

    let secret_key = SecretKey::from_slice(&input.private_key_bytes).expect("invalid private key");

    let eligible_address = derive_ethereum_address(&secret_key);

    let leaf_hash = Sha256::new().chain_update(&eligible_address).finalize();
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&leaf_hash);

    assert!(leaf == input.merkle_proof.leaf, "leaf mismatch");

    assert!(
        verify_merkle_proof(&input.merkle_proof, &input.merkle_root),
        "proof fail"
    );

    assert!(input.claimant_address != [0u8; 20], "zero claimant");

    let nullifier = compute_nullifier(
        &input.private_key_bytes,
        &input.airdrop_contract,
        input.chain_id,
    );

    input.private_key_bytes.fill(0);

    // Journal format: 96 bytes total
    //   [0..32]   merkle_root as bytes32
    //   [32..64]  nullifier as bytes32
    //   [64..84]  claimant_address as bytes20
    //   [84..96]  zero padding (12 bytes)
    //
    // This raw byte layout MUST match Solidity's abi.encode(GuestOutput) where
    // GuestOutput is (bytes32, bytes32, bytes20). Solidity ABI-encodes bytes20
    // as a 32-byte word with the 20-byte value left-aligned and 12 zero bytes
    // right-padded. Changing this format will break on-chain verification.
    let mut journal = [0u8; 96];
    journal[0..32].copy_from_slice(&input.merkle_root);
    journal[32..64].copy_from_slice(&nullifier);
    journal[64..84].copy_from_slice(&input.claimant_address);
    env::commit_slice(&journal);
}
