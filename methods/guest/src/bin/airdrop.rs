use k256::{
    ecdsa::signature::DigestSigner,
    elliptic_curve::{sec1::ToEncodedPoint, FieldBytes},
    SecretKey,
};
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
    let mut hasher = Sha256::new();
    hasher.update(b"airdrop-nullifier");
    hasher.update(secret_key_bytes);
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
    let input: GuestInput = env::read();

    let secret_key = SecretKey::from_slice(&input.private_key_bytes).unwrap();

    let eligible_address = derive_ethereum_address(&secret_key);

    let mut leaf_hash_input = [0u8; 20];
    leaf_hash_input.copy_from_slice(&eligible_address);
    let leaf_hash = Sha256::new().chain_update(&leaf_hash_input).finalize();
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&leaf_hash);

    assert!(
        verify_merkle_proof(&input.merkle_proof, &input.merkle_root),
        "Merkle proof verification failed"
    );

    let nullifier = compute_nullifier(
        &input.private_key_bytes,
        &input.airdrop_contract,
        input.chain_id,
    );

    let output = GuestOutput {
        merkle_root: input.merkle_root,
        nullifier,
        claimant_address: input.claimant_address,
    };

    env::commit(&output);
}
