use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;

pub fn id_to_idx(id: i32) -> usize {
    (id - 1) as usize
}

/**
 * Serialize the Merkle tree to bytes. Manually serialize the leaf hashes.
 */
pub fn serialize_merkle_tree(tree: &MerkleTree<Sha256>) -> Vec<u8> {
    if tree.leaves_len() == 0 {
        return vec![];
    }

    // Iterate through and serialize all the leaves
    let mut v: Vec<u8> = Vec::new();
    for leaf in tree.leaves().unwrap() {
        v.extend_from_slice(&leaf);
    }
    bincode::serialize(&v).unwrap_or_else(|_| vec![])
}

/**
 * Deserialize the Merkle tree from bytes. Manually deserialize the leaf hashes.
 */
pub fn deserialize_merkle_tree(bytes: &[u8]) -> MerkleTree<Sha256> {
    if bytes.is_empty() {
        return MerkleTree::<Sha256>::new();
    }

    let bytes = bincode::deserialize::<Vec<u8>>(bytes).unwrap_or_else(|_| vec![]);
    let leaves = bytes
        .chunks(32)
        .map(|chunk| {
            let mut array = [0u8; 32];
            array.copy_from_slice(chunk);
            array
        })
        .collect::<Vec<[u8; 32]>>();
    MerkleTree::<Sha256>::from_leaves(&leaves)
}
