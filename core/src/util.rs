use crate::{merkle::MerkleTree, CLog};

pub fn id_to_idx(id: i32) -> usize {
    (id - 1) as usize
}

/**
 * Serialize the Merkle tree elements to bytes.
 */
pub fn serialize_merkle_tree(tree: &MerkleTree<CLog>) -> Vec<u8> {
    bincode::serialize(tree.elements()).unwrap_or_default()
}

/**
 * Deserialize the Merkle tree from bytes.
 */
pub fn deserialize_merkle_tree(bytes: &[u8]) -> MerkleTree<CLog> {
    if bytes.is_empty() {
        return MerkleTree::new(Vec::new());
    }

    let elements = bincode::deserialize(bytes).unwrap_or_else(|_| Vec::<CLog>::new());
    MerkleTree::new(elements)
}
