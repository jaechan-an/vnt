use risc0_zkvm::guest::env;

use core::{util, CLog, QueryJournal, QueryPrivateInput};

use bincode;
use rs_merkle::{Hasher, MerkleTree};

fn main() {
    let input: QueryPrivateInput = env::read();

    let tree = deserialize_merkle_tree(&input.tree);

    assert!(
        tree.root() == Some(input.root),
        "Merkle root does not match"
    );

    // Filter all logs that match the query
    // Example:
    // 1. SELECT SUM(hop_cnt) FROM clogs WHERE src = 0 AND dst = 6;
    // 2. SELECT SUM(hop_cnt) FROM clogs WHERE src = 3 AND dst = 9;
    // 3. Calculate the percentage difference between the two results.
    let mut sum_hop_cnt = [0; 2];

    let mut indices_to_prove: Vec<usize> = Vec::new();
    let mut leaves_to_prove: Vec<[u8; 32]> = Vec::new();

    for clog in &input.clogs {
        if clog.src == 0 && clog.dst == 6 {
            sum_hop_cnt[0] += clog.hop_cnt;

            let idx = util::id_to_idx(clog.id);

            indices_to_prove.push(idx);
            leaves_to_prove.push(to_leaf(clog));
        }

        if clog.src == 3 && clog.dst == 9 {
            sum_hop_cnt[1] += clog.hop_cnt;

            let idx = util::id_to_idx(clog.id);

            indices_to_prove.push(idx);
            leaves_to_prove.push(to_leaf(clog));
        }
    }

    let merkle_proof = tree.proof(&indices_to_prove);
    let merkle_root = tree.root().unwrap();

    assert!(merkle_proof.verify(
        merkle_root,
        &indices_to_prove,
        &leaves_to_prove,
        tree.leaves_len()
    ));

    // Calculate the difference
    let message = format!(
        "src 0 to dst 6 hop_cnt: {}, src 3 to dst 9 hop_cnt: {}",
        sum_hop_cnt[0], sum_hop_cnt[1]
    );

    let output = QueryJournal {
        success: true,
        message: message.to_string(),
    };

    env::commit(&output);
}

/**
 * Deserialize the Merkle tree from bytes. Manually deserialize the leaf hashes.
 */
fn deserialize_merkle_tree(bytes: &[u8]) -> MerkleTree<rs_merkle::algorithms::Sha256> {
    let leaves: Vec<[u8; 32]> = bincode::deserialize(bytes).unwrap_or_else(|_| vec![]);
    MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&leaves)
}

fn to_leaf(clog: &CLog) -> [u8; 32] {
    let serialized = bincode::serialize(clog).unwrap();
    rs_merkle::algorithms::Sha256::hash(&serialized)
}
