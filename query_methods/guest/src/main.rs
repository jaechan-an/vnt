use risc0_zkvm::guest::env;

use core::{util, CLog, QueryJournal, QueryPrivateInput};

use bincode;
use rs_merkle::Hasher;

fn main() {
    let input: QueryPrivateInput = env::read();

    let tree = util::deserialize_merkle_tree(&input.tree);

    // Filter all logs that match the query
    // Example:
    // 1. SELECT SUM(hop_cnt) FROM clogs WHERE src = 0 AND dst = 6;
    // 2. Calculate the percentage difference between the two results.
    let mut sum_hop_cnt = 0;

    let mut indices_to_prove: Vec<usize> = Vec::new();
    let mut leaves_to_prove: Vec<[u8; 32]> = Vec::new();

    let src = input.src;
    let dst = input.dst;

    for clog in &input.clogs {
        if clog.src == src && clog.dst == dst {
            sum_hop_cnt += clog.hop_cnt;

            let idx = util::id_to_idx(clog.id);

            indices_to_prove.push(idx);
            leaves_to_prove.push(to_leaf(clog));
        }
    }

    let merkle_proof = tree.proof(&indices_to_prove);
    let merkle_root = tree.root().unwrap_or_else(|| [0; 32]);

    assert!(merkle_proof.verify(
        merkle_root,
        &indices_to_prove,
        &leaves_to_prove,
        tree.leaves_len()
    ));

    // Calculate the difference
    let message = format!("src {} to dst {} hop_cnt: {}", src, dst, sum_hop_cnt);

    let output = QueryJournal {
        success: true,
        message: message.to_string(),
    };

    env::commit(&output);
}

fn to_leaf(clog: &CLog) -> [u8; 32] {
    let serialized = bincode::serialize(clog).unwrap();
    rs_merkle::algorithms::Sha256::hash(&serialized)
}
