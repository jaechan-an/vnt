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
    // 2. SELECT SUM(hop_cnt) FROM clogs WHERE src = 3 AND dst = 9;
    // 3. Calculate the percentage difference between the two results.
    let mut sum_hop_cnt = [0; 2];

    let mut indices_to_prove: Vec<usize> = Vec::new();
    let mut leaves_to_prove: Vec<[u8; 32]> = Vec::new();

    let src1 = input.src1;
    let dst1 = input.dst1;
    let src2 = input.src2;
    let dst2 = input.dst2;

    for clog in &input.clogs {
        if clog.src == src1 && clog.dst == dst1 {
            sum_hop_cnt[0] += clog.hop_cnt;

            let idx = util::id_to_idx(clog.id);

            indices_to_prove.push(idx);
            leaves_to_prove.push(to_leaf(clog));
        }

        if clog.src == src2 && clog.dst == dst2 {
            sum_hop_cnt[1] += clog.hop_cnt;

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
    let message = format!(
        "src {} to dst {} hop_cnt: {}, src {} to dst {} hop_cnt: {}",
        src1, dst1, sum_hop_cnt[0], src2, dst2, sum_hop_cnt[1]
    );

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
