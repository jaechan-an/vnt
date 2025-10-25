use risc0_zkvm::{guest::env, sha::Digest as RiscDigest};

use core::{util, QueryJournal, QueryPrivateInput};

fn main() {
    let input: QueryPrivateInput = env::read();

    let tree = util::deserialize_merkle_tree(&input.tree);
    let merkle_root = tree.root();
    let expected_root = RiscDigest::from(input.root);
    assert_eq!(
        merkle_root.as_bytes(),
        expected_root.as_bytes(),
        "Input Merkle root does not match serialized tree"
    );

    // Filter all logs that match the query
    // Example:
    // 1. SELECT SUM(hop_cnt) FROM clogs WHERE src = 0 AND dst = 6;
    // 2. Calculate the percentage difference between the two results.
    let mut sum_hop_cnt = 0;

    let src = input.src;
    let dst = input.dst;

    for clog in &input.clogs {
        if clog.src == src && clog.dst == dst {
            sum_hop_cnt += clog.hop_cnt;

            let idx = util::id_to_idx(clog.id);

            let proof = tree.prove(idx);
            assert_eq!(idx, proof.index());
            assert!(proof.verify(&merkle_root, clog));
        }
    }

    println!("Merkle tree depth: {}", tree.depth());

    // Calculate the difference
    let message = format!("src {} to dst {} hop_cnt: {}", src, dst, sum_hop_cnt);

    let output = QueryJournal {
        success: true,
        message: message.to_string(),
    };

    env::commit(&output);
}
