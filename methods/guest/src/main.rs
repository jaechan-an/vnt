use risc0_zkvm::guest::env;

use bincode;
use core::{util, AggregationJournal, AggregationPrivateInput, CLog, Log};
use hex;
use rs_merkle::{Hasher, MerkleTree};
use sha2;
use sha2::Digest;

fn main() {
    let mut start = env::cycle_count();

    // Read the input
    let input: AggregationPrivateInput = env::read();

    let mut end = env::cycle_count();

    println!("Input read in {} cycles", end - start);

    let success = true;
    let message: String = String::from("Aggregation successful");

    start = env::cycle_count();

    // Step 1. Compute the hash of the logs and compare with the input hashes.
    // The n'th hash is the hash of the n'th log. If it doesn't match, the logs are corrupted.
    for (i, logs) in input.logs.iter().enumerate() {
        let computed_hash = compute_hash(logs);

        assert!(
            computed_hash == input.hashes[i],
            "Hash mismatch for logs_{}, Expected: {}, got: {}",
            i,
            hex::encode(input.hashes[i]),
            hex::encode(computed_hash)
        );
    }

    end = env::cycle_count();
    println!("Hashes computed and matched in {} cycles", end - start);

    // Step 2. Check if the old clogs match the ones in the Merkle tree.
    // If they don't match, the clogs are corrupted.
    start = env::cycle_count();

    let prev_tree = util::deserialize_merkle_tree(&input.tree);

    if prev_tree.leaves_len() != 0 {
        // TODO: delete all prints
        println!(
            "Prev Merkle tree root: {}",
            hex::encode(prev_tree.root().unwrap())
        );
        println!("Prev Merkle tree leaves:");
        for (idx, leaf) in prev_tree.leaves().unwrap().iter().enumerate() {
            println!("\tIndex: {}, hash: {}", idx, hex::encode(leaf));
        }

        // Verify that the modified_old logs match the previous Merkle tree.
        let mut indices_to_prove: Vec<usize> = Vec::new();
        let mut leaves_to_prove: Vec<[u8; 32]> = Vec::new();

        // Find all old clogs that are being updated.
        for (flow_id, clog) in &input.update_clogs {
            let old_clog = input.old_clogs.get(flow_id).unwrap();

            assert!(old_clog.id == clog.id);

            let idx = util::id_to_idx(old_clog.id);
            indices_to_prove.push(idx);
            leaves_to_prove.push(to_leaf(old_clog));

            println!(
                "Index to prove: {}, hash: {}, clog: {}",
                old_clog.id,
                hex::encode(to_leaf(old_clog)),
                old_clog.to_string()
            );
            println!(
                "\tLeaf hash: {}",
                hex::encode(prev_tree.leaves().unwrap()[idx])
            );
        }

        let merkle_proof = prev_tree.proof(&indices_to_prove);
        let merkle_root = prev_tree.root().unwrap();

        assert!(merkle_proof.verify(
            merkle_root,
            &indices_to_prove,
            &leaves_to_prove,
            prev_tree.leaves_len(),
        ));
    }

    end = env::cycle_count();
    println!("Old clogs verified in {} cycles", end - start);

    /*
     * Update the merkle tree
     */
    let mut leaves = prev_tree.leaves().unwrap_or_else(|| vec![]);

    for (flow_id, clog) in &input.update_clogs {
        assert!(input.old_clogs.get(flow_id).is_some());
        assert!(clog.flow_id == *flow_id);

        let old_clog = input.old_clogs.get(flow_id).unwrap();
        assert!(old_clog.id == clog.id);

        let new_clog = old_clog.aggregate(clog);
        assert!(new_clog.id == old_clog.id);

        // Update the leaf
        let idx = util::id_to_idx(new_clog.id);
        leaves[idx] = to_leaf(&new_clog);
    }

    /*
     * Insert to the merkle tree
     */
    // Insert with sort by clog.id
    let sorted = {
        let mut vec: Vec<(&i32, &CLog)> = input.insert_clogs.iter().collect();
        vec.sort_by_key(|(_, clog)| clog.id);
        vec
    };
    for (flow_id, clog) in &sorted {
        assert!(input.old_clogs.get(flow_id).is_none());
        println!("{} for {}, {}", clog.id, clog.flow_id, clog.hop_cnt);

        // Insert the new clog
        let leaf = to_leaf(clog);
        leaves.push(leaf);
    }

    // Build the new Merkle tree from the updated leaves
    let mut new_tree = MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&leaves);
    new_tree.commit();

    println!(
        "New Merkle tree root: {}",
        hex::encode(new_tree.root().unwrap())
    );

    end = env::cycle_count();
    println!("New Merkle tree built in {} cycles", end - start);
    println!("Merkle tree depth: {}", new_tree.depth());
    println!("New merkle tree has {} leaves.", leaves.len());

    println!("New Merkle tree leaves:");
    for (idx, leaf) in new_tree.leaves().unwrap().iter().enumerate() {
        println!("\tIndex: {}, hash: {}", idx + 1, hex::encode(leaf));
    }

    // Step 4. Output the journal with the success status, Merkle tree, and root.
    start = env::cycle_count();

    let bytes = util::serialize_merkle_tree(&new_tree);
    let root = new_tree.root().unwrap();

    let journal = AggregationJournal {
        success: success,
        tree: bytes,
        root: root,
        message: message.to_string(),
    };

    env::commit(&journal);

    end = env::cycle_count();
    println!("Journal committed in {} cycles", end - start);
}

fn to_leaf(clog: &CLog) -> [u8; 32] {
    let serialized = bincode::serialize(clog).unwrap();
    rs_merkle::algorithms::Sha256::hash(&serialized)
}

/**
 * Computes the hash of the logs using SHA-256.
 * This is used to verify the integrity of the logs.
 */
fn compute_hash(logs: &Vec<Log>) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();

    for log in logs {
        let serialized = bincode::serialize(&log).unwrap();
        hasher.update(serialized);
    }

    hasher.finalize().into()
}

