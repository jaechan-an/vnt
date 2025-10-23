use risc0_zkvm::guest::env;

use bincode;
use core::{util, AggregationJournal, AggregationPrivateInput, CLog, Log};
use hex;
use rs_merkle::{Hasher, MerkleTree};
use sha2;
use sha2::Digest;
use std::collections::HashMap;

fn main() {
    let mut start = env::cycle_count();

    // Read the input
    let input: AggregationPrivateInput = env::read();

    let prev_tree = util::deserialize_merkle_tree(&input.tree);

    let mut end = env::cycle_count();

    println!("Input read in {} cycles", end - start);

    let mut success = true;
    let mut message: String = String::from("Aggregation successful");

    // Step 1. Compute the hash of the logs and compare with the input hashes.
    // The n'th hash is the hash of the n'th log. If it doesn't match, the logs are corrupted.
    start = env::cycle_count();

    for (i, logs) in input.logs.iter().enumerate() {
        let computed_hash = compute_hash(logs);

        // Unnecessary but checking if the new_logs[i] match the log in the logs.
        for new_log in &input.new_logs[i] {
            // Check new_log in logs
            assert!(logs.contains(new_log), "New log not found in logs");
        }

        if computed_hash != input.hashes[i] {
            success = false;

            message = format!(
                "Hash mismatch for logs_{}. Expected: {}, got: {}",
                i,
                hex::encode(input.hashes[i]),
                hex::encode(computed_hash)
            );

            break;
        }
    }

    end = env::cycle_count();
    println!("Hashes computed and matched in {} cycles", end - start);

    // Step 2. Check if the old clogs match the ones in the Merkle tree.
    // If they don't match, the clogs are corrupted.
    start = env::cycle_count();

    if prev_tree.leaves_len() != 0 {
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

        for (_flow_id, id) in &input.upserted_indices {
            let _old_clog = input.old_clogs.iter().find(|clog| &clog.id == id);

            if _old_clog.is_none() {
                continue;
            }

            let old_clog = _old_clog.unwrap();

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

    // Step 3. Now update the Merkle tree with the input.modified_new and input.inserted_new.
    // The result will be a new Merkle tree with the updated logs. This Merkle tree will
    // be used to verify the integrity of the logs in the next round.
    start = env::cycle_count();

    let mut leaves = prev_tree.leaves().unwrap_or_else(|| vec![]);

    // TODO: For each in input.modified_old, update the corresponding leaf in the Merkle tree.
    // We use the input.new_logs to aggregate the value to the original clogs.
    // The clog has the same idk
    let mut diff_clogs = aggregate_logs(&input.new_logs);
    for (flow_id, id) in &input.upserted_indices {
        assert!(diff_clogs.contains_key(&flow_id));
        diff_clogs.get_mut(&flow_id).unwrap().id = *id;
    }

    // 1. Iterate through the upserted_indices and UPDATE the leaves
    let mut inserted_clogs: Vec<CLog> = Vec::new();
    for (flow_id, id) in &input.upserted_indices {
        assert!(diff_clogs.contains_key(flow_id));

        let clog = diff_clogs.get(flow_id).unwrap();

        assert!(clog.id == *id);

        let _old_clog = input.old_clogs.iter().find(|clog| &clog.id == id);
        if _old_clog.is_none() {
            // Insert will be handled after this for loop
            inserted_clogs.push(clog.clone());
        } else {
            // Update the leaf
            let old_clog = _old_clog.unwrap();
            let new_clog = old_clog.aggregate(clog);
            assert!(new_clog.id == clog.id, "CLog ID mismatch after aggregation");

            let idx = util::id_to_idx(clog.id);
            leaves[idx] = to_leaf(&new_clog);
        }
    }

    // 2. Sort the inserted_clogs by clog id
    let sorted_inserted_clogs: Vec<CLog> = {
        let mut clogs: Vec<CLog> = inserted_clogs.iter().cloned().collect();
        clogs.sort_by_key(|clog| clog.id);
        clogs
    };

    // 3. Append the new clogs to the end
    for clog in &sorted_inserted_clogs {
        let leaf = to_leaf(clog);

        // Insert the new clog
        leaves.push(leaf);
        println!(
            "Index Inserted: {}, hash: {}, clog: {}",
            clog.id,
            hex::encode(leaf),
            clog.to_string()
        );
    }

    println!("New leaves {}", leaves.len());

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

/**
 * Aggregates logs from all nodes into a single HashMap where the key is the flow_id.
 * The CLog struct is used to represent the aggregated log.
 */
fn aggregate_logs(new_logs: &Vec<Vec<Log>>) -> HashMap<i32 /* flow_id */, CLog> {
    let mut aggregated_map = HashMap::<i32, CLog>::new();

    for logs in new_logs {
        for log in logs {
            let key = log.flow_id;

            // If key exists, modify it; otherwise, insert a new value
            aggregated_map
                .entry(key)
                .and_modify(|clog: &mut CLog| clog.hop_cnt += log.hop_cnt)
                .or_insert(CLog::from_log(&log));
        }
    }

    aggregated_map
}
