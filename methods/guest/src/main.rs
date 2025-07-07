use risc0_zkvm::guest::env;

use bincode;
use core::{AggregationJournal, AggregationPrivateInput, CLog, Log};
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use std::collections::HashMap;

fn main() {
    let mut start = env::cycle_count();

    // Read the input
    let input: AggregationPrivateInput = env::read();

    let mut end = env::cycle_count();

    println!("Input read in {} cycles", end - start);

    /*
     * 1. Compute the aggregated logs from the input logs and compare it with the input new_clogs.
     *    - If they match, the aggregation logic is performed trustfully.
     *    - This ensures that the aggregation computation is done correctly.
     * 2. Build a Merkle tree from the aggregated logs.
     *    - The Merkle tree is built from the aggregated logs to ensure integrity and consistency.
     *    - We do it in the guest program to ensure that the aggregation logic is correct and can
     *      be verified.
     * 3. Return the Merkle root in the journal.
     */

    start = env::cycle_count();

    let aggregated_new_clogs = aggregate_logs(&input.logs);

    end = env::cycle_count();
    println!("Logs aggregated in {} cycles", end - start);

    // Check if aggregated_new_clogs is the same as input.new_clogs
    let success = aggregated_new_clogs == input.new_clogs;

    let mut message = "Success";
    if !success {
        message = "Aggregation failed: new clogs do not match aggregated logs.";
    }

    start = env::cycle_count();

    let merkle_tree = build_merkle_tree(&input.clogs);
    let bytes = serialize_merkle_tree(&merkle_tree);
    let root = merkle_tree.root().unwrap();

    end = env::cycle_count();
    println!("Merkle tree built in {} cycles", end - start);

    // Write public output to the journal
    let journal = AggregationJournal {
        /*
         * Indicates whether the aggregation was successful. If false, the data is corrupted.
         */
        success: success,
        tree: bytes,
        root: root,
        message: message.to_string(),
    };

    env::commit(&journal);

    end = env::cycle_count();

    println!("Journal committed in {} cycles", end - start);
}

/**
 * Must be same as the one in the host.
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

/**
 * Builds a Merkle tree from the provided CLog entries.
 * Each CLog is serialized to JSON, then hashed using rs_merkle's Sha256.
 */
fn build_merkle_tree(clogs: &Vec<CLog>) -> MerkleTree<Sha256> {
    let leaves: Vec<[u8; 32]> = clogs
        .iter()
        .map(|clog| {
            let serialized = bincode::serialize(clog).unwrap();
            Sha256::hash(&serialized)
        })
        .collect();

    // Create the Merkle tree from the leaves
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);

    merkle_tree
}

/**
 * Serialize the Merkle tree to bytes. Manually serialize the leaf hashes.
 */
fn serialize_merkle_tree(tree: &MerkleTree<Sha256>) -> Vec<u8> {
    bincode::serialize(&tree.leaves()).unwrap_or_else(|_| vec![])
}
