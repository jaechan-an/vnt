use bincode;
use core::{merkle::MerkleTree, util, AggregationJournal, AggregationPrivateInput, CLog, Log};
use hex;
use risc0_zkvm::guest::env;
use sha2;
use sha2::Digest;
use std::convert::TryInto;

fn main() {
    let mut start = env::cycle_count();

    // Read the input
    let input: AggregationPrivateInput = env::read();
    let prev_tree = util::deserialize_merkle_tree(&input.tree);

    let mut end = env::cycle_count();

    println!("Input read in {} cycles", end - start);

    let success = true;
    let message: String = String::from("Aggregation successful");

    // Step 1. Compute the hash of the logs and compare with the input hashes.
    // The n'th hash is the hash of the n'th log. If it doesn't match, the logs are corrupted.
    start = env::cycle_count();

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

    if !prev_tree.is_empty() {
        let prev_root = prev_tree.root();
        println!(
            "Prev Merkle tree root: {}",
            hex::encode(prev_root.as_bytes())
        );
        println!("Prev Merkle tree entries:");
        for (idx, clog) in prev_tree.elements().iter().enumerate() {
            println!("\tIndex: {}, clog: {}", idx + 1, clog.to_string());
        }

        for (flow_id, _clog) in &input.update_clogs {
            if let Some(old_clog) = input.old_clogs.get(flow_id) {
                let idx = util::id_to_idx(old_clog.id);
                let proof = prev_tree.prove(idx);
                println!(
                    "Index to prove: {}, clog: {}",
                    old_clog.id,
                    old_clog.to_string()
                );
                assert_eq!(idx, proof.index());
                assert!(proof.verify(&prev_root, old_clog));
            }
        }
    }

    end = env::cycle_count();
    println!("Old clogs verified in {} cycles", end - start);

    // Step 3. Now update the Merkle tree with update_clogs and insert_clogs.
    // The result will be a new Merkle tree with the updated logs. This Merkle tree will
    // be used to verify the integrity of the logs in the next round.
    start = env::cycle_count();

    let mut elements: Vec<CLog> = prev_tree.elements().to_vec();

    // Update existing leaves.
    for (flow_id, clog_update) in &input.update_clogs {
        let old_clog = input
            .old_clogs
            .get(flow_id)
            .expect("Old clog not found for update");

        assert!(
            old_clog.id == clog_update.id,
            "CLog ID mismatch for flow {}",
            flow_id
        );

        let new_clog = old_clog.aggregate(clog_update);
        let idx = util::id_to_idx(new_clog.id);
        assert!(
            idx < elements.len(),
            "Index {} out of bounds for existing Merkle elements",
            idx
        );
        elements[idx] = new_clog;
    }

    /*
     * Insert to the merkle tree
     */
    let mut sorted_inserts: Vec<(&i32, &CLog)> = input.insert_clogs.iter().collect();
    sorted_inserts.sort_by_key(|(_, clog)| clog.id);
    for (flow_id, clog) in sorted_inserts {
        assert!(input.old_clogs.get(flow_id).is_none());
        println!("{} for {}, {}", clog.id, clog.flow_id, clog.hop_cnt);

        elements.push(clog.clone());
        println!(
            "Index Inserted: {}, clog: {}",
            clog.id,
            clog.to_string()
        );
    }

    println!("New elements {}", elements.len());

    // Build the new Merkle tree from the updated elements
    let new_tree = MerkleTree::new(elements);

    let new_root = new_tree.root();
    println!(
        "New Merkle tree root: {}",
        hex::encode(new_root.as_bytes())
    );

    end = env::cycle_count();
    println!("New Merkle tree built in {} cycles", end - start);
    println!("Merkle tree depth: {}", new_tree.depth());
    println!(
        "New merkle tree has {} leaves.",
        new_tree.elements().len()
    );

    println!("New Merkle tree elements:");
    for (idx, clog) in new_tree.elements().iter().enumerate() {
        println!("\tIndex: {}, clog: {}", idx + 1, clog.to_string());
    }

    // Step 4. Output the journal with the success status, Merkle tree, and root.
    start = env::cycle_count();

    let bytes = util::serialize_merkle_tree(&new_tree);
    let root: [u8; 32] = new_root
        .as_bytes()
        .try_into()
        .expect("Digest must be 32 bytes");

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
