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

    let prev_tree = util::deserialize_merkle_tree(&input.tree);

    let mut end = env::cycle_count();

    println!("Input read in {} cycles", end - start);

    /*
     * 1. Compute the hash of the input logs and compare it with the input hashes.
     *   - If they match, there has been no manipulation of the logs.
     * 1. Compute the aggregated logs from the input logs and compare it with the input new_clogs.
     *    - If they match, the aggregation logic is performed trustfully.
     *    - This ensures that the aggregation computation is done correctly.
     * 2. Build a Merkle tree from the aggregated logs.
     *    - The Merkle tree is built from the aggregated logs to ensure integrity and consistency.
     *    - We do it in the guest program to ensure that the aggregation logic is correct and can
     *      be verified.
     * 3. Return the Merkle root in the journal.
     */
    let mut success = true;
    let mut message: String = String::from("Aggregation successful");

    // Step 1. Compute the hash of the logs and compare with the input hashes.
    // The n'th hash is the hash of the n'th log. If it doesn't match, the logs are corrupted.
    start = env::cycle_count();

    for (i, logs) in input.logs.iter().enumerate() {
        let computed_hash = compute_hash(logs);
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

    if prev_tree.leaves_len() == 0 {
        // First round, no previous tree.
        assert!(
            input.modified_old.is_empty(),
            "Tree is empty but modified_old is not"
        );
    } else {
        // Verify that the modified_old logs match the previous Merkle tree.
        let mut indices_to_prove: Vec<usize> = Vec::new();
        let mut leaves_to_prove: Vec<[u8; 32]> = Vec::new();

        for (_flow_id, clog) in &input.modified_old {
            let idx = util::id_to_idx(clog.id);

            indices_to_prove.push(idx);
            leaves_to_prove.push(to_leaf(clog));
        }

        let merkle_proof = prev_tree.proof(&indices_to_prove);
        let merkle_root = prev_tree.root().unwrap();

        assert!(merkle_proof.verify(
            merkle_root,
            &indices_to_prove,
            &leaves_to_prove,
            prev_tree.leaves_len()
        ));
    }

    end = env::cycle_count();
    println!("Old clogs verified in {} cycles", end - start);

    // Step 3. Now update the Merkle tree with the input.modified_new and input.inserted_new.
    // The result will be a new Merkle tree with the updated logs. This Merkle tree will
    // be used to verify the integrity of the logs in the next round.
    start = env::cycle_count();

    let mut leaves = prev_tree.leaves().unwrap_or_else(|| vec![]);

    for (_flow_id, clog) in &input.modified_new {
        let leaf = to_leaf(clog);

        let idx = util::id_to_idx(clog.id);

        // Update the existing clog
        leaves[idx] = leaf;
    }

    for clog in &input.inserted_new {
        let leaf = to_leaf(clog);

        // Insert the new clog
        leaves.push(leaf);

        assert!(
            clog.id as usize == leaves.len(),
            "Inserted clog id {} does not match the expected index {}",
            clog.id,
            leaves.len()
        );
    }
    println!("New leaves {}", leaves.len());

    // Build the new Merkle tree from the updated leaves
    let mut new_tree = MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&leaves);
    new_tree.commit();

    end = env::cycle_count();
    println!("New Merkle tree built in {} cycles", end - start);

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
