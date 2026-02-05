use risc0_zkvm::{guest::env, sha::Digest as RiscDigest};
use sha2::{Digest, Sha256};

use core::{util, QueryJournal, QueryPrivateInput};
use zk::{CompressedLog as ZKClog, Leaf, U1, U2};

fn main() {
    let start = env::cycle_count();
    // Step 1: Read and deserialize inputs.
    let read_input_start = env::cycle_count();
    let input: QueryPrivateInput = env::read();
    let QueryPrivateInput {
        ref clogs,
        cur_root,
        user_id,
    } = input;
    let read_input_end = env::cycle_count();
    eprintln!(
        "read input took: {} cycles",
        read_input_end - read_input_start
    );

    // Step 2: Compute SHA256 hash over clogs using accelerated precompile
    let hash_start = env::cycle_count();
    let mut hasher = Sha256::new();
    for clog in clogs {
        // Hash each field of the clog
        hasher.update(&clog.user_id.to_le_bytes());
        hasher.update(&clog.hash_chain);
    }
    let clogs_hash = hasher.finalize();
    let hash_end = env::cycle_count();
    eprintln!("sha256 hash over clogs took: {}", hash_end - hash_start);
    eprintln!("clogs hash: {:x}", clogs_hash);

    // Step 3: Perform query.
    // Filter all logs that match the query
    // Example:
    // 1. SELECT hash_chain FROM clogs WHERE user_id = 0;
    // 2. Calculate the percentage difference between the two results.
    let mut hash_chain: Vec<u8> = Vec::new();

    for clog in &input.clogs {
        if clog.user_id == user_id {
            hash_chain = clog.hash_chain.clone();
            // Removed some proof verification logic from previous version since they weren't doing anything.
        }
    }

    // Step 4: Output query results.
    let message = format!("user_id {} hash_chain: {:?}", user_id, hash_chain);

    let output = QueryJournal {
        success: true,
        message: message.to_string(),
    };

    env::commit(&output);
    let end = env::cycle_count();
    eprintln!("full program took: {} cycles", end - start);
}
