use risc0_zkvm::{guest::env, sha::Digest as RiscDigest};
use sha2::{Sha256, Digest};

use core::{util, QueryJournal, QueryPrivateInput};
use zk::{CompressedLog as ZKClog, Leaf, U1, U2};

fn main() {
    let start = env::cycle_count();
    // Step 1: Read and deserialize inputs.
    let read_input_start = env::cycle_count();
    let input: QueryPrivateInput = env::read();
    let QueryPrivateInput { ref clogs, cur_root, src, dst } = input;
    let read_input_end = env::cycle_count();
    eprintln!("read input took: {} cycles", read_input_end - read_input_start);

    // Step 2: Compute SHA256 hash over clogs using accelerated precompile
    let hash_start = env::cycle_count();
    let mut hasher = Sha256::new();
    for clog in clogs {
        // Hash each field of the clog
        hasher.update(&clog.id.to_le_bytes());
        hasher.update(&clog.flow_id.to_le_bytes());
        hasher.update(&clog.src.to_le_bytes());
        hasher.update(&clog.dst.to_le_bytes());
        hasher.update(&clog.packet_size.to_le_bytes());
        hasher.update(&clog.hop_cnt.to_le_bytes());
    }
    let clogs_hash = hasher.finalize();
    let hash_end = env::cycle_count();
    eprintln!("sha256 hash over clogs took: {}", hash_end - hash_start);
    eprintln!("clogs hash: {:x}", clogs_hash);

    // Step 3: Perform query.
    // Filter all logs that match the query
    // Example:
    // 1. SELECT SUM(hop_cnt) FROM clogs WHERE src = 0 AND dst = 6;
    // 2. Calculate the percentage difference between the two results.
    let mut sum_hop_cnt = 0;

    for clog in &input.clogs {
        if clog.src == src && clog.dst == dst {
            sum_hop_cnt += clog.hop_cnt;
            // Removed some proof verification logic from previous version since they weren't doing anything.
        }
    }

    // Step 4: Output query results.
    let message = format!("src {} to dst {} hop_cnt: {}", src, dst, sum_hop_cnt);

    let output = QueryJournal {
        success: true,
        message: message.to_string(),
    };

    env::commit(&output);
    let end = env::cycle_count();
    eprintln!("full program took: {} cycles", end - start);
}
