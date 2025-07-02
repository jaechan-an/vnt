use risc0_zkvm::guest::env;

use core::{AggregationJournal, AggregationPrivateInput};

fn main() {
    let mut start = env::cycle_count();

    // Read the input
    let input: AggregationPrivateInput = env::read();

    let mut end = env::cycle_count();

    println!("Input read in {} cycles", end - start);

    /*
     * 1. Check if the logs are consistent by using the hash value for each logs_i table.
     * 2. Check if the compute (aggregation) is correct. -- compare with the original compute.
     * 3. Create a new merkle tree for the diff and return it in the Journal.
     */

    start = env::cycle_count();

    // Write public output to the journal
    let journal = AggregationJournal {
        success: true, // Placeholder for success status
        root: [0; 32], // Placeholder for Merkle root
    };

    env::commit(&journal);

    end = env::cycle_count();

    println!("Journal committed in {} cycles", end - start);
}
