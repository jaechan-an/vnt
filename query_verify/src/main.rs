use query_methods::QUERY_METHOD_ID;

use risc0_zkvm::Receipt;

use clap::Parser;

use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;

use core::{log, NovaConsistencyProof, QueryJournal};

use std::fs;
use std::path::Path;
use std::time::Instant;

use ff::{Field, PrimeField};
use nova_snark::{
    nova::{CompressedSNARK, VerifierKey},
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{Engine, Group},
};
use zk::ConsistencyCircuit;

// Nova type aliases (matching query_consistency_proof)
type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;
type Scalar = <<E1 as Engine>::GE as Group>::Scalar;
type C = ConsistencyCircuit<Scalar>;
type CompSNARK = CompressedSNARK<E1, E2, C, S1, S2>;
type VK = VerifierKey<E1, E2, C, S1, S2>;
type ScalarRepr = <Scalar as PrimeField>::Repr;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Log directory
    #[clap(long, default_value = "logs")]
    logdir: String,

    /// Log file name
    #[clap(long, default_value = "query_verify")]
    logfile: String,

    /// Log level
    #[clap(long, default_value = "INFO")]
    logfilter: String,

    /// Proof directory
    #[clap(long, default_value = "proofs")]
    proof_dir: String,

    /// Query proof (RISC Zero receipt) file
    #[clap(short = 'r', long, value_parser, default_value = "query_proof.bin")]
    receiptfile: String,

    /// Consistency proof file
    #[clap(long, default_value = "consistency_proof.bin")]
    consistency_proof_file: String,
}

fn main() {
    let args = Args::parse();

    let logfilter = log::get_log_level(&args.logfilter);
    let logdir = Path::new(".").join(&args.logdir);
    fs::create_dir_all(&logdir).expect("Failed to create log directory");

    let file_appender = rolling::daily(logdir, &args.logfile);
    let (non_blocking, log_guard) = tracing_appender::non_blocking(file_appender);

    let logger = layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .compact()
        .with_filter(logfilter);

    tracing_subscriber::registry().with(logger).init();

    let proof_dir = Path::new(".").join(&args.proof_dir);
    let receiptfile = proof_dir.join(&args.receiptfile);

    assert!(fs::exists(&receiptfile).is_ok());

    info!("Verifying receipt file: {}", &receiptfile.display());

    // Load and verify the receipt file.
    let receipt: Receipt = bincode::deserialize(&fs::read(&receiptfile).unwrap()).unwrap();

    let start = Instant::now();
    receipt.verify(QUERY_METHOD_ID).unwrap();
    let receipt_verify_ms = start.elapsed().as_millis();

    let journal: QueryJournal = receipt.journal.decode().unwrap();
    if !journal.success {
        error!("Journal verification is not successful!");
    }

    info!("Message: {}", journal.message);

    info!("Journal size: {} bytes", receipt.journal.bytes.len());
    info!("Seal size: {} bytes", receipt.seal_size());

    info!("Receipt verification took {} ms", receipt_verify_ms);

    // Load and verify the consistency proof file.
    let consistency_proof_file = proof_dir.join(&args.consistency_proof_file);

    assert!(
        fs::exists(&consistency_proof_file).is_ok(),
        "Consistency proof file not found: {}",
        consistency_proof_file.display()
    );

    info!(
        "Verifying consistency proof file: {}",
        &consistency_proof_file.display()
    );

    let proof_bytes = fs::read(&consistency_proof_file).unwrap();
    let consistency_proof: NovaConsistencyProof<ScalarRepr, CompSNARK, VK> =
        bincode::deserialize(&proof_bytes[..]).unwrap();

    let pub_merkle_root = Scalar::from_repr(consistency_proof.pub_merkle_root).unwrap();
    let pub_hash_hi = Scalar::from_repr(consistency_proof.pub_hash_hi).unwrap();
    let pub_hash_lo = Scalar::from_repr(consistency_proof.pub_hash_lo).unwrap();
    let vk = consistency_proof.verifier_key;

    // Initial state for consistency proof: [merkle_root, hash_hi, hash_lo, step_count]
    let initial_state = &[pub_merkle_root, pub_hash_hi, pub_hash_lo, Scalar::ZERO];

    let start = Instant::now();
    let res = consistency_proof
        .compressed_snark
        .verify(&vk, 1, initial_state);
    assert!(res.is_ok(), "Consistency proof verification failed");
    let consistency_verify_ms = start.elapsed().as_millis();

    let final_state = res.unwrap();
    match &final_state[..] {
        [a, b, c, d] => {
            assert!(*a == pub_merkle_root, "merkle_root mismatch");
            assert!(*b == pub_hash_hi, "hash_hi mismatch");
            assert!(*c == pub_hash_lo, "hash_lo mismatch");
            assert!(*d == Scalar::ONE, "step_count should be 1");
        }
        _ => error!("Expected 4 elements in final state"),
    }

    info!("Merkle root: {:?}", pub_merkle_root);
    info!(
        "CLogs SHA-256 hash: {}",
        hex::encode(&consistency_proof.clogs_hash)
    );
    info!(
        "Consistency proof verification took {} ms",
        consistency_verify_ms
    );

    info!(
        "SUMMARY: receipt_verify={} ms, consistency_verify={} ms",
        receipt_verify_ms, consistency_verify_ms
    );

    // Make sure all logs are dropped.
    drop(log_guard);
}
