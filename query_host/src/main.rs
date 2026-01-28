use methods::VNT_ZKP_ID;
use query_methods::QUERY_METHOD_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

use clap::Parser;
use tokio_postgres::Error;

use std::{fs, path::Path, time::Instant};

use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;

use ff::{Field, PrimeField};
use nova_snark::{
    nova::{CompressedSNARK, VerifierKey},
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{snark::RelaxedR1CSSNARKTrait, Engine, Group},
};

use core::{
    log, merkle::MerkleTree as CLogMerkleTree, postgres::Postgres, util, AggregationJournal, CLog,
    QueryJournal, QueryPrivateInput, NovaAggregationProof,
};
use zk;
mod db;

// Nova related type aliases (they are complicated)
const HEIGHT: usize = 15;
const BATCH_SIZE: usize = 10;
type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;
type Scalar = <<E1 as Engine>::GE as Group>::Scalar;
type C = zk::AggregationCircuit<Scalar, u32, HEIGHT, BATCH_SIZE>;
type CompSNARK = CompressedSNARK<E1, E2, C, S1, S2>;
type AggregationProof = NovaAggregationProof<
    <Scalar as PrimeField>::Repr,
    CompSNARK,
    VerifierKey<E1, E2, C, S1, S2>,
>;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Log directory
    #[clap(long, default_value = "logs")]
    logdir: String,

    /// Log file name
    #[clap(long, default_value = "query")]
    logfile: String,

    /// Log level
    #[clap(long, default_value = "INFO")]
    logfilter: String,

    /// Proof directory
    #[clap(long, default_value = "proofs")]
    receiptdir: String,

    /// Aggregation proof
    #[clap(
        short = 'a',
        long,
        value_parser,
        default_value = "aggregation_proof.bin"
    )]
    aggregation_receiptfile: String,

    /// Merkle Tree leaves
    #[clap(
        short = 'a',
        long,
        value_parser,
        default_value = "merkle_tree_vector_state.bin"
    )]
    merkle_tree_vector_file: String,

    /// Output file path to save the proof.
    #[clap(short = 'q', long, value_parser, default_value = "query_proof.bin")]
    receiptfile: String,

    /// Total count of internal nodes
    #[clap(short = 'n', long, value_parser, default_value_t = 10, value_parser = clap::value_parser!(i32).range(1..=10))]
    tables: i32,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    let logfilter = log::get_log_level(&args.logfilter);
    let logdir = Path::new(".").join(&args.logdir);
    std::fs::create_dir_all(&logdir).expect("Failed to create log directory");

    let file_appender = rolling::daily(logdir, &args.logfile);
    let (non_blocking, log_guard) = tracing_appender::non_blocking(file_appender);

    let logger = layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .compact()
        .with_filter(logfilter);

    tracing_subscriber::registry().with(logger).init();

    /*
     * Preparing inputs by reading database
     */

    let postgres = Postgres::new();
    let pg_client = postgres
        .connect()
        .await
        .expect("Failed to connect to Postgres");

    info!("Starting query prover");

    // Step 1. Check the aggregation proof file.
    let proof_dir = Path::new(".").join(&args.receiptdir);
    let aggregation_proof_file = proof_dir.join(&args.aggregation_receiptfile);

    assert!(fs::exists(&aggregation_proof_file).is_ok());
    info!(
        "Verifying aggregation proof file: {}",
        &aggregation_proof_file.display()
    );

    // Load and verify the aggregation proof file.
    let aggregation_proof: AggregationProof =
        bincode::deserialize(&fs::read(&aggregation_proof_file).unwrap()).unwrap();

    // Verify the Nova proof
    let pub_prev_root = Scalar::from_repr(aggregation_proof.pub_prev_root).unwrap();
    let pub_cur_root = Scalar::from_repr(aggregation_proof.pub_cur_root).unwrap();
    let pub_hash_chain = Scalar::from_repr(aggregation_proof.pub_hash_chain).unwrap();
    let pub_n_steps = Scalar::from_repr(aggregation_proof.pub_n_steps).unwrap();
    let n_steps = aggregation_proof.n_steps;
    assert!(Scalar::from(n_steps as u64) == pub_n_steps);
    let vk = aggregation_proof.verifier_key;

    let initial_state = &[pub_prev_root, pub_prev_root, Scalar::ZERO, Scalar::ZERO];

    let res = aggregation_proof
        .compressed_snark
        .verify(&vk, n_steps, initial_state);
    assert!(res.is_ok());
    let final_state = res.unwrap();
    match &final_state[..] {
        [a, b, c, d] => {
            assert!(*a == pub_prev_root);
            assert!(*b == pub_cur_root);
            assert!(*c == pub_hash_chain);
            assert!(*d == pub_n_steps);
        }
        _ => panic!("Expected 4 elements"),
    }

    // // Step 2. Read the aggregated logs from the database.
    let clogs: Vec<CLog> = db::get_clogs(&pg_client).await;

    // Select random source and destination for the query.
    // Source should be different from destination.
    let src = rand::random::<u32>() % args.tables as u32;
    let mut dst = rand::random::<u32>() % args.tables as u32;
    while src == dst {
        dst = rand::random::<u32>() % args.tables as u32;
    }
    assert!(src != dst, "Source and destination must be different");

    let merkle_tree_vector_file = proof_dir.join(&args.merkle_tree_vector_file);
    let clogs_from_file: Vec<CLog> =
        bincode::deserialize(&fs::read(&merkle_tree_vector_file).unwrap()).unwrap();
    assert!(
        clogs_from_file.len() == clogs.len(),
        "Merkle tree vector size mismatch"
    );

    info!(
        "Querying from src: {}, dst: {}, total logs: {}",
        src,
        dst,
        clogs.len()
    );

    // Step 3. Pass the Merkle tree to the guest program.
    let input = QueryPrivateInput {
        clogs: clogs,                     // Aggregated logs: Vec<CLog>
        cur_root: pub_cur_root.to_repr().try_into().unwrap(), // Aggregation Merkle root: Vec<u8>
        src: src as i32,                  // Source for query
        dst: dst as i32,                  // Destination for query
    };

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    // TODO: Experiment with different proving options. 
    // succinct() and composite() are the other options.
    // I expect they will be faster.
    let opts = ProverOpts::composite();

    let start = Instant::now();
    let prove_info = prover
        .prove_with_opts(env, QUERY_METHOD_ELF, &opts)
        .unwrap();
    let elapsed = start.elapsed().as_millis();

    let receipt = prove_info.receipt;

    let journal: QueryJournal = receipt.journal.decode().expect("Journal decoding failed");
    if !journal.success {
        error!("Aggregation failed: {}", journal.message);
        return Ok(());
    }

    // Output receipt to file
    let receiptdir = Path::new(".").join(&args.receiptdir);
    std::fs::create_dir_all(&receiptdir).expect("Failed to create log directory");

    let encoded_receipt = bincode::serialize(&receipt).unwrap();
    let receiptfile = receiptdir.join(&args.receiptfile);
    fs::write(&receiptfile, encoded_receipt).expect("Failed to write receipt");

    info!("Receipt wrote to {}", receiptfile.display());

    info!("Journal size: {} bytes", receipt.journal.bytes.len());
    info!("Seal size: {} bytes", receipt.seal_size());

    info!("Execution took {} ms", elapsed);

    // Make sure all logs are dropped.
    drop(log_guard);

    Ok(())
}
