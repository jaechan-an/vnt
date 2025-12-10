use clap::Parser;

use flate2::read::ZlibDecoder;

use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;

use core::{log, NovaAggregationProof};
use zk;

use std::fs;
use std::path::Path;
use std::time::Instant;

use ff::PrimeField;
use nova_snark::{
    nova::{CompressedSNARK, VerifierKey},
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{Engine, Group},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Log directory
    #[clap(long, default_value = "logs")]
    logdir: String,

    /// Log file name
    #[clap(long, default_value = "verify")]
    logfile: String,

    /// Log level
    #[clap(long, default_value = "INFO")]
    logfilter: String,

    /// Receipt directory
    #[clap(long, default_value = "receipts")]
    receiptdir: String,

    /// Output file path to save the receipt.
    #[clap(
        short = 'r',
        long,
        value_parser,
        default_value = "aggregation_receipt.bin"
    )]
    receiptfile: String,
}

fn main() {
    const HEIGHT: usize = 15;
    const BATCH_SIZE: usize = 10;
    type E1 = Bn256EngineKZG;
    type E2 = GrumpkinEngine;
    type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
    type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
    type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK
    type Scalar = <<E1 as Engine>::GE as Group>::Scalar;
    type C = zk::AggregationCircuit<Scalar, u32, HEIGHT, BATCH_SIZE>;
    type CompSNARK = CompressedSNARK<E1, E2, C, S1, S2>;
    type VK = VerifierKey<E1, E2, C, S1, S2>;
    type ScalarRepr = <Scalar as PrimeField>::Repr;

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

    let receiptdir = Path::new(".").join(&args.receiptdir);
    let proof_file = receiptdir.join(&args.receiptfile);

    assert!(fs::exists(&proof_file).is_ok());

    info!("Verifying proof file: {}", &proof_file.display());

    // Load and verify the proof file.
    let proof_bytes = fs::read(&proof_file).unwrap();
    let decoder = ZlibDecoder::new(&proof_bytes[..]);
    let aggregation_proof: NovaAggregationProof<
        ScalarRepr,
        CompSNARK,
        VK,
    > = bincode::deserialize_from(decoder).unwrap();

    let pub_prev_root = Scalar::from_repr(aggregation_proof.pub_prev_root).unwrap();
    let pub_cur_root = Scalar::from_repr(aggregation_proof.pub_cur_root).unwrap();
    let pub_hash_chain = Scalar::from_repr(aggregation_proof.pub_hash_chain).unwrap();
    let pub_n_steps = Scalar::from_repr(aggregation_proof.pub_n_steps).unwrap();
    let n_steps = aggregation_proof.n_steps;
    assert!(Scalar::from(n_steps as u64) == pub_n_steps);
    let vk = aggregation_proof.verifier_key;

    let initial_state = &[pub_prev_root, pub_prev_root, Scalar::zero(), Scalar::zero()];

    let start = Instant::now();
    let res = aggregation_proof.proof.verify(&vk, n_steps, initial_state);
    assert!(res.is_ok());
    let final_state = res.unwrap();
    match &final_state[..] {
        [a, b, c, d] => {
            assert!(*a == pub_prev_root);
            assert!(*b == pub_cur_root);
            assert!(*c == pub_hash_chain);
            assert!(*d == pub_n_steps);
        },
        _ => error!("Expected 4 elements"),
    }
    let elapsed = start.elapsed().as_millis();

    info!("Execution took {} ms", elapsed);

    // Make sure all logs are dropped.
    drop(log_guard);
}
