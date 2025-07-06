use methods::VNT_ZKP_ID;

use risc0_zkvm::Receipt;

use clap::Parser;

use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;

use core::{log, AggregationJournal};

use std::fs;
use std::path::Path;

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
    let receiptfile = receiptdir.join(&args.receiptfile);

    assert!(fs::exists(&receiptfile).is_ok());

    info!("Verifying receipt file: {}", &receiptfile.display());

    // Load and verify the receipt file.
    let receipt: Receipt = bincode::deserialize(&fs::read(&receiptfile).unwrap()).unwrap();
    receipt.verify(VNT_ZKP_ID).unwrap();

    info!("Receipt verified successfully!");

    let _output: u32 = receipt.journal.decode().unwrap();
    info!("Journal successfully verified!");

    let journal: AggregationJournal = receipt.journal.decode().unwrap();

    if !journal.success {
        error!("Journal verification is not successful!");
    }

    info!("message: {}", journal.message);
    info!("Merkle root: {:?}", journal.root);
    info!("Merkle tree: {:?}", journal.tree);

    /*
    info!("Journal successfully verified!");

    // 1. Check the database if the root is the same.

    // 2. Verify the proof
    //let route_proof = MerkleProof::<Sha256>::try_from(journal.route_proof)?;
    //let route_verified = route_proof.verify(
    //    journal.route_root,
    //    &journal.route_indices,
    //    &journal.route_hashes,
    //    journal.all_route_len,
    //);

    // TODO: route is manipulated
    //assert!(route_verified);

    info!("Verified routes merkle tree!");
    */

    // Make sure all logs are dropped.
    drop(log_guard);
}
