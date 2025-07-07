use methods::VNT_ZKP_ID;
use query_methods::QUERY_METHOD_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

use clap::Parser;
use tokio_postgres::Error;

use std::{fs, path::Path, time::Instant};

use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;

use core::{log, postgres::Postgres, AggregationJournal, CLog, QueryJournal, QueryPrivateInput};

mod db;

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

    /// Receipt directory
    #[clap(long, default_value = "receipts")]
    receiptdir: String,

    /// Aggregation receipt
    #[clap(
        short = 'a',
        long,
        value_parser,
        default_value = "aggregation_receipt.bin"
    )]
    aggregation_receiptfile: String,

    /// Output file path to save the receipt.
    #[clap(short = 'q', long, value_parser, default_value = "query.bin")]
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

    let start = Instant::now();

    info!("Starting query prover");

    // Step 1. Check the aggregation receipt file.
    let receiptdir = Path::new(".").join(&args.receiptdir);
    let aggregation_receiptfile = receiptdir.join(&args.aggregation_receiptfile);

    assert!(fs::exists(&aggregation_receiptfile).is_ok());
    info!(
        "Verifying aggregation receipt file: {}",
        &aggregation_receiptfile.display()
    );

    // Load and verify the aggregation receipt file.
    let aggregation_receipt: Receipt =
        bincode::deserialize(&fs::read(&aggregation_receiptfile).unwrap()).unwrap();
    aggregation_receipt.verify(VNT_ZKP_ID).unwrap();

    let aggregation_journal: AggregationJournal = aggregation_receipt.journal.decode().unwrap();
    assert!(
        aggregation_journal.success,
        "Aggregation journal verification failed"
    );

    // Step 2. Read the aggregated logs from the database.
    let clogs: Vec<CLog> = db::get_clogs(&pg_client).await;

    // Step 3. Pass the Merkle tree to the guest program.
    let input = QueryPrivateInput {
        clogs: clogs,                   // Aggregated logs: Vec<CLog>
        tree: aggregation_journal.tree, // Aggregation Merkle tree: Vec<u8>
        root: aggregation_journal.root, // Aggregation Merkle root: Vec<u8>
    };

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    let prove_info = prover.prove(env, QUERY_METHOD_ELF).unwrap();
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

    info!(
        "Query prover completed in {:.2?} sec",
        start.elapsed().as_secs()
    );

    // Make sure all logs are dropped.
    drop(log_guard);

    Ok(())
}
