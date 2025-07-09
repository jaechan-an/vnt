use query_methods::QUERY_METHOD_ID;

use risc0_zkvm::Receipt;

use clap::Parser;

use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;

use core::{log, QueryJournal};

use std::fs;
use std::path::Path;
use std::time::Instant;

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

    /// Receipt directory
    #[clap(long, default_value = "receipts")]
    receiptdir: String,

    /// Output file path to save the receipt.
    #[clap(short = 'r', long, value_parser, default_value = "query.bin")]
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

    let start = Instant::now();
    receipt.verify(QUERY_METHOD_ID).unwrap();
    let elapsed = start.elapsed().as_millis();

    let journal: QueryJournal = receipt.journal.decode().unwrap();
    if !journal.success {
        error!("Journal verification is not successful!");
    }

    info!("Message: {}", journal.message);

    info!("Journal size: {} bytes", receipt.journal.bytes.len());
    info!("Seal size: {} bytes", receipt.seal_size());

    info!("Execution took {} ms", elapsed);

    // Make sure all logs are dropped.
    drop(log_guard);
}
