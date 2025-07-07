use clap::Parser;
use rand::Rng;

use std::path::Path;
use std::sync::Arc;

use tokio::task;
use tokio_postgres::Client;

use tracing::info;
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;

use core::log;
use core::postgres::Postgres;
use core::Route;

use sha2::{Digest, Sha256};

mod db;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Log directory
    #[clap(long, default_value = "logs")]
    logdir: String,

    /// Log file name
    #[clap(long, default_value = "simulator")]
    logfile: String,

    /// Log level
    #[clap(long, default_value = "INFO")]
    logfilter: String,

    /// Source IP, implies the total count of internal nodes
    #[clap(short = 'n', long, value_parser, default_value_t = 10, value_parser = clap::value_parser!(i32).range(1..=10))]
    tables: i32,

    /// Total running time for the simulator
    #[clap(short = 't', long, value_parser, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=100000))]
    time: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arc::new(Args::parse());

    let logfilter = log::get_log_level(&args.logfilter);
    let logdir = Path::new(".").join(&args.logdir);
    std::fs::create_dir_all(&logdir).expect("Failed to create log directory");

    let file_appender = rolling::daily(logdir, &args.logfile);
    let (non_blocking, log_guard) = tracing_appender::non_blocking(file_appender);

    let debug_logs = layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .compact()
        .with_filter(logfilter);

    tracing_subscriber::registry().with(debug_logs).init();

    info!("Starting simulator with args: {:?}", args);

    let postgres = Postgres::new();
    let pg_client = Arc::new(postgres.connect().await?);

    let mut workers = task::JoinSet::new();

    // Create workers that simulate the network traffic
    for id in 0..args.tables {
        let num_tables = args.tables;
        let client = Arc::clone(&pg_client);
        let duration = std::time::Duration::from_secs(args.time);

        workers.spawn(async move {
            info!("Starting worker for table {}", id);

            let _ = worker_function(id, num_tables, &client, duration).await;

            id as usize
        });
    }

    // Create a worker that generates hashes for the logs
    let round: i32;
    {
        let num_tables = args.tables;
        let client = Arc::clone(&pg_client);
        let duration = std::time::Duration::from_secs(args.time);

        let join = task::spawn(async move {
            info!("Starting hash generation");

            let round = hash_generation(num_tables, &client, duration).await;

            round.unwrap_or(0)
        });

        round = join.await.unwrap();
    }

    while let Some(res) = workers.join_next().await {
        assert!(res.is_ok(), "Worker task failed");
    }

    // Final hash generation
    {
        let num_tables = args.tables;
        let client = Arc::clone(&pg_client);

        let _ = hash_logs(num_tables, &client, round)
            .await
            .expect("Failed to hash logs");
    }

    info!("All workers have completed their tasks");

    // Make sure all logs are dropped.
    drop(log_guard);

    Ok(())
}

async fn worker_function(
    id: i32,
    num_tables: i32,
    client: &Client,
    duration: std::time::Duration,
) -> Result<usize, Box<dyn std::error::Error>> {
    let db_routes = db::get_all_routes(&client).await;

    let mut routes = vec![vec![Route::default(); num_tables as usize]; num_tables as usize];
    for route in &db_routes {
        let src = route.src as usize;
        let dst = route.dst as usize;

        routes[src][dst] = route.clone();
    }

    let now = std::time::Instant::now();

    // Choose a path to run
    // 1. Select a random destination
    // 2. Choose the next hop from the table (minimum cost - greedy algorithm)
    //    TODO: change to a different routing policy
    // 3. BEGIN flows (insert)
    // 4. Insert logs into each hop
    // 5. END flows (udpate status)
    while now.elapsed() <= duration {
        let mut curr_id: i32 = id;

        let dst_id = rand::rng().random_range(0..num_tables);
        let packet_size = rand::rng().random_range(1..=100);
        let mut hop_cnt = 0;

        let flow_id = db::insert_flow(&client, curr_id, dst_id).await;

        while curr_id != dst_id {
            let hop_route = &routes[curr_id as usize][dst_id as usize];

            let pred_id = curr_id;
            curr_id = hop_route.next as i32;

            hop_cnt += 1;

            // Insert log
            db::insert_log(
                &client,
                curr_id,
                flow_id,
                id,
                dst_id,
                pred_id,
                packet_size,
                hop_cnt,
            )
            .await;

            // Mimic a random interval
            let rand_interval = std::time::Duration::from_millis(rand::rng().random_range(5..=10));
            tokio::time::sleep(rand_interval).await;
        }

        db::update_flow(&client, flow_id).await;
    }

    // Return the current thread ID as usize
    Ok(id as usize)
}

async fn hash_generation(
    num_tables: i32,
    client: &Client,
    duration: std::time::Duration,
) -> Result<i32, Box<dyn std::error::Error>> {
    let now = std::time::Instant::now();
    let sleep_time = std::time::Duration::from_secs(5);

    let mut round: i32 = 0;
    while now.elapsed() <= duration {
        let _ = hash_logs(num_tables, client, round).await;

        tokio::time::sleep(sleep_time).await;

        round += 1;
    }

    Ok(round)
}

async fn hash_logs(
    num_tables: i32,
    client: &Client,
    round: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Generating hash for all logs, round: {}", round);

    for i in 0..num_tables {
        let logs = db::get_logs(&client, i).await;

        if logs.is_empty() {
            info!("No logs found for table {}", i);
            continue;
        }

        // Generate hash from all the logs. We want a single hash for all logs in the table.
        let mut hasher = Sha256::new();
        for log in logs {
            let serialized = bincode::serialize(&log).unwrap();
            hasher.update(serialized);
        }

        db::put_hash(&client, i, hasher.finalize().into(), round).await;
    }

    db::put_metadata(&client, "last_logs_hash_round", round.into()).await;

    Ok(())
}
