use clap::Parser;
use tokio_postgres::Error;

use std::{collections::HashMap, fs, iter, path::Path, time::Instant};

use tracing::info;
use tracing_appender::rolling;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::prelude::*;

use core::{log, postgres::Postgres, util, CLog, Log, NovaAggregationProof};
use zk;

use ff::{Field, PrimeField};
use nova_snark::{
    frontend::gadgets::poseidon::{Sponge, SpongeTrait, Strength},
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{snark::RelaxedR1CSSNARKTrait, Engine, Group},
};

mod db;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Log directory
    #[clap(long, default_value = "logs")]
    logdir: String,

    /// Log file name
    #[clap(long, default_value = "aggregation_prover")]
    logfile: String,

    /// Log level
    #[clap(long, default_value = "INFO")]
    logfilter: String,

    /// Proof directory
    #[clap(long, default_value = "proofs")]
    proof_dir: String,

    /// Output file path to save the proof.
    #[clap(
        short = 'r',
        long,
        value_parser,
        default_value = "aggregation_proof.bin"
    )]
    proof_file: String,

    /// File containing the vector of CLogs
    #[clap(
        short = 'r',
        long,
        value_parser,
        default_value = "merkle_tree_vector_state.bin"
    )]
    merkle_tree_vector_state: String,

    /// Total count of internal nodes
    #[clap(short = 'n', long, value_parser, default_value_t = 10, value_parser = clap::value_parser!(i32).range(1..=10))]
    tables: i32,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    const HEIGHT: usize = 15;
    const BATCH_SIZE: usize = 10;
    const BATCHES_PER_STEP: usize = 10;
    type E1 = Bn256EngineKZG;
    type E2 = GrumpkinEngine;
    type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
    type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
    type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK
    type Scalar = <<E1 as Engine>::GE as Group>::Scalar;
    type C = zk::AggregationCircuit<Scalar, u32, HEIGHT, BATCH_SIZE>;
    type ZKClog = zk::CompressedLog<Scalar>;
    type ZKLog = zk::Log<u32>;
    type CompSNARK = CompressedSNARK<E1, E2, C, S1, S2>;

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

    info!("Starting aggregation prover");

    let proof_dir = Path::new(".").join(&args.proof_dir);

    /*
     * 1. Check if there are new logs to process
     * 2. Read all logs and hashes from database
     * 3. Read all new logs that were written since the last sequence number
     * 4. Calculate the diff between the aggregation of new logs and the existing CLogs
     */

    let prev_seq = db::get_metadata(&pg_client, "last_seq").await;
    info!("Processing new logs from seq > {}", prev_seq);

    // Read all logs and hashes from database
    let mut logs: Vec<Vec<Log>> = Vec::new();
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    let num_tables = args.tables;

    let hash_round = db::get_metadata(&pg_client, "last_logs_hash_round").await as i32;

    for i in 0..num_tables {
        let table_logs = db::get_logs(&pg_client, i).await;
        logs.push(table_logs);
        info!(
            "Fetched {} logs from table {}",
            logs.last().unwrap().len(),
            i
        );

        let table_hash = db::get_hash(&pg_client, i, hash_round).await;
        hashes.push(table_hash);
    }
    info!(
        "Total logs fetched from all tables: {}",
        logs.iter().map(|l| l.len()).sum::<usize>()
    );

    // Read all new logs that were written since the last sequence number
    let new_logs = db::get_new_logs(&pg_client, &args.tables, &prev_seq).await;
    assert!(new_logs.len() != 0, "No logs found to process");

    // Must get before upsert
    let old_clogs: Vec<CLog> = db::get_clogs(&pg_client).await;
    let old_clogs_map: HashMap<i32 /* user_id */, CLog> = old_clogs
        .iter()
        .map(|clog| (clog.user_id, clog.clone()))
        .collect();

    let mut clogs_map = old_clogs_map.clone();

    // Calculate the CLogs to insert or update (without the ids yet)
    let insertion_order = aggregate_logs(&mut clogs_map, &new_logs);

    // Distinguish the updates and inserts by checking the old clogs table.
    // If it exists, we update. If not, we insert and use the id as clog.id.
    // We DO NOT use the clog.id as the id. It's assigned during the database inserts.
    let mut update_clogs: HashMap<i32 /* user_id */, CLog> = clogs_map
        .iter()
        .filter(|(user_id, _clog)| old_clogs_map.contains_key(user_id))
        .map(|(user_id, clog)| (*user_id, clog.clone()))
        .collect();
    let mut insert_clogs: HashMap<i32 /* user_id */, CLog> = insertion_order
        .iter()
        .filter(|user_id| !old_clogs_map.contains_key(user_id))
        .map(|user_id| (*user_id, clogs_map.get(user_id).unwrap().clone()))
        .collect();
    let insertion_order: Vec<i32> = insertion_order
        .iter()
        .filter(|user_id| insert_clogs.contains_key(user_id))
        .map(|user_id| *user_id)
        .collect();
    // Update keys don't contain Insert keys
    assert!(
        update_clogs
            .keys()
            .all(|user_id| !insert_clogs.contains_key(user_id)),
        "Update clogs contain insert clog keys"
    );

    info!("Old CLogs:");
    for clog in old_clogs.iter() {
        info!("  {}", clog.to_string());
    }

    /*
     * Update database with new aggregated CLogs
     */
    for (_flow_id, clog) in update_clogs.iter_mut() {
        let id = db::update_aggregate_clog(&pg_client, &clog).await;
        clog.id = id;
    }
    for user_id in insertion_order.iter() {
        let clog: &mut CLog = insert_clogs.get_mut(&user_id).unwrap();
        let id = db::insert_clog(&pg_client, clog).await;
        clog.id = id;
    }

    info!("Update CLogs:");
    for clog in update_clogs.values() {
        info!("  {}", clog.to_string());
    }
    info!("Insert CLogs:");
    for user_id in insertion_order.iter() {
        info!("  {}", insert_clogs.get(&user_id).unwrap().to_string());
    }

    // Update the last sequence number in the database metadata
    let curr_seq = db::get_curr_seq(&pg_client).await;
    db::put_metadata(&pg_client, "last_seq", curr_seq).await;
    info!("Updated last_seq in DB metadata to {}", curr_seq);

    let mut new_clogs: Vec<CLog> = db::get_clogs(&pg_client).await;
    new_clogs.sort_unstable_by_key(|clog| clog.id);
    let new_clogs_map: HashMap<i32 /* user_id */, CLog> = new_clogs
        .iter()
        .map(|clog| (clog.user_id, clog.clone()))
        .collect();

    info!("New CLogs:");
    for clog in new_clogs.iter() {
        info!("  {}", clog.to_string());
    }

    // Check if the new clogs contain the match of update_clogs and exact match of insert_clogs
    assert!(
        update_clogs.iter().all(|(user_id, clog)| {
            new_clogs_map.contains_key(user_id) && new_clogs_map.get(user_id).unwrap().id == clog.id
        }),
        "Updated clogs not found in new clogs"
    );
    assert!(
        insert_clogs.iter().all(|(user_id, clog)| {
            new_clogs_map.contains_key(user_id) && new_clogs_map.get(user_id).unwrap() == clog
        }),
        "Inserted clogs not found in new clogs"
    );

    // Build circuits

    // Build input: old compressed logs
    // This is the same as old_clogs_map but we convert Clog to ZKCLog
    // next_idx is 0 for now, will be filled in during circuit creation
    let old_compressed_logs: HashMap<u32, ZKClog> = old_clogs_map
        .clone()
        .into_iter()
        .map(|(k, clog)| {
            (
                k as u32,
                ZKClog {
                    merkle_idx: util::id_to_idx(clog.id),
                    user_id: Scalar::from(clog.user_id as u64),
                    hash_chain: Scalar::from_bytes(clog.hash_chain[..].try_into().unwrap())
                        .unwrap(),
                },
            )
        })
        .collect();

    // Build input: new raw logs

    const EMPTY_LOG: ZKLog = ZKLog {
        id: 0,
        user_id: 0,
        src: 0,
        dst: 0,
        pred: 0,
        packet_size: 0,
        hop_cnt: 0,
    };
    let mut batch_padding = 0;
    let mut new_raw_logs: Vec<ZKLog> = new_logs
        .iter()
        .enumerate()
        .map(|(i, node_logs)| {
            // For each router we need to pad the logs to a multiple of the batch size
            let n_pad = match node_logs.len() % BATCH_SIZE {
                0 => 0,
                x => BATCH_SIZE - x,
            };
            info!("node {}: found {} new logs", i, node_logs.len());
            batch_padding += n_pad;
            node_logs
                .iter()
                .map(|log| ZKLog {
                    id: log.id as u32,
                    user_id: log.flow_id as u32,
                    src: log.src as u32,
                    dst: log.dst as u32,
                    pred: log.pred as u32,
                    packet_size: log.packet_size as u32,
                    hop_cnt: log.hop_cnt as u32,
                })
                .chain(iter::repeat_n(EMPTY_LOG, n_pad))
        })
        .flatten()
        .collect();
    let n_pad = match new_raw_logs.len() % (BATCH_SIZE * BATCHES_PER_STEP) {
        0 => 0,
        x => (BATCH_SIZE * BATCHES_PER_STEP) - x,
    };
    new_raw_logs.extend(iter::repeat_n(EMPTY_LOG, n_pad));

    info!(
        "added {} logs to pad to batch size, {} to pad to step size",
        batch_padding, n_pad
    );

    let (circuits, (pub_prev_root, pub_cur_root, pub_hash_chain, pub_n_steps)) =
        C::new_circuits(&old_compressed_logs, new_raw_logs, BATCHES_PER_STEP);

    let t0 = Instant::now();
    let pp =
        PublicParams::<E1, E2, _>::setup(&circuits[0], &*S1::ck_floor(), &*S2::ck_floor()).unwrap();
    let pp_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = pp_ms, "public_params");

    let (primary_vars, secondary_vars) = pp.num_variables();
    info!(
        "Circuit variables: primary={}, secondary={}",
        primary_vars, secondary_vars
    );
    let (primary_constraints, secondary_constraints) = pp.num_constraints();
    info!(
        "Circuit constraints: primary={}, secondary={}",
        primary_constraints, secondary_constraints
    );

    let initial_state = &[pub_prev_root, pub_prev_root, Scalar::ZERO, Scalar::ZERO];

    let n_steps = circuits.len();
    // let n_clogs = old_compressed_logs.len();

    // Create recursive SNARK
    let mut recursive_snark: RecursiveSNARK<E1, E2, C> =
        RecursiveSNARK::<E1, E2, C>::new(&pp, &circuits[0], initial_state).unwrap();

    // PROVE
    let t0 = Instant::now();
    for circuit in circuits.iter() {
        let res = recursive_snark.prove_step(&pp, circuit);
        assert!(res.is_ok());
    }
    let prove_ms = t0.elapsed().as_millis();
    let step_ms = prove_ms / (n_steps as u128);
    info!(elapsed_ms = step_ms, "prove_step");
    info!(elapsed_ms = prove_ms, "prove");

    // VERIFY
    let t0 = Instant::now();
    let res = recursive_snark.verify(&pp, n_steps, initial_state);
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "verify");
    assert!(res.is_ok());

    // Create compressed SNARK
    let (pk, vk) = CompSNARK::setup(&pp).unwrap();

    // COMPRESSED PROVE
    let t0 = Instant::now();
    let res = CompSNARK::prove(&pp, &pk, &recursive_snark);
    let compressed_prove_ms = t0.elapsed().as_millis();
    assert!(res.is_ok());
    info!(elapsed_ms = compressed_prove_ms, "compressed_prove");

    let compressed_snark = res.unwrap();

    let nova_proof = NovaAggregationProof {
        pub_prev_root: pub_prev_root.to_repr(),
        pub_cur_root: pub_cur_root.to_repr(),
        pub_hash_chain: pub_hash_chain.to_repr(),
        pub_n_steps: pub_n_steps.to_repr(),
        n_steps,
        verifier_key: vk,
        compressed_snark,
    };

    let t0 = Instant::now();
    let proof_encoded = bincode::serialize(&nova_proof).expect("Failed to serialize proof");
    let serialize_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = serialize_ms, "serialize");
    info!("proof length: {:?} bytes", proof_encoded.len());

    // Output compressed snark to file
    std::fs::create_dir_all(&proof_dir).expect("Failed to create log directory");

    let proof_file = proof_dir.join(&args.proof_file);
    fs::write(&proof_file, proof_encoded).expect("Failed to write proof");

    info!("Proof written to {}", proof_file.display());

    // Write the CLogs to persistent storage
    let t0 = Instant::now();
    let clog_vector_encoded = bincode::serialize(&new_clogs).expect("Failed to serialize proof");
    let serialize_clogs_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = serialize_clogs_ms, "serialize clogs");
    info!("clog vector length: {:?} bytes", clog_vector_encoded.len());

    let clog_vector_file = proof_dir.join(&args.merkle_tree_vector_state);
    fs::write(&clog_vector_file, clog_vector_encoded).expect("Failed to write clog vector");

    info!("Clog vector written to {}", clog_vector_file.display());

    // Make sure all logs are dropped.
    drop(log_guard);

    Ok(())
}

/**
 * Aggregates logs from all nodes into a single HashMap where the key is the flow_id.
 * The CLog struct is used to represent the aggregated log.
 */
fn aggregate_logs(old_clogs: &mut HashMap<i32, CLog>, new_logs: &Vec<Vec<Log>>) -> Vec<i32> {
    type ZKLog = zk::Log<u32>;
    type E1 = Bn256EngineKZG;
    type Scalar = <<E1 as Engine>::GE as Group>::Scalar;

    let hash_params = Sponge::<Scalar, zk::U2>::api_constants(Strength::Standard);

    let mut insertion_order = Vec::<i32>::new();

    for logs in new_logs {
        for log in logs {
            let key = log.flow_id;

            // If we're inserting, update the insertion order
            if !old_clogs.contains_key(&key) {
                insertion_order.push(key);
            }

            let zklog_packed = ZKLog {
                id: log.id as u32,
                user_id: log.flow_id as u32,
                src: log.src as u32,
                dst: log.dst as u32,
                pred: log.pred as u32,
                packet_size: log.packet_size as u32,
                hop_cnt: log.hop_cnt as u32,
            }
            .to_scalar_log()
            .pack();

            // If key exists, modify it; otherwise, insert a new value
            old_clogs
                .entry(key)
                .and_modify(|clog: &mut CLog| {
                    clog.hash_chain = zk::hash_U2(
                        vec![
                            Scalar::from_bytes(clog.hash_chain[..].try_into().unwrap()).unwrap(),
                            zklog_packed,
                        ],
                        &hash_params,
                    )
                    .to_bytes()
                    .into()
                })
                .or_insert(CLog {
                    id: log.id,
                    user_id: log.flow_id,
                    hash_chain: zk::hash_U2(vec![Scalar::ZERO, zklog_packed], &hash_params)
                        .to_bytes()
                        .into(),
                });
        }
    }

    insertion_order
}
