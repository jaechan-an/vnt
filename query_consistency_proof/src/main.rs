// This circuit is part of the query proofs. It shows that the vector underlying a given Merkle
// root has a given SHA-256 hash.
//
// Uses Microsoft Nova as the proof backend to ensure consistency with the aggregation prover.

use clap::Parser;
use std::{fs, path::Path, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

use ff::{Field, PrimeField};
use nova_snark::{
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK, VerifierKey},
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{snark::RelaxedR1CSSNARKTrait, Engine, Group},
};

use core::{CLog, NovaAggregationProof, NovaConsistencyProof};
use zk::{hash_to_field_elements, ConsistencyCircuit};

// Nova type aliases (matching host/src/main.rs)
const HEIGHT: usize = 15;
const BATCH_SIZE: usize = 10;
type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;
type Scalar = <<E1 as Engine>::GE as Group>::Scalar;
type AggregationCircuitType = zk::AggregationCircuit<Scalar, u32, HEIGHT, BATCH_SIZE>;
type AggregationProof = NovaAggregationProof<
    <Scalar as PrimeField>::Repr,
    CompressedSNARK<E1, E2, AggregationCircuitType, S1, S2>,
    VerifierKey<E1, E2, AggregationCircuitType, S1, S2>,
>;
type ConsistencyCircuitType = ConsistencyCircuit<Scalar>;
type ConsistencyProof = NovaConsistencyProof<
    <Scalar as PrimeField>::Repr,
    CompressedSNARK<E1, E2, ConsistencyCircuitType, S1, S2>,
    VerifierKey<E1, E2, ConsistencyCircuitType, S1, S2>,
>;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Proof directory
    #[clap(long, default_value = "proofs")]
    proof_dir: String,

    /// Aggregation proof file
    #[clap(long, default_value = "aggregation_proof.bin")]
    aggregation_proof_file: String,

    /// Merkle Tree leaves file
    #[clap(long, default_value = "merkle_tree_vector_state.bin")]
    merkle_tree_vector_file: String,

    /// Output file path to save the consistency proof
    #[clap(long, default_value = "consistency_proof.bin")]
    consistency_proof_file: String,
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Step 1. Load the aggregation proof file.
    let proof_dir = Path::new(".").join(&args.proof_dir);
    let aggregation_proof_file = proof_dir.join(&args.aggregation_proof_file);

    assert!(
        aggregation_proof_file.exists(),
        "Aggregation proof file not found: {}",
        aggregation_proof_file.display()
    );
    info!(
        "Loading aggregation proof file: {}",
        aggregation_proof_file.display()
    );

    let aggregation_proof: AggregationProof =
        bincode::deserialize(&fs::read(&aggregation_proof_file).unwrap()).unwrap();

    // Step 2. Verify the Nova aggregation proof.
    let pub_prev_root = Scalar::from_repr(aggregation_proof.pub_prev_root).unwrap();
    let pub_cur_root = Scalar::from_repr(aggregation_proof.pub_cur_root).unwrap();
    let pub_hash_chain = Scalar::from_repr(aggregation_proof.pub_hash_chain).unwrap();
    let pub_n_steps = Scalar::from_repr(aggregation_proof.pub_n_steps).unwrap();
    let n_steps = aggregation_proof.n_steps;
    assert!(Scalar::from(n_steps as u64) == pub_n_steps);
    let vk = aggregation_proof.verifier_key;

    let initial_state = &[pub_prev_root, pub_prev_root, Scalar::ZERO, Scalar::ZERO];

    info!("Verifying Nova aggregation proof ({} steps)...", n_steps);
    let res = aggregation_proof
        .compressed_snark
        .verify(&vk, n_steps, initial_state);
    assert!(res.is_ok(), "Nova proof verification failed");

    let final_state = res.unwrap();
    match &final_state[..] {
        [a, b, c, d] => {
            assert!(*a == pub_prev_root, "prev_root mismatch");
            assert!(*b == pub_cur_root, "cur_root mismatch");
            assert!(*c == pub_hash_chain, "hash_chain mismatch");
            assert!(*d == pub_n_steps, "n_steps mismatch");
        }
        _ => panic!("Expected 4 elements in final state"),
    }
    info!("Nova aggregation proof verified successfully");

    // Step 3. Load the Merkle tree vector file.
    let merkle_tree_vector_file = proof_dir.join(&args.merkle_tree_vector_file);

    assert!(
        merkle_tree_vector_file.exists(),
        "Merkle tree vector file not found: {}",
        merkle_tree_vector_file.display()
    );
    info!(
        "Loading Merkle tree vector file: {}",
        merkle_tree_vector_file.display()
    );

    let clogs: Vec<CLog> =
        bincode::deserialize(&fs::read(&merkle_tree_vector_file).unwrap()).unwrap();

    info!("Loaded {} CLogs from Merkle tree vector", clogs.len());

    // Step 4. Convert CLogs to bytes and compute SHA-256 hash
    let preimage = ConsistencyCircuit::<Scalar>::clogs_to_bytes(&clogs);
    let clogs_hash = ConsistencyCircuit::<Scalar>::hash_clogs(&clogs);
    let (hash_hi, hash_lo): (Scalar, Scalar) = hash_to_field_elements(&clogs_hash);

    info!("CLogs serialized to {} bytes", preimage.len());
    info!("SHA-256 hash of CLogs: {}", hex::encode(&clogs_hash));

    // Step 5. Create the consistency circuit
    let circuit = ConsistencyCircuit::<Scalar>::new(preimage.clone(), clogs_hash, 0);

    // Initial state for consistency proof: [merkle_root, hash_hi, hash_lo, step_count]
    let consistency_initial_state = &[pub_cur_root, hash_hi, hash_lo, Scalar::ZERO];

    info!("Setting up Nova public parameters...");
    let t0 = Instant::now();
    let pp = PublicParams::<E1, E2, _>::setup(&circuit, &*S1::ck_floor(), &*S2::ck_floor())
        .expect("Failed to setup public parameters");
    let setup_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = setup_ms, "public_params");

    let (primary_constraints, secondary_constraints) = pp.num_constraints();
    info!(
        "Circuit constraints: primary={}, secondary={}",
        primary_constraints, secondary_constraints
    );

    // Step 6. Create and run recursive SNARK
    info!("Creating recursive SNARK...");
    let t0 = Instant::now();
    let mut recursive_snark =
        RecursiveSNARK::<E1, E2, _>::new(&pp, &circuit, consistency_initial_state)
            .expect("Failed to create recursive SNARK");

    // Prove one step
    let res = recursive_snark.prove_step(&pp, &circuit);
    assert!(res.is_ok(), "prove_step failed: {:?}", res.err());
    let prove_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prove_ms, "prove");

    // Verify recursive SNARK
    let t0 = Instant::now();
    let res = recursive_snark.verify(&pp, 1, consistency_initial_state);
    assert!(res.is_ok(), "verify failed: {:?}", res.err());
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "verify");

    // Step 7. Compress the SNARK
    info!("Compressing SNARK...");
    let (pk, vk) = CompressedSNARK::<E1, E2, _, S1, S2>::setup(&pp).unwrap();

    let t0 = Instant::now();
    let compressed_snark = CompressedSNARK::<E1, E2, _, S1, S2>::prove(&pp, &pk, &recursive_snark)
        .expect("Failed to create compressed SNARK");
    let compress_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = compress_ms, "compress");

    // Verify compressed SNARK
    let t0 = Instant::now();
    let res = compressed_snark.verify(&vk, 1, consistency_initial_state);
    assert!(res.is_ok(), "compressed verify failed: {:?}", res.err());
    let compressed_verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = compressed_verify_ms, "compressed_verify");

    // Print Merkle roots for comparison
    let final_state = res.unwrap();
    info!("Merkle root from file:   {:?}", pub_cur_root.to_repr());
    info!("Merkle root from proof:  {:?}", final_state[0].to_repr());

    // Step 8. Serialize and write the consistency proof to file
    let consistency_proof = ConsistencyProof {
        pub_merkle_root: pub_cur_root.to_repr(),
        pub_hash_hi: hash_hi.to_repr(),
        pub_hash_lo: hash_lo.to_repr(),
        clogs_hash,
        verifier_key: vk,
        compressed_snark,
    };

    let t0 = Instant::now();
    let proof_encoded =
        bincode::serialize(&consistency_proof).expect("Failed to serialize consistency proof");
    let serialize_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = serialize_ms, "serialize");
    info!("Consistency proof length: {:?} bytes", proof_encoded.len());

    std::fs::create_dir_all(&proof_dir).expect("Failed to create proof directory");

    let consistency_proof_file = proof_dir.join(&args.consistency_proof_file);
    fs::write(&consistency_proof_file, proof_encoded).expect("Failed to write consistency proof");

    info!(
        "Consistency proof written to {}",
        consistency_proof_file.display()
    );

    info!(
        "SUMMARY: setup={} ms, prove={} ms, verify={} ms, compress={} ms, compressed_verify={} ms, serialize={} ms",
        setup_ms, prove_ms, verify_ms, compress_ms, compressed_verify_ms, serialize_ms
    );

    info!("Consistency proof complete!");
    info!("  CLogs SHA-256 hash: {}", hex::encode(&clogs_hash));
}
