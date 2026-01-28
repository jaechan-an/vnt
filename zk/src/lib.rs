#![allow(non_snake_case)]
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::frontend::{
    AllocatedBit, Boolean, ConstraintSystem, Elt, PoseidonConstants, SpongeCircuit, SynthesisError,
    gadgets::{
        boolean::field_into_allocated_bits_le,
        poseidon::{IOPattern, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength},
    },
    num::{AllocatedNum, Num},
};
use nova_snark::traits::circuit::StepCircuit;
use std::marker::PhantomData;

pub use generic_array::typenum::{U1, U2};
pub use merkle_trees::vanilla_tree;
pub use merkle_trees::vanilla_tree::tree::{Leaf, MerkleTree, idx_to_bits};

use serde::{Deserialize, Serialize};
use std::cmp::Ord;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::hash::Hash;
use std::iter::zip;

// Annoyingly, nova_snark::frontend::num::AllocatedNum and bellpepper::gadgets::num::AllocatedNum
// seem to be incompatible. Hence we reproduce various functions from other crates below.
pub fn hash_U1<F: PrimeField>(input: Vec<F>, p: &PoseidonConstants<F, U1>) -> F {
    let parameter = IOPattern(vec![
        SpongeOp::Absorb(input.len() as u32),
        SpongeOp::Squeeze(1),
    ]);
    let mut sponge = Sponge::new_with_constants(p, Simplex);
    let acc = &mut ();

    sponge.start(parameter, None, acc);
    SpongeAPI::absorb(&mut sponge, input.len() as u32, &input, acc);

    let output = SpongeAPI::squeeze(&mut sponge, 1, acc);
    assert_eq!(output.len(), 1);

    sponge.finish(acc).unwrap();

    output[0]
}

pub fn hash_U2<F: PrimeField>(input: Vec<F>, p: &PoseidonConstants<F, U2>) -> F {
    let parameter = IOPattern(vec![
        SpongeOp::Absorb(input.len() as u32),
        SpongeOp::Squeeze(1),
    ]);
    let mut sponge = Sponge::new_with_constants(p, Simplex);
    let acc = &mut ();

    sponge.start(parameter, None, acc);
    SpongeAPI::absorb(&mut sponge, input.len() as u32, &input, acc);

    let output = SpongeAPI::squeeze(&mut sponge, 1, acc);
    assert_eq!(output.len(), 1);

    sponge.finish(acc).unwrap();

    output[0]
}
pub fn hash_circuit_U1<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    input: Vec<AllocatedNum<F>>,
    p: &PoseidonConstants<F, U1>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut sponge = SpongeCircuit::<F, U1, _>::new_with_constants(p, Simplex);

    let mut ns = cs.namespace(|| "ns");

    let val_var: Vec<Elt<F>> = input
        .clone()
        .into_iter()
        .map(|s| Elt::Allocated(s))
        .collect();
    assert_eq!(val_var.len(), input.len());

    let acc = &mut ns;
    let parameter = IOPattern(vec![
        SpongeOp::Absorb(input.len() as u32),
        SpongeOp::Squeeze(1),
    ]);

    sponge.start(parameter, None, acc);

    SpongeAPI::absorb(&mut sponge, input.len() as u32, val_var.as_slice(), acc);

    let calc_node = SpongeAPI::squeeze(&mut sponge, 1, acc);

    assert_eq!(calc_node.len(), 1);

    sponge.finish(acc).unwrap();

    calc_node[0].ensure_allocated(acc, true)
}
// This crate is honestly just incredibly toxic. nova_snark doesn't expose the internal Arity trait
// so we have to write separate implementations for U1 and U2
pub fn hash_circuit_U2<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    input: Vec<AllocatedNum<F>>,
    p: &PoseidonConstants<F, U2>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut sponge = SpongeCircuit::<F, U2, _>::new_with_constants(p, Simplex);

    let mut ns = cs.namespace(|| "ns");

    let val_var: Vec<Elt<F>> = input
        .clone()
        .into_iter()
        .map(|s| Elt::Allocated(s))
        .collect();
    assert_eq!(val_var.len(), input.len());

    let acc = &mut ns;
    let parameter = IOPattern(vec![
        SpongeOp::Absorb(input.len() as u32),
        SpongeOp::Squeeze(1),
    ]);

    sponge.start(parameter, None, acc);

    SpongeAPI::absorb(&mut sponge, input.len() as u32, val_var.as_slice(), acc);

    let calc_node = SpongeAPI::squeeze(&mut sponge, 1, acc);

    assert_eq!(calc_node.len(), 1);

    sponge.finish(acc).unwrap();

    calc_node[0].ensure_allocated(acc, true)
}
pub fn pack_bits<Scalar, CS>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut num = Num::<Scalar>::zero();
    let mut coeff = Scalar::ONE;
    for bit in bits.iter().take(Scalar::CAPACITY as usize) {
        num = num.add_bool_with_coeff(CS::one(), bit, coeff);

        coeff = coeff.double();
    }

    let alloc_num = AllocatedNum::alloc(cs.namespace(|| "input"), || {
        num.get_value().ok_or(SynthesisError::AssignmentMissing)
    })?;

    // num * 1 = input
    cs.enforce(
        || "packing constraint",
        |_| num.lc(Scalar::ONE),
        |lc| lc + CS::one(),
        |lc| lc + alloc_num.get_variable(),
    );

    Ok(alloc_num)
}

pub fn path_computed_root<
    F: PrimeField + PrimeFieldBits,
    const N: usize,
    CS: ConstraintSystem<F>,
>(
    cs: &mut CS,
    val_var: Vec<AllocatedNum<F>>,
    mut idx_var: Vec<AllocatedBit>,
    siblings_var: Vec<AllocatedNum<F>>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let node_hash_params = Sponge::<F, U2>::api_constants(Strength::Standard);
    let leaf_hash_params = Sponge::<F, U1>::api_constants(Strength::Standard);
    let mut cur_hash_var = hash_circuit_U1(
        &mut cs.namespace(|| "hash num -1 :"),
        val_var,
        &leaf_hash_params,
    )
    .unwrap();

    idx_var.reverse(); // Going from leaf to root

    for (i, sibling) in siblings_var.clone().into_iter().rev().enumerate() {
        let (lc, rc) = AllocatedNum::conditionally_reverse(
            &mut cs.namespace(|| format!("rev num {} :", i)),
            &cur_hash_var,
            &sibling,
            &Boolean::from(idx_var[i].clone()),
        )
        .unwrap();
        cur_hash_var = hash_circuit_U2(
            &mut cs.namespace(|| format!("hash num {} :", i)),
            vec![lc, rc],
            &node_hash_params,
        )
        .unwrap();
    }

    Ok(cur_hash_var)
}
// end reproduced functions

#[derive(Clone, Debug)]
pub struct Log<T> {
    pub id: T,
    pub flow_id: T,
    pub src: T,
    pub dst: T,
    pub pred: T,
    pub packet_size: T,
    pub hop_cnt: T,
}

const ENTRY_SIZE: usize = 32;
const LOG_OFFSETS: Log<(usize, usize)> = Log {
    // This defines the packing of Log fields into a Scalar. Each field takes up 32 bits in the resulting Scalar.
    id: (ENTRY_SIZE * 0, ENTRY_SIZE),
    flow_id: (ENTRY_SIZE * 1, ENTRY_SIZE),
    src: (ENTRY_SIZE * 2, ENTRY_SIZE),
    dst: (ENTRY_SIZE * 3, ENTRY_SIZE),
    pred: (ENTRY_SIZE * 4, ENTRY_SIZE),
    packet_size: (ENTRY_SIZE * 5, ENTRY_SIZE),
    hop_cnt: (ENTRY_SIZE * 6, ENTRY_SIZE),
};

impl<T> Log<T> {
    fn fields(&self) -> Vec<&T> {
        // List of all fields that are hashed
        vec![
            &self.id,
            &self.flow_id,
            &self.src,
            &self.dst,
            &self.pred,
            &self.packet_size,
            &self.hop_cnt,
        ]
    }
}

impl<T: Copy + Into<u64>> Log<T> {
    fn to_scalar_log<Scalar: PrimeField + PrimeFieldBits>(&self) -> Log<Scalar> {
        Log {
            id: Scalar::from(self.id.into()),
            flow_id: Scalar::from(self.flow_id.into()),
            src: Scalar::from(self.src.into()),
            dst: Scalar::from(self.dst.into()),
            pred: Scalar::from(self.pred.into()),
            packet_size: Scalar::from(self.packet_size.into()),
            hop_cnt: Scalar::from(self.hop_cnt.into()),
        }
    }
}

pub fn update_clogs<T: Eq + Hash + Copy + Into<u64>, Scalar: PrimeField + PrimeFieldBits>(
    compressed_logs: &mut HashMap<T, CompressedLog<Scalar>>,
    raw_log: &Log<T>,
) -> CompressedLog<Scalar> {
    let scalar_log = raw_log.to_scalar_log::<Scalar>();
    let len = compressed_logs.len();
    match compressed_logs.entry(raw_log.flow_id) {
        Entry::Occupied(clog) => {
            let clog = clog.into_mut();
            clog.hop_cnt += scalar_log.hop_cnt;
            (*clog).clone()
        }
        Entry::Vacant(entry) => {
            let clog = CompressedLog::from_idx_log(len, &scalar_log);
            entry.insert(clog.clone());
            clog
        }
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> Log<Scalar> {
    fn pack(&self) -> Scalar {
        // Combine fields into a single Scalar.
        let mut packed = Scalar::ZERO;
        let TWO = Scalar::from(2);
        for (field, (offset, _nbits)) in zip(self.fields(), LOG_OFFSETS.fields()) {
            packed += *field * TWO.pow(std::slice::from_ref(&(*offset as u64)));
        }
        packed
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressedLog<Scalar> {
    pub merkle_idx: usize,
    pub id: Scalar,
    pub flow_id: Scalar,
    pub src: Scalar,
    pub dst: Scalar,
    pub packet_size: Scalar,
    pub hop_cnt: Scalar,
}

const CLOG_OFFSETS: CompressedLog<(usize, usize)> = CompressedLog {
    // Each CompressedLog field takes up 32 bits in the resulting Scalar.
    merkle_idx: 0,
    id: (ENTRY_SIZE * 0, ENTRY_SIZE),
    flow_id: (ENTRY_SIZE * 1, ENTRY_SIZE),
    src: (ENTRY_SIZE * 2, ENTRY_SIZE),
    dst: (ENTRY_SIZE * 3, ENTRY_SIZE),
    packet_size: (ENTRY_SIZE * 4, ENTRY_SIZE),
    hop_cnt: (ENTRY_SIZE * 5, ENTRY_SIZE),
};

impl<T> CompressedLog<T> {
    fn fields(&self) -> Vec<&T> {
        // List of all fields that are hashed
        vec![
            &self.id,
            &self.flow_id,
            &self.src,
            &self.dst,
            &self.packet_size,
            &self.hop_cnt,
        ]
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> CompressedLog<Scalar> {
    pub fn to_leaf(&self) -> Leaf<Scalar, U1> {
        Leaf {
            val: vec![self.pack()],
            _arity: PhantomData::<U1>,
        }
    }

    fn from_idx_log(merkle_idx: usize, log: &Log<Scalar>) -> Self {
        CompressedLog {
            merkle_idx,
            id: Scalar::from((merkle_idx as u64) + 1),
            flow_id: log.flow_id,
            src: log.src,
            dst: log.dst,
            packet_size: log.packet_size,
            hop_cnt: log.hop_cnt,
        }
    }

    fn pack(&self) -> Scalar {
        // Combine fields into a single Scalar.
        let mut packed = Scalar::ZERO;
        let TWO = Scalar::from(2);
        for (field, (offset, _nbits)) in zip(self.fields(), CLOG_OFFSETS.fields()) {
            packed += *field * TWO.pow(std::slice::from_ref(&(*offset as u64)));
        }
        packed
    }

    pub fn to_repr(&self) -> CompressedLog<Scalar::Repr> {
        CompressedLog {
            merkle_idx: self.merkle_idx,
            id: self.id.to_repr(),
            flow_id: self.flow_id.to_repr(),
            src: self.src.to_repr(),
            dst: self.dst.to_repr(),
            packet_size: self.packet_size.to_repr(),
            hop_cnt: self.hop_cnt.to_repr(),
        }
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> CompressedLog<Scalar> {
    pub fn from_repr(repr: &CompressedLog<Scalar::Repr>) -> Self {
        CompressedLog {
            merkle_idx: repr.merkle_idx,
            id: Scalar::from_repr(repr.id).unwrap(),
            flow_id: Scalar::from_repr(repr.flow_id).unwrap(),
            src: Scalar::from_repr(repr.src).unwrap(),
            dst: Scalar::from_repr(repr.dst).unwrap(),
            packet_size: Scalar::from_repr(repr.packet_size).unwrap(),
            hop_cnt: Scalar::from_repr(repr.hop_cnt).unwrap(),
        }
    }
}

// Returns a string representation of the leaves. Repeated empty leaves are compressed
fn tree_str<Scalar: PrimeField + PrimeFieldBits, const N: usize>(
    tree: &MerkleTree<Scalar, N, U1, U2>,
) -> String {
    let mut empty_streak = 0;
    let mut elements: Vec<String> = vec![];
    let empty_hash =
        vanilla_tree::tree::Leaf::<Scalar, U1>::default().hash_leaf(&tree.leaf_hash_params);
    for leaf_hash in tree.iter_leaf_hashes() {
        if leaf_hash == empty_hash {
            empty_streak += 1;
        } else {
            if empty_streak != 0 {
                elements.push(format!("<empty> x {}", empty_streak));
                empty_streak = 0;
            }
            let bits: Vec<bool> = tree
                .leaf_hash_db
                .get(&format!("{:?}", leaf_hash))
                .unwrap()
                .val[0]
                .to_le_bits()
                .into_iter()
                .collect();
            let fields: Vec<u64> = CLOG_OFFSETS
                .fields()
                .iter()
                .map(|(offset, nbits)| {
                    bits[*offset..*offset + *nbits]
                        .iter()
                        .rev()
                        .fold(0u64, |acc, x| acc * 2 + (*x as u64))
                })
                .collect();
            elements.push(format!("{:?}", fields));
        }
    }
    if empty_streak != 0 {
        elements.push(format!("<empty> x {}", empty_streak));
    }
    elements.join(", ")
}

#[derive(Clone, Debug)]
pub struct Batch<
    Scalar: PrimeField + PrimeFieldBits,
    K: Ord + Hash + Copy + Into<u64> + Sync + Send,
    const BATCH_SIZE: usize,
> {
    pub raw_logs: [Log<K>; BATCH_SIZE], // Single batch of raw logs from router
    pub idxs: [usize; BATCH_SIZE],
    pub siblings: [Vec<Scalar>; BATCH_SIZE],
    pub old_clogs: [Option<CompressedLog<Scalar>>; BATCH_SIZE], // Old compressed logs
}

#[derive(Clone, Debug)]
pub struct AggregationCircuit<
    Scalar: PrimeField + PrimeFieldBits,
    K: Ord + Hash + Copy + Into<u64> + Sync + Send,
    const HEIGHT: usize,
    const BATCH_SIZE: usize,
> {
    pub batches: Vec<Batch<Scalar, K, BATCH_SIZE>>,
    pub step_count: Scalar,
}

impl<
    Scalar: PrimeField + PrimeFieldBits,
    K: Ord + Hash + Copy + Into<u64> + Sync + Send,
    const HEIGHT: usize,
    const BATCH_SIZE: usize,
> AggregationCircuit<Scalar, K, HEIGHT, BATCH_SIZE>
{
    // Outputs a vector of circuits, and also the expected (public) final state
    pub fn new_circuits(
        old_compressed_logs: &HashMap<K, CompressedLog<Scalar>>,
        raw_logs: Vec<Log<K>>,
        batches_per_step: usize,
    ) -> (Vec<Self>, (Scalar, Scalar, Scalar, Scalar)) {
        // Split the new logs into batches
        let (batched_logs, rem) = raw_logs.as_chunks::<BATCH_SIZE>();
        assert_eq!(
            rem.len(),
            0,
            "Number of inputs ({}) was not a multiple of the batch size ({})",
            raw_logs.len(),
            BATCH_SIZE
        );
        let batched_logs = batched_logs.to_vec();

        let step_logs_iter = batched_logs.chunks_exact(batches_per_step);
        assert_eq!(
            step_logs_iter.remainder().len(),
            0,
            "Number of batches ({}) was not a multiple of batches_per_step ({})",
            batched_logs.len(),
            batches_per_step
        );

        // Build prev_tree from old compressed logs
        let mut merkle_leaves: Vec<Option<_>> = Vec::new();
        merkle_leaves.resize(old_compressed_logs.len(), None);
        for clog in old_compressed_logs.values() {
            merkle_leaves[clog.merkle_idx] = Some(clog);
        }

        let merkle_leaves: Vec<_> = merkle_leaves
            .iter()
            .map(|clog| clog.unwrap().to_leaf())
            .collect();

        let prev_tree: MerkleTree<Scalar, HEIGHT, U1, U2> =
            MerkleTree::from_vec(merkle_leaves.clone(), vanilla_tree::tree::Leaf::default());

        println!("prev tree: {}", tree_str(&prev_tree));

        // Compress the new logs
        let mut compressed_logs = old_compressed_logs.clone();

        let mut new_tree = prev_tree.clone();

        let log_hash_constants = Sponge::<Scalar, U2>::api_constants(Strength::Standard);
        let mut hash_chain = Scalar::ZERO;

        // Create circuits
        let circuits: Vec<_> = step_logs_iter
            .enumerate()
            .map(|(step, batches)| {
                let circuit_batches = batches
                    .iter()
                    .map(|batch| {
                        let mut idxs: Vec<usize> = Vec::new();
                        let mut siblings: Vec<Vec<Scalar>> = Vec::new();
                        let mut old_clogs: Vec<Option<CompressedLog<Scalar>>> = Vec::new();
                        let mut scalar_logs: Vec<Scalar> = Vec::new();

                        for log in batch.into_iter() {
                            let scalar_log = log.to_scalar_log();
                            let packed_log = scalar_log.pack();
                            scalar_logs.push(packed_log);
                            let old_clog = compressed_logs.get(&log.flow_id).cloned();
                            if packed_log != Scalar::ZERO {
                                let clog = update_clogs(&mut compressed_logs, &log);
                                let idx = clog.merkle_idx;
                                let idx_bits = idx_to_bits(HEIGHT, Scalar::from(idx as u64));
                                new_tree.insert(idx_bits.clone(), &clog.to_leaf());
                                let siblings_path = new_tree.get_siblings_path(idx_bits);
                                siblings.push(siblings_path.siblings);
                                idxs.push(idx);
                                old_clogs.push(old_clog);
                            } else {
                                // Log is empty -- "insert" empty CLog at largest possible index to
                                // simulate a no-op
                                let last_idx = (1 << HEIGHT) - 1;
                                let zero_clog = CompressedLog {
                                    merkle_idx: last_idx,
                                    id: Scalar::ZERO,
                                    flow_id: Scalar::ZERO,
                                    src: Scalar::ZERO,
                                    dst: Scalar::ZERO,
                                    packet_size: Scalar::ZERO,
                                    hop_cnt: Scalar::ZERO,
                                };
                                let idx_bits = idx_to_bits(HEIGHT, Scalar::from(last_idx as u64));
                                let siblings_path = new_tree.get_siblings_path(idx_bits);
                                siblings.push(siblings_path.siblings);
                                idxs.push(last_idx);
                                old_clogs.push(Some(zero_clog));
                            }
                        }

                        let batch_hash = hash_U2(scalar_logs, &log_hash_constants);
                        hash_chain = hash_U2(vec![hash_chain, batch_hash], &log_hash_constants);

                        Batch {
                            raw_logs: batch.clone(),
                            idxs: idxs.try_into().unwrap(),
                            siblings: siblings.try_into().unwrap(),
                            old_clogs: old_clogs.try_into().unwrap(),
                        }
                    })
                    .collect();
                Self {
                    batches: circuit_batches,
                    step_count: Scalar::from(step as u64),
                }
            })
            .collect::<Vec<_>>();

        println!("next tree: {}", tree_str(&new_tree));

        let n_steps = circuits.len();
        (
            circuits,
            (
                prev_tree.root,
                new_tree.root,
                hash_chain,
                Scalar::from(n_steps as u64),
            ),
        )
    }
}

impl<
    Scalar: PrimeField + PrimeFieldBits,
    K: Ord + Hash + Copy + Into<u64> + Sync + Send,
    const HEIGHT: usize,
    const BATCH_SIZE: usize,
> StepCircuit<Scalar> for AggregationCircuit<Scalar, K, HEIGHT, BATCH_SIZE>
{
    fn arity(&self) -> usize {
        4
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let [initial_root, prev_root, hash_chain, step_count] = match z_in {
            [a, b, c, d] => [a, b, c, d],
            _ => panic!("Expected 4 elements"),
        };

        // We create a boolean with the value step_count != 0. To do this, we compute the inverse
        // of step_count (if it exists) and use the value of step_count * step_count_inv. But we
        // also need to ensure that step_count_inv != 0 so that the prover can't make the result 0
        // when step_count != 0.
        let step_count_inv = self.step_count.invert().unwrap_or(Scalar::ONE);
        let step_count_inv_var =
            AllocatedNum::alloc(cs.namespace(|| "step count inverse"), || Ok(step_count_inv))?;
        step_count_inv_var.assert_nonzero(cs.namespace(|| "step count inverse != 0"))?;

        let step_count_invertible = step_count.mul(
            cs.namespace(|| "1 if step_count invertible, else 0"),
            &step_count_inv_var,
        )?;

        cs.enforce(
            || "step_count_invertible is a boolean",
            |lc| lc + step_count_invertible.get_variable(),
            |lc| lc + step_count_invertible.get_variable() - CS::one(),
            |lc| lc,
        );

        // Enforce initial conditions
        cs.enforce(
            || "step_count != 0 OR initial_root == prev_root",
            |lc| lc + prev_root.get_variable() - initial_root.get_variable(),
            |lc| lc + step_count_invertible.get_variable() - CS::one(),
            |lc| lc,
        );

        cs.enforce(
            || "step_count != 0 OR hash_chain == 0",
            |lc| lc + hash_chain.get_variable(),
            |lc| lc + step_count_invertible.get_variable() - CS::one(),
            |lc| lc,
        );

        // Make sure step_count < 2^128
        let unpacked_step_bits: Vec<_> = field_into_allocated_bits_le(
            cs.namespace(|| format!("step count bit decomposition")),
            Some(self.step_count),
        )?
        .iter()
        .map(|bit| Boolean::from(bit.clone()))
        .collect();

        let packed_step_var = pack_bits(
            cs.namespace(|| format!("step count packed, 128 bits")),
            &unpacked_step_bits[..128],
        )?;

        cs.enforce(
            || "step_count < 2^128",
            |lc| lc + packed_step_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + step_count.get_variable(),
        );

        // Process batches
        let mut cur_root = prev_root.clone();
        let mut new_hash_chain = hash_chain.clone();

        for (batch_idx, batch) in self.batches.iter().enumerate() {
            let mut batch_vars = Vec::new();
            for log_idx in 0..BATCH_SIZE {
                let idx = batch.idxs[log_idx];

                let scalar_log = batch.raw_logs[log_idx].to_scalar_log();

                // This creates as many variables as the field size in bits, but we only use some
                // of them. Not sure if the unused ones get eliminated
                let unpacked_bits: Vec<_> = field_into_allocated_bits_le(
                    cs.namespace(|| format!("log {batch_idx}-{log_idx}: bit decomposition")),
                    Some(scalar_log.pack()),
                )?
                .iter()
                .map(|bit| Boolean::from(bit.clone()))
                .collect();

                let packed_log_var = pack_bits(
                    cs.namespace(|| format!("log {batch_idx}-{log_idx}: packed log")),
                    &unpacked_bits,
                )?;

                batch_vars.push(packed_log_var);

                // Extract hop count from bit decomposition
                let (hop_cnt_offset, hop_cnt_sz) = LOG_OFFSETS.hop_cnt;
                let hop_cnt_var = pack_bits(
                    cs.namespace(|| format!("log {batch_idx}-{log_idx}: hop_cnt")),
                    &unpacked_bits[hop_cnt_offset..hop_cnt_offset + hop_cnt_sz],
                )?;

                // Keep track of new/modified flows
                let (old_leaf, new_clog) = match &batch.old_clogs[log_idx] {
                    Some(clog) => {
                        let mut new_clog = clog.clone();
                        new_clog.hop_cnt += scalar_log.hop_cnt;
                        (clog.to_leaf(), new_clog)
                    }
                    None => (
                        vanilla_tree::tree::Leaf::default(),
                        CompressedLog::from_idx_log(idx, &scalar_log),
                    ),
                };

                let index_bits = idx_to_bits(HEIGHT, Scalar::from(idx as u64));

                let index_bits_var = index_bits
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(j, b)| {
                        AllocatedBit::alloc(
                            cs.namespace(|| format!("log {batch_idx}-{log_idx}: index bit {j}")),
                            Some(b),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let siblings_var = batch.siblings[log_idx]
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(j, s)| {
                        AllocatedNum::alloc(
                            cs.namespace(|| format!("log {batch_idx}-{log_idx}: sibling {j}")),
                            || Ok(s),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                // Extract old hop count from bit decomposition
                let old_unpacked_bits: Vec<_> = field_into_allocated_bits_le(
                    cs.namespace(|| {
                        format!("log {batch_idx}-{log_idx}: old clog bit decomposition")
                    }),
                    Some(old_leaf.val[0]),
                )?
                .iter()
                .map(|bit| Boolean::from(bit.clone()))
                .collect();

                let old_packed_clog_var = pack_bits(
                    cs.namespace(|| format!("log {batch_idx}-{log_idx}: old packed clog")),
                    &old_unpacked_bits,
                )?;

                let (hop_cnt_offset, hop_cnt_sz) = CLOG_OFFSETS.hop_cnt;
                let old_hop_cnt_var = pack_bits(
                    cs.namespace(|| format!("log {batch_idx}-{log_idx}: old clog hop_cnt")),
                    &old_unpacked_bits[hop_cnt_offset..hop_cnt_offset + hop_cnt_sz],
                )?;

                // Verify membership of old compressed log
                let old_computed_root_var = path_computed_root::<Scalar, HEIGHT, _>(
                    &mut cs.namespace(|| format!("valid old {batch_idx}-{log_idx}")),
                    vec![old_packed_clog_var.clone()],
                    index_bits_var.clone(),
                    siblings_var.clone(),
                )?;
                cs.enforce(
                    || format!("log {batch_idx}-{log_idx}: current root == old computed root"),
                    |lc| lc + cur_root.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + old_computed_root_var.get_variable(),
                );

                // Extract new hop count from bit decomposition
                let new_unpacked_bits: Vec<_> = field_into_allocated_bits_le(
                    cs.namespace(|| {
                        format!("log {batch_idx}-{log_idx}: new clog bit decomposition")
                    }),
                    Some(new_clog.pack()),
                )?
                .iter()
                .map(|bit| Boolean::from(bit.clone()))
                .collect();

                let (hop_cnt_offset, hop_cnt_sz) = CLOG_OFFSETS.hop_cnt;
                let new_hop_cnt_bits =
                    &new_unpacked_bits[hop_cnt_offset..hop_cnt_offset + hop_cnt_sz];
                let new_hop_cnt_var = pack_bits(
                    cs.namespace(|| format!("log {batch_idx}-{log_idx}: new clog hop_cnt")),
                    new_hop_cnt_bits,
                )?;
                let new_packed_clog_var = pack_bits(
                    cs.namespace(|| format!("log {batch_idx}-{log_idx}: new packed clog")),
                    &new_unpacked_bits,
                )?;

                // Verify that new hop count is related to the old hop count
                cs.enforce(
                    || format!("log {batch_idx}-{log_idx}: enforce new hop_cnt == old hop_cnt + hop_cnt"),
                    |lc| lc + old_hop_cnt_var.get_variable() + hop_cnt_var.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + new_hop_cnt_var.get_variable(),
                );

                // Reconstruct new leaf by updating hop_cnt of old leaf
                let mut recons_unpacked_bits = old_unpacked_bits.clone();
                recons_unpacked_bits[hop_cnt_offset..hop_cnt_offset + hop_cnt_sz]
                    .clone_from_slice(new_hop_cnt_bits);

                let recons_packed_clog_var = pack_bits(
                    cs.namespace(|| {
                        format!("log {batch_idx}-{log_idx}: reconstructed packed clog")
                    }),
                    &recons_unpacked_bits,
                )?;

                // Clog is updated, in which case it should equal the reconstructed Clog, or it's
                // new, in which case the old packed Clog should be 0 (default leaf value)
                cs.enforce(
                    || format!("log {batch_idx}-{log_idx}: leaf is updated or new"),
                    |lc| {
                        lc + new_packed_clog_var.get_variable()
                            - recons_packed_clog_var.get_variable()
                    },
                    |lc| lc + old_packed_clog_var.get_variable(),
                    |lc| lc,
                );

                // Compute root for new compressed log
                let new_computed_root_var = path_computed_root::<Scalar, HEIGHT, _>(
                    &mut cs.namespace(|| format!("log {batch_idx}-{log_idx}: new computed root")),
                    vec![new_packed_clog_var],
                    index_bits_var.clone(),
                    siblings_var.clone(),
                )?;
                // Update current root
                cur_root = new_computed_root_var.clone();
            }

            // Compute hash for this batch of logs
            let log_hash_constants = Sponge::<Scalar, U2>::api_constants(Strength::Standard);
            let hashed_batch = hash_circuit_U2(
                &mut cs.namespace(|| format!("batch {batch_idx} hash")),
                batch_vars,
                &log_hash_constants,
            )?;

            // Update hash chain
            new_hash_chain = hash_circuit_U2(
                &mut cs.namespace(|| format!("hash chain {batch_idx}")),
                vec![new_hash_chain.clone(), hashed_batch],
                &log_hash_constants,
            )?;
        }

        // Update step counter
        let new_step_count = AllocatedNum::alloc(cs.namespace(|| "step counter"), || {
            Ok(self.step_count + Scalar::ONE)
        })?;

        cs.enforce(
            || format!("enforce new step count == old step count + 1"),
            |lc| lc + step_count.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + new_step_count.get_variable(),
        );

        Ok(vec![
            initial_root.clone(),
            cur_root.clone(),
            new_hash_chain,
            new_step_count,
        ])
    }
}

// Code for Consistency Check Circuit (different from aggregation circuit)

/// Convert a 32-byte hash to two field elements (high and low 128 bits each)
pub fn hash_to_field_elements<F: PrimeField>(hash: &[u8; 32]) -> (F, F) {
    let mut hi_val = F::ZERO;
    for (i, &byte) in hash[..16].iter().enumerate() {
        let byte_scalar = F::from(byte as u64);
        let shift = F::from(1u64 << (8 * (i % 8)));
        let big_shift = if i >= 8 {
            let base = F::from(1u64 << 63) * F::from(2u64);
            base
        } else {
            F::ONE
        };
        hi_val += byte_scalar * shift * big_shift;
    }

    let mut lo_val = F::ZERO;
    for (i, &byte) in hash[16..].iter().enumerate() {
        let byte_scalar = F::from(byte as u64);
        let shift = F::from(1u64 << (8 * (i % 8)));
        let big_shift = if i >= 8 {
            let base = F::from(1u64 << 63) * F::from(2u64);
            base
        } else {
            F::ONE
        };
        lo_val += byte_scalar * shift * big_shift;
    }

    (hi_val, lo_val)
}

/// Compute Merkle root in-circuit using the same algorithm as MerkleTree::from_vec.
/// This matches the tree structure used by the aggregation circuit.
pub fn merkle_root_from_leaves_circuit<F, CS, const N: usize>(
    cs: &mut CS,
    leaf_values: Vec<AllocatedNum<F>>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
{
    let leaf_hash_params = Sponge::<F, U1>::api_constants(Strength::Standard);
    let node_hash_params = Sponge::<F, U2>::api_constants(Strength::Standard);

    // Compute empty leaf hash (hash of Scalar::ZERO)
    let empty_leaf_hash = hash_U1(vec![F::ZERO], &leaf_hash_params);

    // Precompute empty hashes for each level
    let mut empty_hashes = vec![empty_leaf_hash];
    for level in 0..N {
        let prev = empty_hashes[level];
        let next = hash_U2(vec![prev, prev], &node_hash_params);
        empty_hashes.push(next);
    }

    // Track left hashes at each level (None = empty, Some = waiting for right)
    let mut left_hashes: Vec<Option<AllocatedNum<F>>> = vec![None; N + 1];

    // Process each leaf
    for (i, leaf_val) in leaf_values.iter().enumerate() {
        // Hash the leaf using zk's circuit hash function
        let mut right_hash = hash_circuit_U1(
            &mut cs.namespace(|| format!("leaf_hash_{}", i)),
            vec![leaf_val.clone()],
            &leaf_hash_params,
        )?;

        // Propagate up the tree while there's a left hash waiting
        let mut level = 0;
        while level < N {
            match left_hashes[level].take() {
                Some(left_hash) => {
                    // Combine left and right hashes
                    right_hash = hash_circuit_U2(
                        &mut cs.namespace(|| format!("node_hash_{}_{}", i, level)),
                        vec![left_hash, right_hash],
                        &node_hash_params,
                    )?;
                    level += 1;
                }
                None => {
                    break;
                }
            }
        }
        left_hashes[level] = Some(right_hash);
    }

    // Fill in remaining levels with empty hashes
    // Allocate empty hash for level 0 (we'll need it for combining)
    let mut right_hash_var =
        AllocatedNum::alloc(cs.namespace(|| "empty_leaf_hash"), || Ok(empty_leaf_hash))?;

    for level in 0..N {
        match left_hashes[level].take() {
            Some(left_hash) => {
                // Combine left_hash with right_hash
                let next_hash = hash_circuit_U2(
                    &mut cs.namespace(|| format!("fill_node_hash_{}", level)),
                    vec![left_hash, right_hash_var.clone()],
                    &node_hash_params,
                )?;

                match &left_hashes[level + 1] {
                    Some(_) => {
                        // There's already something at next level, this becomes new right
                        right_hash_var = next_hash;
                    }
                    None => {
                        // Store at next level, right becomes empty for next level
                        left_hashes[level + 1] = Some(next_hash);
                        right_hash_var = AllocatedNum::alloc(
                            cs.namespace(|| format!("empty_hash_next_{}", level)),
                            || Ok(empty_hashes[level + 1]),
                        )?;
                    }
                }
            }
            None => {
                // No left hash, right becomes empty for next level
                right_hash_var = AllocatedNum::alloc(
                    cs.namespace(|| format!("empty_propagate_{}", level)),
                    || Ok(empty_hashes[level + 1]),
                )?;
            }
        }
    }

    // The root is at left_hashes[N]
    left_hashes[N]
        .take()
        .ok_or(SynthesisError::AssignmentMissing)
}

/// Circuit that proves consistency between a Merkle root and a SHA-256 hash of the underlying vector.
/// Uses SHA-256 hashing to be consistent with query_methods/guest/src/main.rs.
#[derive(Clone, Debug)]
pub struct ConsistencyCircuit<Scalar: PrimeField> {
    /// The serialized CLogs data (as bytes, matching guest serialization)
    pub preimage: Vec<u8>,
    /// Expected SHA-256 hash (32 bytes)
    pub expected_hash: [u8; 32],
    /// Step counter (for Nova's recursive structure)
    pub step: usize,
    _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> ConsistencyCircuit<Scalar> {
    pub fn new(preimage: Vec<u8>, expected_hash: [u8; 32], step: usize) -> Self {
        Self {
            preimage,
            expected_hash,
            step,
            _p: PhantomData,
        }
    }

    /// Convert CLogs to bytes matching query_methods/guest/src/main.rs serialization
    pub fn clogs_to_bytes(clogs: &[core::CLog]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for clog in clogs {
            bytes.extend_from_slice(&clog.id.to_le_bytes());
            bytes.extend_from_slice(&clog.flow_id.to_le_bytes());
            bytes.extend_from_slice(&clog.src.to_le_bytes());
            bytes.extend_from_slice(&clog.dst.to_le_bytes());
            bytes.extend_from_slice(&clog.packet_size.to_le_bytes());
            bytes.extend_from_slice(&clog.hop_cnt.to_le_bytes());
        }
        bytes
    }

    pub fn hash_clogs(clogs: &[core::CLog]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let bytes = Self::clogs_to_bytes(clogs);
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> StepCircuit<Scalar> for ConsistencyCircuit<Scalar> {
    fn arity(&self) -> usize {
        // State: [merkle_root, hash_hi, hash_lo, step_count]
        4
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        use nova_snark::frontend::gadgets::sha256::sha256;

        let [merkle_root, hash_hi, hash_lo, step_count] = match z_in {
            [a, b, c, d] => [a, b, c, d],
            _ => panic!("Expected 4 elements in state"),
        };

        // 1. Allocate preimage bits (MSB-first within each byte, as SHA-256 expects)
        let mut preimage_bits: Vec<Boolean> = Vec::with_capacity(self.preimage.len() * 8);
        for (byte_idx, &byte) in self.preimage.iter().enumerate() {
            for i in (0..8).rev() {
                let bit_value = (byte >> i) & 1 == 1;
                let bit = AllocatedBit::alloc(
                    cs.namespace(|| format!("preimage_bit_{}_{}", byte_idx, i)),
                    Some(bit_value),
                )?;
                preimage_bits.push(Boolean::from(bit));
            }
        }

        // 2. Compute SHA-256 in-circuit
        let hash_bits = sha256(cs.namespace(|| "sha256"), &preimage_bits)?;

        // 3. Verify hash_bits match expected hash (MSB-first in hash output)
        let expected_bits: Vec<bool> = self
            .expected_hash
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .collect();

        for (i, (computed_bit, &expected_bit)) in
            hash_bits.iter().zip(expected_bits.iter()).enumerate()
        {
            let expected_var = AllocatedBit::alloc(
                cs.namespace(|| format!("expected_bit_{}", i)),
                Some(expected_bit),
            )?;

            // Constrain computed_bit == expected_bit
            cs.enforce(
                || format!("hash_bit_{}_matches", i),
                |_| computed_bit.lc(CS::one(), Scalar::ONE),
                |lc| lc + CS::one(),
                |lc| lc + expected_var.get_variable(),
            );
        }

        // 4. Verify that hash_hi and hash_lo encode the expected hash
        // Convert expected hash to field elements and constrain
        let (expected_hi, expected_lo) = hash_to_field_elements(&self.expected_hash);

        let expected_hi_var =
            AllocatedNum::alloc(cs.namespace(|| "expected_hi"), || Ok(expected_hi))?;
        let expected_lo_var =
            AllocatedNum::alloc(cs.namespace(|| "expected_lo"), || Ok(expected_lo))?;

        cs.enforce(
            || "hash_hi matches",
            |lc| lc + hash_hi.get_variable() - expected_hi_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        cs.enforce(
            || "hash_lo matches",
            |lc| lc + hash_lo.get_variable() - expected_lo_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // 5. Pack preimage bits into field elements matching other packing logic.
        const BITS_PER_CLOG: usize = 192; // Each CLog is 192 bits (6 32 bit fields)
        let num_clogs = preimage_bits.len() / BITS_PER_CLOG;

        let mut packed_clogs: Vec<AllocatedNum<Scalar>> = Vec::with_capacity(num_clogs);
        for clog_idx in 0..num_clogs {
            let clog_start = clog_idx * BITS_PER_CLOG;

            // Reorder bits from MSB-first (SHA-256) to LSB-first (everywhere else)
            let mut reordered_bits: Vec<Boolean> = Vec::with_capacity(BITS_PER_CLOG);
            for bit_idx in 0..BITS_PER_CLOG {
                let byte_idx = bit_idx / 8;
                let bit_in_byte = bit_idx % 8; // 0 = LSB needed for pack_bits
                // In preimage_bits (MSB-first), bit 0 of byte is at offset 7
                let preimage_offset = clog_start + byte_idx * 8 + (7 - bit_in_byte);
                reordered_bits.push(preimage_bits[preimage_offset].clone());
            }

            // Pack using the same logic as CompressedLog.pack()
            let packed = pack_bits(
                cs.namespace(|| format!("pack_clog_{}", clog_idx)),
                &reordered_bits,
            )?;
            packed_clogs.push(packed);
        }

        // 6. Recompute Poseidon Merkle Root from packed CLogs
        const HEIGHT: usize = 15;
        let computed_root = merkle_root_from_leaves_circuit::<Scalar, _, HEIGHT>(
            &mut cs.namespace(|| "merkle_root"),
            packed_clogs,
        )?;

        // Constrain computed root == input merkle_root
        cs.enforce(
            || "merkle_root_matches",
            |lc| lc + computed_root.get_variable() - merkle_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // 7. Update step counter
        let new_step_count = AllocatedNum::alloc(cs.namespace(|| "new_step_count"), || {
            Ok(Scalar::from((self.step + 1) as u64))
        })?;

        cs.enforce(
            || "step_count increments",
            |lc| lc + step_count.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + new_step_count.get_variable(),
        );

        Ok(vec![
            merkle_root.clone(),
            hash_hi.clone(),
            hash_lo.clone(),
            new_step_count,
        ])
    }
}
