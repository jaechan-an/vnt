#![allow(non_snake_case)]
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::{
    frontend::{
        AllocatedBit, Boolean, ConstraintSystem, Elt, PoseidonConstants, SpongeCircuit,
        SynthesisError,
        gadgets::poseidon::{
            IOPattern, Simplex, Sponge, SpongeAPI, SpongeOp, SpongeTrait, Strength,
        },
        num::{AllocatedNum, Num},
    },
    gadgets::utils::le_bits_to_num,
};
use std::marker::PhantomData;

pub use generic_array::typenum::{U1, U2};
pub use merkle_trees::vanilla_tree;
pub use merkle_trees::vanilla_tree::tree::{Leaf, MerkleTree, idx_to_bits};

use serde::{Deserialize, Serialize};
use std::cmp::Ord;
use std::collections::HashMap;
use std::fmt::Debug;
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

fn scalar_to_u64<Scalar: PrimeField + PrimeFieldBits>(n: Scalar) -> u64 {
    let bits: Vec<bool> = n.to_le_bits().into_iter().collect();
    bits[0..64]
        .iter()
        .rev()
        .fold(0u64, |acc, x| acc * 2 + (*x as u64))
}

fn allocated_n_bits_le<Scalar: PrimeField + PrimeFieldBits, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: Scalar,
    n_bits: usize,
) -> Result<Vec<AllocatedBit>, SynthesisError> {
    value
        .to_le_bits()
        .into_iter()
        .enumerate()
        .take(n_bits)
        .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), Some(b)))
        .collect()
}

#[derive(Clone, Debug)]
pub struct Log<T> {
    pub id: T,
    pub user_id: T,
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
    user_id: (ENTRY_SIZE * 1, ENTRY_SIZE),
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
            &self.user_id,
            &self.src,
            &self.dst,
            &self.pred,
            &self.packet_size,
            &self.hop_cnt,
        ]
    }
}

impl<T: Copy + Into<u64>> Log<T> {
    pub fn to_scalar_log<Scalar: PrimeField + PrimeFieldBits>(&self) -> Log<Scalar> {
        Log {
            id: Scalar::from(self.id.into()),
            user_id: Scalar::from(self.user_id.into()),
            src: Scalar::from(self.src.into()),
            dst: Scalar::from(self.dst.into()),
            pred: Scalar::from(self.pred.into()),
            packet_size: Scalar::from(self.packet_size.into()),
            hop_cnt: Scalar::from(self.hop_cnt.into()),
        }
    }
}

// Update compressed_logs with the raw log as input.
pub fn update_clogs<
    const HEIGHT: usize,
    T: Ord + Hash + Copy + Into<u64> + Sync + Send,
    Scalar: PrimeField + PrimeFieldBits,
>(
    tree: &mut MerkleTree<Scalar, HEIGHT, U1, U2>,
    compressed_logs: &mut HashMap<u64, CompressedLog<Scalar>>,
    raw_log: &Log<T>,
) -> Update<Scalar, T> {
    let scalar_log = raw_log.to_scalar_log::<Scalar>();
    let len = compressed_logs.len();

    let hash_params = Sponge::<Scalar, U2>::api_constants(Strength::Standard);
    let (old_clog, to_insert) = match compressed_logs.get(&raw_log.user_id.into()) {
        Some(old_clog) => {
            let old_clog = old_clog.clone();
            let mut clog = old_clog.clone();

            // Update clog hash chain
            clog.hash_chain = hash_U2(vec![clog.hash_chain, scalar_log.pack()], &hash_params);

            (old_clog.clone(), clog)
        }
        None => (
            CompressedLog::zero(len),
            CompressedLog::from_idx_log(len, &scalar_log),
        ),
    };

    // update tree
    let clog_update = ClogUpdate::do_update(tree, old_clog, to_insert.clone());
    compressed_logs.insert(raw_log.user_id.into(), to_insert.clone());

    Update {
        raw_log: raw_log.clone(),
        clog_update,
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> Log<Scalar> {
    pub fn pack(&self) -> Scalar {
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
    pub user_id: Scalar,
    pub hash_chain: Scalar,
}

const CLOG_OFFSETS: CompressedLog<(usize, usize)> = CompressedLog {
    // Each CompressedLog field takes up 32 bits in the resulting Scalar.
    merkle_idx: 0,
    user_id: (ENTRY_SIZE * 0, ENTRY_SIZE),
    hash_chain: (0, 0),
};

impl<T> CompressedLog<T> {
    fn fields(&self) -> Vec<&T> {
        // List of all fields that are hashed
        vec![&self.user_id]
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> CompressedLog<Scalar> {
    pub fn to_leaf(&self) -> Leaf<Scalar, U1> {
        Leaf {
            val: self.pack(),
            _arity: PhantomData::<U1>,
        }
    }

    fn from_idx_log(merkle_idx: usize, log: &Log<Scalar>) -> Self {
        let hash_params = Sponge::<Scalar, U2>::api_constants(Strength::Standard);
        Self {
            merkle_idx,
            user_id: log.user_id,
            hash_chain: hash_U2(vec![Scalar::ZERO, log.pack()], &hash_params),
        }
    }

    fn pack(&self) -> Vec<Scalar> {
        // Combine fields into a leaf value.
        let mut packed = Scalar::ZERO;
        let TWO = Scalar::from(2);
        for (field, (offset, _nbits)) in zip(self.fields(), CLOG_OFFSETS.fields()) {
            packed += *field * TWO.pow(std::slice::from_ref(&(*offset as u64)));
        }
        vec![packed, self.hash_chain]
    }

    pub fn to_repr(&self) -> CompressedLog<Scalar::Repr> {
        CompressedLog {
            merkle_idx: self.merkle_idx,
            user_id: self.user_id.to_repr(),
            hash_chain: self.hash_chain.to_repr(),
        }
    }

    pub fn from_repr(repr: &CompressedLog<Scalar::Repr>) -> Self {
        CompressedLog {
            merkle_idx: repr.merkle_idx,
            user_id: Scalar::from_repr(repr.user_id).unwrap(),
            hash_chain: Scalar::from_repr(repr.hash_chain).unwrap(),
        }
    }

    pub fn zero(idx: usize) -> Self {
        Self {
            merkle_idx: idx,
            user_id: Scalar::ZERO,
            hash_chain: Scalar::ZERO,
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
            let val: &Vec<Scalar> = &tree
                .leaf_hash_db
                .get(&format!("{:?}", leaf_hash))
                .unwrap()
                .val;
            let bits: Vec<bool> = val[0].to_le_bits().into_iter().collect();
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
            elements.push(format!("{:?}, {:?}", fields, val[1]));
        }
    }
    if empty_streak != 0 {
        elements.push(format!("<empty> x {}", empty_streak));
    }
    elements.join(", ")
}

#[derive(Clone, Debug)]
pub struct ClogUpdate<Scalar: PrimeField + PrimeFieldBits> {
    pub idx: usize,                      // Index in merkle tree
    pub siblings: Vec<Scalar>,           // Siblings that verify clog
    pub old_clog: CompressedLog<Scalar>, // Old compressed log
    pub new_clog: CompressedLog<Scalar>, // New compressed log
}

impl<Scalar: PrimeField + PrimeFieldBits> ClogUpdate<Scalar> {
    pub fn noop<const HEIGHT: usize>(tree: &MerkleTree<Scalar, HEIGHT, U1, U2>) -> Self {
        let last_idx = (1 << HEIGHT) - 1;
        let zero_clog = CompressedLog {
            merkle_idx: last_idx,
            user_id: Scalar::ZERO,
            hash_chain: Scalar::ZERO,
        };
        let idx_bits = idx_to_bits(HEIGHT, Scalar::from(last_idx as u64));
        let siblings_path = tree.get_siblings_path(idx_bits);
        ClogUpdate {
            idx: last_idx,
            siblings: siblings_path.siblings,
            old_clog: zero_clog.clone(),
            new_clog: zero_clog.clone(),
        }
    }

    pub fn do_update<const HEIGHT: usize>(
        tree: &mut MerkleTree<Scalar, HEIGHT, U1, U2>,
        old_clog: CompressedLog<Scalar>,
        new_clog: CompressedLog<Scalar>,
    ) -> Self {
        let idx = new_clog.merkle_idx;
        let idx_bits = idx_to_bits(HEIGHT, Scalar::from(idx as u64));
        let siblings_path = tree.get_siblings_path(idx_bits.clone());
        tree.insert(idx_bits, &new_clog.to_leaf());
        ClogUpdate {
            idx,
            siblings: siblings_path.siblings,
            old_clog,
            new_clog,
        }
    }

    // Helper function for processing merkle tree update
    // Returns (index_bits, old_packed, new_packed, old_hash_chain, new_hash_chain, new_root)
    pub fn merkle_tree_update_circuit<const HEIGHT: usize, CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        cur_root: AllocatedNum<Scalar>,
    ) -> Result<
        (
            Vec<AllocatedBit>,
            AllocatedNum<Scalar>,
            AllocatedNum<Scalar>,
            AllocatedNum<Scalar>,
            AllocatedNum<Scalar>,
            AllocatedNum<Scalar>,
        ),
        SynthesisError,
    > {
        // Get index and siblings
        let index_bits = idx_to_bits(HEIGHT, Scalar::from(self.idx as u64));

        let index_bits_var = index_bits
            .clone()
            .into_iter()
            .enumerate()
            .map(|(j, b)| AllocatedBit::alloc(cs.namespace(|| format!("index bit {j}")), Some(b)))
            .collect::<Result<Vec<_>, _>>()?;

        let siblings_var = self
            .siblings
            .clone()
            .into_iter()
            .enumerate()
            .map(|(j, s)| AllocatedNum::alloc(cs.namespace(|| format!("sibling {j}")), || Ok(s)))
            .collect::<Result<Vec<_>, _>>()?;

        // Compute root for old_clog
        let old_packed = self.old_clog.pack();
        let old_packed_var =
            AllocatedNum::alloc(cs.namespace(|| format!("old clog packed 0")), || {
                Ok(old_packed[0])
            })?;
        let old_hash_chain_var =
            AllocatedNum::alloc(cs.namespace(|| format!("old clog hash chain")), || {
                Ok(old_packed[1])
            })?;

        let old_computed_root_var = path_computed_root::<Scalar, HEIGHT, _>(
            &mut cs.namespace(|| "valid old"),
            vec![old_packed_var.clone(), old_hash_chain_var.clone()],
            index_bits_var.clone(),
            siblings_var.clone(),
        )?;

        // Verify membership of old_clog
        enforce_checked(
            &mut cs,
            format!("Verify old root"),
            vec![Var::Plus(&cur_root)],
            vec![Var::PlusOne],
            vec![Var::Plus(&old_computed_root_var)],
        );

        // Compute root for new_clog
        let new_packed = self.new_clog.pack();
        let new_packed_var =
            AllocatedNum::alloc(cs.namespace(|| format!("new clog packed 0")), || {
                Ok(new_packed[0])
            })?;
        let new_hash_chain_var =
            AllocatedNum::alloc(cs.namespace(|| format!("new clog hash chain")), || {
                Ok(new_packed[1])
            })?;
        let new_computed_root_var = path_computed_root::<Scalar, HEIGHT, _>(
            &mut cs.namespace(|| "valid new"),
            vec![new_packed_var.clone(), new_hash_chain_var.clone()],
            index_bits_var.clone(),
            siblings_var.clone(),
        )?;
        Ok((
            index_bits_var,
            old_packed_var,
            new_packed_var,
            old_hash_chain_var,
            new_hash_chain_var,
            new_computed_root_var,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct Update<
    Scalar: PrimeField + PrimeFieldBits,
    K: Ord + Hash + Copy + Into<u64> + Sync + Send,
> {
    pub raw_log: Log<K>,                 // Single raw log from router
    pub clog_update: ClogUpdate<Scalar>, // Update info for clog
}

#[derive(Clone, Debug)]
pub struct AggregationCircuit<
    Scalar: PrimeField + PrimeFieldBits,
    K: Ord + Hash + Copy + Into<u64> + Sync + Send,
    const HEIGHT: usize,
    const BATCH_SIZE: usize,
> {
    pub batches: Vec<[Update<Scalar, K>; BATCH_SIZE]>,
    pub step_count: Scalar,
}

impl<
    Scalar: PrimeField + PrimeFieldBits,
    K: Ord + Hash + Copy + Into<u64> + Sync + Send + Debug,
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
        // Index 0 is reserved
        let zero_clog = CompressedLog {
            merkle_idx: 0,
            user_id: Scalar::ZERO,
            hash_chain: Scalar::ZERO,
        };

        // Create vector of leaves
        let mut merkle_leaves: Vec<Option<_>> = vec![Some(zero_clog.clone())];
        merkle_leaves.resize(old_compressed_logs.len() + 1, None);
        for clog in old_compressed_logs.values() {
            merkle_leaves[clog.merkle_idx] = Some(clog.clone());
        }

        let merkle_leaves: Vec<_> = merkle_leaves
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .unwrap();

        let mut compressed_logs: HashMap<u64, CompressedLog<Scalar>> = HashMap::new();

        // Compress existing logs
        for clog in merkle_leaves.iter() {
            compressed_logs.insert(scalar_to_u64(clog.user_id), clog.clone());
        }

        let merkle_leaves: Vec<_> = merkle_leaves.iter().map(|clog| clog.to_leaf()).collect();

        let prev_tree: MerkleTree<Scalar, HEIGHT, U1, U2> =
            MerkleTree::from_vec(merkle_leaves.clone(), vanilla_tree::tree::Leaf::default());

        println!("prev tree: {}", tree_str(&prev_tree));

        let mut new_tree = prev_tree.clone();

        let log_hash_constants = Sponge::<Scalar, U2>::api_constants(Strength::Standard);
        let mut hash_chain = Scalar::ZERO;

        // Create circuits
        let mut circuits: Vec<AggregationCircuit<_, _, _, _>> = Vec::new();
        for (step, batches) in step_logs_iter.enumerate() {
            let mut circuit_batches: Vec<[Update<Scalar, K>; BATCH_SIZE]> = Vec::new();
            for batch in batches {
                let mut scalar_logs: Vec<Scalar> = Vec::new();
                let mut update_batch: Vec<Update<Scalar, K>> = Vec::new();

                for log in batch {
                    let scalar_log = log.to_scalar_log();
                    let packed_log = scalar_log.pack();
                    scalar_logs.push(packed_log);
                    let update = if packed_log != Scalar::ZERO {
                        update_clogs(&mut new_tree, &mut compressed_logs, &log)
                    } else {
                        // Log is empty
                        Update {
                            raw_log: log.clone(),
                            clog_update: ClogUpdate::noop(&new_tree),
                        }
                    };
                    update_batch.push(update);
                }

                // Compute batch hash and update hash chain
                let batch_hash = hash_U2(scalar_logs, &log_hash_constants);
                hash_chain = hash_U2(vec![hash_chain, batch_hash], &log_hash_constants);

                circuit_batches.push(update_batch.try_into().unwrap());
            }
            circuits.push(Self {
                batches: circuit_batches,
                step_count: Scalar::from(step as u64),
            });
        }

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

#[derive(Clone)]
enum Var<'a, Scalar: PrimeField> {
    Plus(&'a AllocatedNum<Scalar>),
    Minus(&'a AllocatedNum<Scalar>),
    PlusOne,
    MinusOne,
}

// Wrapper around cs.enforce() that asserts constraints
fn enforce_checked<AR: Into<String>, Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    annotation: AR,
    a: Vec<Var<Scalar>>,
    b: Vec<Var<Scalar>>,
    c: Vec<Var<Scalar>>,
) {
    let annotation: String = annotation.into();

    // Nova runs synthesize twice, and on the first run all the variables have value None.
    // To handle this we wrap the check in an IIFE returning a Result, which is then discarded.
    let _ = || -> Result<(), ()> {
        let accumulate_value = |variables: &Vec<Var<Scalar>>| {
            variables.iter().fold(Ok(Scalar::ZERO), |acc, x| {
                Ok(match x {
                    Var::Plus(var) => acc? + var.get_value().ok_or(())?,
                    Var::Minus(var) => acc? - var.get_value().ok_or(())?,
                    Var::PlusOne => acc? + Scalar::ONE,
                    Var::MinusOne => acc? - Scalar::ONE,
                })
            })
        };

        let a_value = accumulate_value(&a)?;
        let b_value = accumulate_value(&b)?;
        let c_value = accumulate_value(&c)?;
        assert!(
            a_value * b_value == c_value,
            "constraint '{}' failed: {:?} * {:?} != {:?}",
            annotation.clone(),
            a_value,
            b_value,
            c_value
        );
        Ok(())
    }();

    let accumulate_lincomb = |lc, variables: &Vec<Var<Scalar>>| {
        variables.iter().fold(lc, |lc, x| match x {
            Var::Plus(var) => lc + var.get_variable(),
            Var::Minus(var) => lc - var.get_variable(),
            Var::PlusOne => lc + CS::one(),
            Var::MinusOne => lc - CS::one(),
        })
    };

    cs.enforce(
        || annotation,
        |lc| accumulate_lincomb(lc, &a),
        |lc| accumulate_lincomb(lc, &b),
        |lc| accumulate_lincomb(lc, &c),
    );
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

        enforce_checked(
            cs,
            "step_count_invertible is a boolean",
            vec![Var::Plus(&step_count_invertible)],
            vec![Var::Plus(&step_count_invertible), Var::MinusOne],
            vec![],
        );

        // Enforce initial conditions
        enforce_checked(
            cs,
            "step_count != 0 OR initial_root == prev_root",
            vec![Var::Plus(&prev_root), Var::Minus(&initial_root)],
            vec![Var::Plus(&step_count_invertible), Var::MinusOne],
            vec![],
        );

        enforce_checked(
            cs,
            "step_count != 0 OR hash_chain == 0",
            vec![Var::Plus(&hash_chain)],
            vec![Var::Plus(&step_count_invertible), Var::MinusOne],
            vec![],
        );

        // Make sure step_count < 2^128
        let unpacked_step_bits: Vec<_> = allocated_n_bits_le(
            cs.namespace(|| format!("step count bit decomposition")),
            self.step_count,
            128,
        )?;

        let packed_step_var = le_bits_to_num(
            cs.namespace(|| format!("step count packed, 128 bits")),
            &unpacked_step_bits,
        )?;

        enforce_checked(
            cs,
            "step_count < 2^128",
            vec![Var::Plus(&packed_step_var)],
            vec![Var::PlusOne],
            vec![Var::Plus(&step_count)],
        );

        // Process batches
        let mut cur_root = prev_root.clone();
        let mut new_hash_chain = hash_chain.clone();

        for (batch_idx, batch) in self.batches.iter().enumerate() {
            let mut batch_vars = Vec::new();
            for log_idx in 0..BATCH_SIZE {
                let update = &batch[log_idx];
                let idx_info = format!("log {batch_idx}-{log_idx}");

                // Get packed raw log
                let packed_log_var = AllocatedNum::alloc(cs.namespace(|| "packed log"), || {
                    Ok(update.raw_log.to_scalar_log().pack())
                })?;

                // Keep track of raw logs to compute batch hash
                batch_vars.push(packed_log_var.clone());

                // ------ Enforce all merkle tree updates ------
                // Process update: update clog
                let (
                    _clog_index_bits_var,
                    clog_old_packed_var,
                    clog_new_packed_var,
                    old_hash_chain_var,
                    new_hash_chain_var,
                    new_computed_root_var,
                ) = update.clog_update.merkle_tree_update_circuit::<HEIGHT, _>(
                    cs.namespace(|| format!("{idx_info}: clog_update")),
                    cur_root,
                )?;
                cur_root = new_computed_root_var;

                // ------ Constraints on clog update ------
                // Clog is updated, in which case the old user id equals the new user id, or it's
                // new, in which case the old user id is 0
                enforce_checked(
                    cs,
                    format!("{idx_info}: enforce old user id == new user id"),
                    vec![
                        Var::Plus(&clog_old_packed_var),
                        Var::Minus(&clog_new_packed_var),
                    ],
                    vec![Var::Plus(&clog_old_packed_var)],
                    vec![],
                );

                // Verify that new hash chain is related to the old hash chain
                let hash_constants = Sponge::<Scalar, U2>::api_constants(Strength::Standard);
                let computed_new_hash_chain = hash_circuit_U2(
                    &mut cs.namespace(|| format!("{idx_info}: hash chain update")),
                    vec![old_hash_chain_var, packed_log_var.clone()],
                    &hash_constants,
                )?;

                // Hash chains should match, unless packed_log_var is 0
                enforce_checked(
                    cs,
                    format!("{idx_info}: enforce computed hash chain == new hash chain"),
                    vec![
                        Var::Plus(&computed_new_hash_chain),
                        Var::Minus(&new_hash_chain_var),
                    ],
                    vec![Var::Plus(&packed_log_var)],
                    vec![],
                );
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

        enforce_checked(
            cs,
            format!("enforce new step count == old step count + 1"),
            vec![Var::Plus(&step_count), Var::PlusOne],
            vec![Var::PlusOne],
            vec![Var::Plus(&new_step_count)],
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
            bytes.extend_from_slice(&clog.user_id.to_le_bytes());
            bytes.extend_from_slice(&clog.hash_chain);
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
