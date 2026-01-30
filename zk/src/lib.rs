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
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::zip;
use std::ops::Bound;

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

fn first_key_before<'a, K: Ord>(btreeset: &'a BTreeSet<K>, key: &K) -> Option<&'a K> {
    btreeset
        .range((Bound::Unbounded, Bound::Excluded(key)))
        .next_back()
}

fn first_key_after<'a, K: Ord>(btreeset: &'a BTreeSet<K>, key: &K) -> Option<&'a K> {
    btreeset
        .range((Bound::Excluded(key), Bound::Unbounded))
        .next()
}

// Update compressed_logs and priorities with the raw log as input.
pub fn update_clogs<
    const HEIGHT: usize,
    T: Ord + Hash + Copy + Into<u64> + Sync + Send,
    Scalar: PrimeField + PrimeFieldBits,
>(
    tree: &mut MerkleTree<Scalar, HEIGHT, U1, U2>,
    compressed_logs: &mut HashMap<u64, CompressedLog<Scalar>>,
    priorities: &mut BTreeSet<(bool, u64, usize, u64)>,
    raw_log: &Log<T>,
) -> Update<Scalar, T> {
    let scalar_log = raw_log.to_scalar_log::<Scalar>();
    let len = compressed_logs.len();

    let (old_prev_clog_update, old_clog, mut to_insert) =
        match compressed_logs.get(&raw_log.flow_id.into()) {
            Some(old_clog) => {
                let old_clog = old_clog.clone();
                let mut clog = old_clog.clone();

                // Remove log from linked list: old_prev.next = cur.next
                let old_priority = clog.priority_key();
                let prev_priority = first_key_before(priorities, &old_priority).unwrap();
                let (_, _, _, prev_flow_id) = prev_priority;
                let prev = compressed_logs.get_mut(prev_flow_id).unwrap();
                let old_prev = prev.clone();
                prev.next_idx = clog.next_idx.clone();

                // Remove old priority
                assert!(
                    priorities.remove(&old_priority),
                    "old priority did not exist"
                );

                // Update clog hop count
                clog.hop_cnt += scalar_log.hop_cnt;

                (
                    ClogUpdate::do_update(tree, old_prev, prev.clone()),
                    old_clog.clone(),
                    clog,
                )
            }
            None => (
                ClogUpdate::noop(tree),
                CompressedLog::zero(len),
                CompressedLog::from_idx_log(len, &scalar_log),
            ),
        };

    // Insert log into linked list: new_prev.next = cur.idx, cur.next = new_next.idx
    let priority = to_insert.priority_key();
    let priority_after = first_key_after(priorities, &priority).cloned();
    let priority_before = *first_key_before(priorities, &priority).unwrap();

    // update cur.next, update tree
    let (next_idx, next_flow_id) =
        priority_after.map_or((0, 0), |(_, _, idx, flow_id)| (idx as u64, flow_id));
    to_insert.next_idx = next_idx.into();
    let clog_update = ClogUpdate::do_update(tree, old_clog, to_insert.clone());
    compressed_logs.insert(raw_log.flow_id.into(), to_insert.clone());

    // Insert priority
    priorities.insert(priority);

    // update new_prev.next
    let (_, _, _, prev_flow_id) = priority_before;
    let new_prev = compressed_logs.get_mut(&prev_flow_id).unwrap();
    let new_prev_saved = new_prev.clone();
    new_prev.next_idx = (to_insert.merkle_idx as u64).into();

    // update new prev clog in tree
    let new_prev_clog_update = ClogUpdate::do_update(tree, new_prev_saved, new_prev.clone());

    // Get next clog info
    let new_next_clog_info =
        ClogPath::verify(tree, compressed_logs.get(&next_flow_id).unwrap().clone());

    Update {
        raw_log: raw_log.clone(),
        old_prev_clog_update,
        clog_update,
        new_prev_clog_update,
        new_next_clog_info,
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
    pub next_idx: Scalar,
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
    next_idx: (ENTRY_SIZE * 6, ENTRY_SIZE),
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
            &self.next_idx,
        ]
    }
}

impl<Scalar: PrimeField + PrimeFieldBits> CompressedLog<Scalar> {
    fn priority(&self) -> Scalar {
        self.hop_cnt
    }

    fn priority_key(&self) -> (bool, u64, usize, u64) {
        // returns (is_node, priority, merkle_idx, flow_id)
        // "special" is false for the linked list head, true for all clogs
        (
            true,
            scalar_to_u64(self.priority()),
            self.merkle_idx,
            scalar_to_u64(self.flow_id),
        )
    }

    pub fn to_leaf(&self) -> Leaf<Scalar, U1> {
        Leaf {
            val: vec![self.pack()],
            _arity: PhantomData::<U1>,
        }
    }

    fn from_idx_log(merkle_idx: usize, log: &Log<Scalar>) -> Self {
        CompressedLog {
            merkle_idx,
            id: Scalar::from(merkle_idx as u64),
            flow_id: log.flow_id,
            src: log.src,
            dst: log.dst,
            packet_size: log.packet_size,
            hop_cnt: log.hop_cnt,
            next_idx: Scalar::ZERO,
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
            next_idx: self.next_idx.to_repr(),
        }
    }

    pub fn from_repr(repr: &CompressedLog<Scalar::Repr>) -> Self {
        CompressedLog {
            merkle_idx: repr.merkle_idx,
            id: Scalar::from_repr(repr.id).unwrap(),
            flow_id: Scalar::from_repr(repr.flow_id).unwrap(),
            src: Scalar::from_repr(repr.src).unwrap(),
            dst: Scalar::from_repr(repr.dst).unwrap(),
            packet_size: Scalar::from_repr(repr.packet_size).unwrap(),
            hop_cnt: Scalar::from_repr(repr.hop_cnt).unwrap(),
            next_idx: Scalar::from_repr(repr.next_idx).unwrap(),
        }
    }

    pub fn zero(idx: usize) -> Self {
        Self {
            merkle_idx: idx,
            id: Scalar::ZERO,
            flow_id: Scalar::ZERO,
            src: Scalar::ZERO,
            dst: Scalar::ZERO,
            packet_size: Scalar::ZERO,
            hop_cnt: Scalar::ZERO,
            next_idx: Scalar::ZERO,
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
pub struct ClogPath<Scalar: PrimeField + PrimeFieldBits> {
    pub idx: usize,                  // Index in merkle tree
    pub siblings: Vec<Scalar>,       // Siblings that verify clog
    pub clog: CompressedLog<Scalar>, // Old compressed log
}

impl<Scalar: PrimeField + PrimeFieldBits> ClogPath<Scalar> {
    pub fn noop<const HEIGHT: usize>(tree: &MerkleTree<Scalar, HEIGHT, U1, U2>) -> Self {
        let last_idx = (1 << HEIGHT) - 1;
        let zero_clog = CompressedLog {
            merkle_idx: last_idx,
            id: Scalar::ZERO,
            flow_id: Scalar::ZERO,
            src: Scalar::ZERO,
            dst: Scalar::ZERO,
            packet_size: Scalar::ZERO,
            hop_cnt: Scalar::ZERO,
            next_idx: Scalar::ZERO,
        };
        let idx_bits = idx_to_bits(HEIGHT, Scalar::from(last_idx as u64));
        let siblings_path = tree.get_siblings_path(idx_bits);
        ClogPath {
            idx: last_idx,
            siblings: siblings_path.siblings,
            clog: zero_clog.clone(),
        }
    }

    pub fn verify<const HEIGHT: usize>(
        tree: &MerkleTree<Scalar, HEIGHT, U1, U2>,
        clog: CompressedLog<Scalar>,
    ) -> Self {
        let idx = clog.merkle_idx;
        let idx_bits = idx_to_bits(HEIGHT, Scalar::from(idx as u64));
        let siblings_path = tree.get_siblings_path(idx_bits.clone());
        ClogPath {
            idx,
            siblings: siblings_path.siblings,
            clog,
        }
    }
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
            id: Scalar::ZERO,
            flow_id: Scalar::ZERO,
            src: Scalar::ZERO,
            dst: Scalar::ZERO,
            packet_size: Scalar::ZERO,
            hop_cnt: Scalar::ZERO,
            next_idx: Scalar::ZERO,
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
    // Returns (index_bits, old_unpacked, old_packed, new_packed, new_root)
    pub fn merkle_tree_update_circuit<const HEIGHT: usize, CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        cur_root: AllocatedNum<Scalar>,
    ) -> Result<
        (
            Vec<AllocatedBit>,
            Vec<Boolean>,
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
        let old_unpacked_bits: Vec<_> = field_into_allocated_bits_le(
            cs.namespace(|| "old clog bit decomposition"),
            Some(self.old_clog.pack()),
        )?
        .iter()
        .map(|bit| Boolean::from(bit.clone()))
        .collect();
        let old_packed_clog_var =
            pack_bits(cs.namespace(|| "old packed clog"), &old_unpacked_bits)?;

        let old_computed_root_var = path_computed_root::<Scalar, HEIGHT, _>(
            &mut cs.namespace(|| "valid old"),
            vec![old_packed_clog_var.clone()],
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
        let new_packed_clog_var =
            AllocatedNum::alloc(cs.namespace(|| format!("new packed clog")), || {
                Ok(self.new_clog.pack())
            })?;
        let new_computed_root_var = path_computed_root::<Scalar, HEIGHT, _>(
            &mut cs.namespace(|| "valid new"),
            vec![new_packed_clog_var.clone()],
            index_bits_var.clone(),
            siblings_var.clone(),
        )?;
        Ok((
            index_bits_var,
            old_unpacked_bits,
            old_packed_clog_var,
            new_packed_clog_var,
            new_computed_root_var,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct Update<
    Scalar: PrimeField + PrimeFieldBits,
    K: Ord + Hash + Copy + Into<u64> + Sync + Send,
> {
    pub raw_log: Log<K>,                          // Single raw log from router
    pub old_prev_clog_update: ClogUpdate<Scalar>, // Update info for old prev clog
    pub clog_update: ClogUpdate<Scalar>,          // Update info for clog
    pub new_prev_clog_update: ClogUpdate<Scalar>, // Update info for new prev clog
    pub new_next_clog_info: ClogPath<Scalar>,     // Verification info for new next clog
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
        // Index 0 is reserved for linked list head
        let zero_clog = CompressedLog {
            merkle_idx: 0,
            id: Scalar::ZERO,
            flow_id: Scalar::ZERO,
            src: Scalar::ZERO,
            dst: Scalar::ZERO,
            packet_size: Scalar::ZERO,
            hop_cnt: Scalar::ZERO,
            next_idx: Scalar::ZERO,
        };

        // Create vector of leaves, and also insert priorities into a BTreeSet to get sorted order
        let mut merkle_leaves: Vec<Option<_>> = vec![Some(zero_clog.clone())];
        merkle_leaves.resize(old_compressed_logs.len() + 1, None);
        let mut clog_priorities: BTreeSet<(bool, u64, usize, u64)> = BTreeSet::new();
        for clog in old_compressed_logs.values() {
            merkle_leaves[clog.merkle_idx] = Some(clog.clone());
            clog_priorities.insert(clog.priority_key());
        }

        let mut merkle_leaves: Vec<_> = merkle_leaves
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .unwrap();

        let mut compressed_logs: HashMap<u64, CompressedLog<Scalar>> = HashMap::new();

        // Assign next_idx to each old clog
        let mut prev_idx: usize = 0;
        for (_is_node, _priority, merkle_idx, _flow_id) in clog_priorities.iter() {
            merkle_leaves[prev_idx].next_idx = Scalar::from(*merkle_idx as u64);
            prev_idx = *merkle_idx;
        }

        // Compress existing logs
        for clog in merkle_leaves.iter() {
            compressed_logs.insert(scalar_to_u64(clog.flow_id), clog.clone());
        }

        // Insert linked list head
        clog_priorities.insert((false, 0, 0, 0));

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
                        update_clogs(
                            &mut new_tree,
                            &mut compressed_logs,
                            &mut clog_priorities,
                            &log,
                        )
                    } else {
                        // Log is empty
                        Update {
                            raw_log: log.clone(),
                            old_prev_clog_update: ClogUpdate::noop(&new_tree),
                            clog_update: ClogUpdate::noop(&new_tree),
                            new_prev_clog_update: ClogUpdate::noop(&new_tree),
                            new_next_clog_info: ClogPath::noop(&new_tree),
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

                let (next_idx_offset, next_idx_sz) = CLOG_OFFSETS.next_idx;
                let (hop_cnt_offset, hop_cnt_sz) = CLOG_OFFSETS.hop_cnt;

                let (log_hop_cnt_offset, log_hop_cnt_sz) = LOG_OFFSETS.hop_cnt;

                // Extract raw log hop count from bit decomposition
                let unpacked_bits: Vec<_> = field_into_allocated_bits_le(
                    cs.namespace(|| format!("{idx_info}: bit decomposition")),
                    Some(update.raw_log.to_scalar_log().pack()),
                )?
                .iter()
                .map(|bit| Boolean::from(bit.clone()))
                .collect();

                let hop_cnt_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: hop_cnt")),
                    &unpacked_bits[log_hop_cnt_offset..log_hop_cnt_offset + log_hop_cnt_sz],
                )?;

                let packed_log_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: packed log")),
                    &unpacked_bits,
                )?;

                // Keep track of raw logs to compute batch hash
                batch_vars.push(packed_log_var);

                // ------ Enforce all merkle tree updates ------
                // Process update: update old prev
                let (
                    _oldprev_index_bits_var,
                    oldprev_old_unpacked_bits,
                    _oldprev_old_packed_var,
                    oldprev_new_packed_var,
                    new_computed_root_var,
                ) = update
                    .old_prev_clog_update
                    .merkle_tree_update_circuit::<HEIGHT, _>(
                        cs.namespace(|| format!("{idx_info}: old_prev_clog_update")),
                        cur_root,
                    )?;
                // Process update: update clog
                let (
                    clog_index_bits_var,
                    clog_old_unpacked_bits,
                    clog_old_packed_var,
                    clog_new_packed_var,
                    new_computed_root_var,
                ) = update.clog_update.merkle_tree_update_circuit::<HEIGHT, _>(
                    cs.namespace(|| format!("{idx_info}: clog_update")),
                    new_computed_root_var,
                )?;
                // Process update: update new prev
                let (
                    _newprev_index_bits_var,
                    newprev_old_unpacked_bits,
                    _newprev_old_packed_var,
                    newprev_new_packed_var,
                    new_computed_root_var,
                ) = update
                    .new_prev_clog_update
                    .merkle_tree_update_circuit::<HEIGHT, _>(
                        cs.namespace(|| format!("{idx_info}: new_prev_clog_update")),
                        new_computed_root_var,
                    )?;
                cur_root = new_computed_root_var;

                // ------ Linked list constraints for old prev ------

                // Extract old_prev.next
                let oldprev_next_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: packed old_prev.next")),
                    &oldprev_old_unpacked_bits[next_idx_offset..next_idx_offset + next_idx_sz],
                )?;

                // Extract clog index
                let clog_idx_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: clog index")),
                    &clog_index_bits_var
                        .clone()
                        .into_iter()
                        .rev()
                        .map(Boolean::from)
                        .collect::<Vec<_>>(),
                )?;

                // If clog already exists, then oldprev.next == idx. Otherwise old_clog == zero_clog
                enforce_checked(
                    cs,
                    format!("{idx_info}: verify oldprev points to old clog, or clog is new"),
                    vec![Var::Plus(&oldprev_next_var), Var::Minus(&clog_idx_var)],
                    vec![Var::Plus(&clog_old_packed_var)],
                    vec![],
                );

                // Get bit decomposition of new next_idx
                let new_clog_next_idx_bits: Vec<_> = allocated_n_bits_le(
                    cs.namespace(|| "new next_idx bit decomposition"),
                    update.clog_update.new_clog.next_idx,
                    next_idx_sz,
                )?;

                let new_clog_next_idx_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: new clog next_idx")),
                    &new_clog_next_idx_bits
                        .clone()
                        .into_iter()
                        .map(Boolean::from)
                        .collect::<Vec<_>>(),
                )?;

                // Reconstruct oldprev, replacing next_idx with clog.next_idx
                let mut recons_unpacked_bits = oldprev_old_unpacked_bits.clone();
                recons_unpacked_bits[next_idx_offset..next_idx_offset + next_idx_sz]
                    .clone_from_slice(
                        &clog_old_unpacked_bits[next_idx_offset..next_idx_offset + next_idx_sz],
                    );

                let recons_packed_oldprev_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: reconstructed packed oldprev")),
                    &recons_unpacked_bits,
                )?;

                // If clog exists, then recons_oldprev == new_oldprev. Otherwise old_clog == zero_clog
                enforce_checked(
                    cs,
                    format!("{idx_info}: reconstructed oldprev == new oldprev, or clog is new"),
                    vec![
                        Var::Plus(&recons_packed_oldprev_var),
                        Var::Minus(&oldprev_new_packed_var),
                    ],
                    vec![Var::Plus(&clog_old_packed_var)],
                    vec![],
                );

                // ------ Constraints on clog update ------

                // Extract old hop count from bit decomposition. If clog is new, this will be 0
                let old_hop_cnt_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: old clog hop_cnt")),
                    &clog_old_unpacked_bits[hop_cnt_offset..hop_cnt_offset + hop_cnt_sz],
                )?;

                // Get bit decomposition of new clog hop count
                let new_clog_hop_cnt = update.clog_update.new_clog.hop_cnt;
                let new_clog_hop_cnt_bits: Vec<_> = allocated_n_bits_le(
                    cs.namespace(|| "new hop_cnt bit decomposition"),
                    new_clog_hop_cnt,
                    hop_cnt_sz,
                )?
                .into_iter()
                .map(Boolean::from)
                .collect();
                let new_hop_cnt_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: new clog hop_cnt")),
                    &new_clog_hop_cnt_bits,
                )?;

                // Verify that new hop count is related to the old hop count
                enforce_checked(
                    cs,
                    format!("{idx_info}: enforce new hop_cnt == old hop_cnt + hop_cnt"),
                    vec![Var::Plus(&old_hop_cnt_var), Var::Plus(&hop_cnt_var)],
                    vec![Var::PlusOne],
                    vec![Var::Plus(&new_hop_cnt_var)],
                );

                // Reconstruct new leaf by updating hop_cnt and next_idx
                let mut recons_unpacked_bits = clog_old_unpacked_bits.clone();
                recons_unpacked_bits[hop_cnt_offset..hop_cnt_offset + hop_cnt_sz]
                    .clone_from_slice(&new_clog_hop_cnt_bits);
                recons_unpacked_bits[next_idx_offset..next_idx_offset + next_idx_sz]
                    .clone_from_slice(
                        &new_clog_next_idx_bits
                            .clone()
                            .into_iter()
                            .map(Boolean::from)
                            .collect::<Vec<_>>(),
                    );

                let recons_packed_clog_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: reconstructed packed clog")),
                    &recons_unpacked_bits,
                )?;

                // Clog is updated, in which case it should equal the reconstructed Clog, or it's
                // new, in which case the old packed Clog should be 0 (default leaf value)
                enforce_checked(
                    cs,
                    format!("{idx_info}: leaf is updated or new"),
                    vec![
                        Var::Plus(&clog_new_packed_var),
                        Var::Minus(&recons_packed_clog_var),
                    ],
                    vec![Var::Plus(&clog_old_packed_var)],
                    vec![],
                );

                // ------ Linked list constraints for new prev ------

                // Extract new_prev.next
                let newprev_next_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: packed new_prev.next")),
                    &newprev_old_unpacked_bits[next_idx_offset..next_idx_offset + next_idx_sz],
                )?;

                // New clog.next_idx should equal old new_prev.next
                enforce_checked(
                    cs,
                    format!("{idx_info}: new clog.next_idx == old new_prev.next"),
                    vec![Var::Plus(&new_clog_next_idx_var)],
                    vec![Var::PlusOne],
                    vec![Var::Plus(&newprev_next_var)],
                );

                // Reconstruct newprev, replacing next_idx with new clog idx
                let mut clog_index_bits_padded: Vec<_> = clog_index_bits_var
                    .into_iter()
                    .rev()
                    .map(Boolean::from)
                    .collect();
                clog_index_bits_padded.resize(next_idx_sz, Boolean::Constant(false));
                let mut recons_unpacked_bits = newprev_old_unpacked_bits.clone();
                recons_unpacked_bits[next_idx_offset..next_idx_offset + next_idx_sz]
                    .clone_from_slice(&clog_index_bits_padded);

                let recons_packed_newprev_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: reconstructed packed newprev")),
                    &recons_unpacked_bits,
                )?;

                // Reconstructed newprev should equal new newprev, or in the case of a no-op, we
                // check that the new newprev is 0
                enforce_checked(
                    cs,
                    format!("{idx_info}: reconstructed newprev == new newprev OR new newprev == 0"),
                    vec![
                        Var::Plus(&recons_packed_newprev_var),
                        Var::Minus(&newprev_new_packed_var),
                    ],
                    vec![Var::Plus(&newprev_new_packed_var)],
                    vec![],
                );

                // ------ Constraints on priority ordering ------

                // Extract new prev priority
                let new_prev_priority_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: prev priority")),
                    &newprev_old_unpacked_bits[hop_cnt_offset..hop_cnt_offset + hop_cnt_sz],
                )?;

                // Extract cur priority
                let clog_priority_var = new_hop_cnt_var.clone();

                // Check that clog_priority - new_prev_priority >= 0
                let priority_diff_bits: Vec<_> = allocated_n_bits_le(
                    cs.namespace(|| format!("{idx_info}: diff 1")),
                    new_clog_hop_cnt - update.new_prev_clog_update.old_clog.hop_cnt,
                    ENTRY_SIZE,
                )?
                .into_iter()
                .map(Boolean::from)
                .collect();
                let priority_diff_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: packed diff 1")),
                    &priority_diff_bits,
                )?;

                enforce_checked(
                    cs,
                    format!("{idx_info}: new_prev_priority + priority_diff = clog_priority"),
                    vec![
                        Var::Plus(&new_prev_priority_var),
                        Var::Plus(&priority_diff_var),
                    ],
                    vec![Var::PlusOne],
                    vec![Var::Plus(&clog_priority_var)],
                );

                // Verify that next clog exists at location specified by clog.next_idx
                let next_siblings_var = update
                    .new_next_clog_info
                    .siblings
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(j, s)| {
                        AllocatedNum::alloc(
                            cs.namespace(|| format!("{idx_info}: next sibling {j}")),
                            || Ok(s),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                // Compute root for next clog
                let next_unpacked_bits: Vec<_> = field_into_allocated_bits_le(
                    cs.namespace(|| format!("{idx_info}: next clog bit decomposition")),
                    Some(update.new_next_clog_info.clog.pack()),
                )?
                .into_iter()
                .map(Boolean::from)
                .collect();
                let next_packed_clog_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: next packed clog")),
                    &next_unpacked_bits,
                )?;

                let computed_root_var = path_computed_root::<Scalar, HEIGHT, _>(
                    &mut cs.namespace(|| format!("{idx_info}: next computed root")),
                    vec![next_packed_clog_var.clone()],
                    new_clog_next_idx_bits
                        .into_iter()
                        .take(HEIGHT)
                        .rev()
                        .collect::<Vec<_>>(),
                    next_siblings_var.clone(),
                )?;

                enforce_checked(
                    cs,
                    format!("{idx_info}: Verify next clog membership OR next_idx == 0"),
                    vec![Var::Plus(&cur_root), Var::Minus(&computed_root_var)],
                    vec![Var::Plus(&new_clog_next_idx_var)],
                    vec![],
                );

                // Get next clog priority
                let next_priority_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: next priority")),
                    &next_unpacked_bits[hop_cnt_offset..hop_cnt_offset + hop_cnt_sz],
                )?;

                // Check that next_priority - clog_priority >= 0, or clog next_idx is 0
                let priority_diff_bits: Vec<_> = allocated_n_bits_le(
                    cs.namespace(|| format!("{idx_info}: diff 2")),
                    update.new_next_clog_info.clog.hop_cnt - new_clog_hop_cnt,
                    ENTRY_SIZE,
                )?
                .into_iter()
                .map(Boolean::from)
                .collect();
                let priority_diff_var = pack_bits(
                    cs.namespace(|| format!("{idx_info}: packed diff 2")),
                    &priority_diff_bits,
                )?;

                enforce_checked(
                    cs,
                    format!(
                        "{idx_info}: clog_priority + priority_diff = next_priority OR next_idx == 0"
                    ),
                    vec![
                        Var::Plus(&clog_priority_var),
                        Var::Plus(&priority_diff_var),
                        Var::Minus(&next_priority_var),
                    ],
                    vec![Var::Plus(&new_clog_next_idx_var)],
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
