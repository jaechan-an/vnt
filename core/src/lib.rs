use serde::{Deserialize, Serialize};

use std::{collections::HashMap, hash::Hasher};

pub mod log;
pub mod merkle;
pub mod util;

#[cfg(any(feature = "host", feature = "simulator"))]
pub mod postgres;

#[derive(Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: i32,
    pub ip: String,
    pub port: i32,
}

impl Node {
    pub fn new(id: i32, ip: String, port: i32) -> Self {
        Node {
            id: id,
            ip: ip,
            port: port,
        }
    }

    pub fn to_string(&self) -> String {
        format!("id: {}, ip: {}, port: {}", self.id, self.ip, self.port)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Route {
    pub id: i32,
    pub src: i32,
    pub dst: i32,
    pub next: i32,
    pub cost: i32,
}

impl Route {
    pub fn new(id: i32, src: i32, dst: i32, next: i32, cost: i32) -> Self {
        Route {
            id: id,
            src: src,
            dst: dst,
            next: next,
            cost: cost,
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "id: {}, src: {}, dst: {}, next: {}, cost: {}",
            self.id, self.src, self.dst, self.next, self.cost
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Flow {
    pub id: i32,
    pub src: i32,
    pub dst: i32,
    pub is_done: bool,
}

impl Flow {
    pub fn new(id: i32, src: i32, dst: i32, is_done: bool) -> Self {
        Flow {
            id: id,
            src: src,
            dst: dst,
            is_done: is_done,
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "id: {}, src: {}, dst: {}, is_done: {}",
            self.id, self.src, self.dst, self.is_done
        )
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Log {
    pub id: i32,
    pub flow_id: i32,
    pub src: i32,
    pub dst: i32,
    pub pred: i32,
    pub packet_size: i32,
    pub hop_cnt: i32,
}

impl Log {
    pub fn new(
        id: i32,
        flow_id: i32,
        src: i32,
        dst: i32,
        pred: i32,
        packet_size: i32,
        hop_cnt: i32,
    ) -> Self {
        Log {
            id: id,
            flow_id: flow_id,
            src: src,
            dst: dst,
            pred: pred,
            packet_size: packet_size,
            hop_cnt: hop_cnt,
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.id, self.flow_id, self.src, self.dst, self.pred, self.packet_size, self.hop_cnt
        )
    }

    pub fn equals(&self, log: &Log) -> bool {
        self.flow_id == log.flow_id
            && self.src == log.src
            && self.dst == log.dst
            && self.pred == log.pred
            && self.packet_size == log.packet_size
            && self.hop_cnt == log.hop_cnt
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct CLog {
    pub id: i32,
    pub user_id: i32,
    pub hash_chain: Vec<u8>,
}

impl CLog {
    pub fn new(id: i32, user_id: i32, hash_chain: Vec<u8>) -> Self {
        CLog {
            id,
            user_id,
            hash_chain,
        }
    }

    pub fn equals(&self, clog: &CLog) -> bool {
        self.user_id == clog.user_id && self.hash_chain == clog.hash_chain
    }

    pub fn to_string(&self) -> String {
        format!(
            "id: {}, user_id: {}, hash_chain: {:?}",
            self.id, self.user_id, self.hash_chain
        )
    }
}

impl merkle_light::hash::Hashable<crate::merkle::ShaHasher> for CLog {
    fn hash(&self, state: &mut crate::merkle::ShaHasher) {
        let serialized =
            bincode::serialize(self).expect("failed to serialize CLog for Merkle hashing");
        state.write(&serialized);
    }
}

/// Private input values.
#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateInput {
    /**
     * Public inputs
     */
    pub src_ip: String,

    pub dst_ip: String,

    /**
     * Private inputs
     */
    pub routes: Vec<Route>,
    pub all_routes: Vec<Route>,
    // pub routing_proof: Vec<u8>,

    // pub node_logs: Vec<Vec<Log>>,

    // pub node_trees: Vec<MerkleTree<Sha256>>,
    // pub node_proofs: Vec<Vec<u8>>,
}

/// Public journal values that will be committed by the metric compute method.
#[derive(Debug, Serialize, Deserialize)]
pub struct Journal {
    pub route_proof: Vec<u8>,
    pub route_root: [u8; 32],
    pub route_indices: Vec<usize>,
    pub route_hashes: Vec<[u8; 32]>,
    pub all_route_len: usize,
    pub latency: i32,
}

/// Private Inputs for Aggregation
#[derive(Debug, Serialize, Deserialize)]
pub struct AggregationPrivateInput {
    /*
     * All logs from each nodes. Used to calculate the hash value and check
     * if it's the same with the existing one.
     */
    pub logs: Vec<Vec<Log>>,

    /*
     * All hashes for logs table. This is used to check if the logs are authentic.
     */
    pub hashes: Vec<[u8; 32]>,

    /*
     * New logs since last aggregation round. Used to update the Merkle tree.
     */
    pub new_logs: Vec<Vec<Log>>,

    pub update_clogs: HashMap<i32 /* flow_id */, CLog>, // UPDATE CLogs with additional hop_count
    pub insert_clogs: HashMap<i32 /* flow_id */, CLog>, // INSERT new CLogs

    pub old_clogs: HashMap<i32 /* flow_id */, CLog>,
    pub new_clogs: HashMap<i32 /* flow_id */, CLog>,

    /*
     * Merkle tree from the previous round.
     */
    pub tree: Vec<u8>,
}

/// Public journal values that will be committed by the metric compute method.
#[derive(Debug, Serialize, Deserialize)]
pub struct AggregationJournal {
    pub success: bool,
    pub tree: Vec<u8>,
    pub root: [u8; 32],
    pub message: String,
}

/// Private Inputs for Query
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryPrivateInput {
    /// All clogs. Queries are computed over this vector.
    pub clogs: Vec<CLog>,

    /// The previously calculated root of the Merkle Tree.
    pub cur_root: [u8; 32],

    /// User id for the query.
    pub user_id: i32,
}

/// Public journal values that will be committed by the metric compute method.
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryJournal {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NovaAggregationProof<ScalarRepr: AsRef<[u8]>, CompressedSNARK, VerifierKey> {
    pub pub_prev_root: ScalarRepr,
    pub pub_cur_root: ScalarRepr,
    pub pub_hash_chain: ScalarRepr,
    pub pub_n_steps: ScalarRepr,
    pub n_steps: usize, // Included for convenience since converting from Scalar to usize is annoying
    pub verifier_key: VerifierKey,
    pub compressed_snark: CompressedSNARK,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NovaConsistencyProof<ScalarRepr: AsRef<[u8]>, CompressedSNARK, VerifierKey> {
    /// Merkle root from the aggregation proof
    pub pub_merkle_root: ScalarRepr,
    /// High 128 bits of SHA-256 hash encoded as field element
    pub pub_hash_hi: ScalarRepr,
    /// Low 128 bits of SHA-256 hash encoded as field element
    pub pub_hash_lo: ScalarRepr,
    /// SHA-256 hash of the CLogs (for reference/verification)
    pub clogs_hash: [u8; 32],
    pub verifier_key: VerifierKey,
    pub compressed_snark: CompressedSNARK,
}
