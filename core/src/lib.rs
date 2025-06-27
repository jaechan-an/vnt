use serde::{Deserialize, Serialize};

use std::collections::HashMap;

pub mod log;
pub mod util;

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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CLog {
    pub id: i32,
    pub flow_id: i32,
    pub src: i32,
    pub dst: i32,
    pub packet_size: i32,
    pub hop_cnt: i32,
    pub version: i32,
}

impl CLog {
    pub fn new(
        id: i32,
        flow_id: i32,
        src: i32,
        dst: i32,
        packet_size: i32,
        hop_cnt: i32,
        version: i32,
    ) -> Self {
        CLog {
            id: id,
            flow_id: flow_id,
            src: src,
            dst: dst,
            packet_size: packet_size,
            hop_cnt: hop_cnt,
            version: version,
        }
    }

    pub fn equals(&self, clog: &CLog) -> bool {
        self.flow_id == clog.flow_id
            && self.src == clog.src
            && self.dst == clog.dst
            && self.packet_size == clog.packet_size
            && self.hop_cnt == clog.hop_cnt
    }

    pub fn to_string(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.id, self.flow_id, self.src, self.dst, self.packet_size, self.hop_cnt, self.version
        )
    }

    pub fn from_log(log: &Log) -> Self {
        CLog {
            id: log.id,
            flow_id: log.flow_id,
            src: log.src,
            dst: log.dst,
            packet_size: log.packet_size,
            hop_cnt: log.hop_cnt,
            version: 0,
        }
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

/// Private Inputs for Merger
#[derive(Debug, Serialize, Deserialize)]
pub struct MergerPrivateInput {
    pub all_logs: Vec<Vec<Log>>,
    pub diff: HashMap<i32, CLog>,
    pub clogs: Vec<CLog>,
    // pub routing_proof: Vec<u8>,

    // pub node_logs: Vec<Vec<Log>>,

    // pub node_trees: Vec<MerkleTree<Sha256>>,
    // pub node_proofs: Vec<Vec<u8>>,
}

/// Public journal values that will be committed by the metric compute method.
#[derive(Debug, Serialize, Deserialize)]
pub struct MergerJournal {
    pub success: bool,
    pub root: [u8; 32],
    // pub node_trees: Vec<MerkleTree<Sha256>>,
}
