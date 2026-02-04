use tokio_postgres::{Client, Row};

use core::{CLog, Log};

pub async fn get_logs(client: &Client, node_id: i32) -> Vec<Log> {
    let query = format!("SELECT * FROM logs_{}", node_id);

    let rows = client
        .query(query.as_str(), &[])
        .await
        .expect("Log fetch failed");

    let mut logs: Vec<Log> = Vec::new();
    for row in rows {
        let id: i32 = row.get("id");
        let flow_id: i32 = row.get("flow_id");
        let src: i32 = row.get("src");
        let dst: i32 = row.get("dst");
        let pred: i32 = row.get("pred");
        let packet_size: i32 = row.get("packet_size");
        let hop_cnt: i32 = row.get("hop_cnt");

        let log = Log::new(id, flow_id, src, dst, pred, packet_size, hop_cnt);

        logs.push(log);
    }

    logs
}

pub async fn get_metadata(client: &Client, k: &str) -> i64 {
    let query = "select * from metadata where key = $1";
    let row = client
        .query_one(query, &[&k])
        .await
        .expect("watermark fetch failed");

    let key: &str = row.get("key");
    let value: i64 = row.get("value");

    assert_eq!(key, k, "fetched key different");

    value
}

pub async fn put_metadata(client: &Client, k: &str, v: i64) {
    let query = "INSERT INTO metadata (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2";
    // let query = "UPDATE metadata SET value = $1 WHERE key = $2";

    let rows_affected = client
        .execute(query, &[&k, &v])
        .await
        .expect("UPSERT metadata");

    assert_eq!(rows_affected, 1, "Expected exactly one row to be updated");
}

pub async fn get_curr_seq(client: &Client) -> i64 {
    let query = "SELECT last_value FROM log_seq";
    let row = client
        .query_one(query, &[])
        .await
        .expect("log_seq fetch failed");

    let value: i64 = row.get("last_value");

    value
}

pub async fn get_new_logs(client: &Client, num_tables: &i32, prev_seq: &i64) -> Vec<Vec<Log>> {
    let mut new_logs: Vec<Vec<Log>> = Vec::new();

    for node_id in 0..*num_tables {
        let logs: Vec<Log> = get_table_new_logs(&client, &node_id, prev_seq).await;

        new_logs.push(logs);
    }

    new_logs
}

async fn get_table_new_logs(client: &Client, node_id: &i32, prev_seq: &i64) -> Vec<Log> {
    let query = format!("SELECT * FROM logs_{} WHERE seq > $1", node_id);
    let rows = client
        .query(query.as_str(), &[prev_seq])
        .await
        .expect("Log fetch failed");

    let mut logs = Vec::new();
    for row in rows {
        let id: i32 = row.get("id");
        let flow_id: i32 = row.get("flow_id");
        let src: i32 = row.get("src");
        let dst: i32 = row.get("dst");
        let pred: i32 = row.get("pred");
        let packet_size: i32 = row.get("packet_size");
        let hop_cnt: i32 = row.get("hop_cnt");

        let log = Log::new(id, flow_id, src, dst, pred, packet_size, hop_cnt);

        logs.push(log);
    }

    logs
}

pub async fn get_clogs(client: &Client) -> Vec<CLog> {
    let query = format!("SELECT * FROM clogs");
    let rows = client
        .query(query.as_str(), &[])
        .await
        .expect("CLog fetch failed");

    let mut clogs = Vec::new();
    for row in rows {
        clogs.push(row_to_clog(&row));
    }

    clogs
}

pub async fn update_aggregate_clog(client: &Client, clog: &CLog) -> i32 {
    let query = "UPDATE clogs SET hash_chain = $1 WHERE user_id = $2 RETURNING id";

    let rows = client
        .query_one(query, &[&clog.hash_chain, &clog.user_id])
        .await
        .expect("UPDATE error in clog");

    let updated_id: i32 = rows.get(0);
    updated_id
}

pub async fn insert_clog(client: &Client, clog: &CLog) -> i32 {
    let query = "INSERT INTO clogs (user_id, hash_chain)
        VALUES ($1, $2) RETURNING id";

    let row = client
        .query_one(query, &[&clog.user_id, &clog.hash_chain])
        .await
        .expect("INSERT error in clog");

    let inserted_id: i32 = row.get(0);
    inserted_id
}

pub async fn get_hash(client: &Client, node_id: i32, round: i32) -> [u8; 32] {
    let query = "SELECT * FROM logs_hashes WHERE node_id = $1 AND round = $2";
    let row = client
        .query_one(query, &[&node_id, &round])
        .await
        .expect("logs_hashes fetch failed");

    //let id: i32 = row.get("id");
    //let node_id: i32 = row.get("node_id");
    let bytes: &[u8] = row.get("hash");
    let hash: &[u8; 32] = bytes.try_into().expect("Hash conversion failed");
    //let round: i32 = row.get("round");

    *hash
}

// TODO: move to core module
fn row_to_clog(row: &Row) -> CLog {
    let id: i32 = row.get("id");
    let user_id: i32 = row.get("user_id");
    let hash_chain: Vec<u8> = row.get("hash_chain");

    CLog::new(id, user_id, hash_chain)
}
