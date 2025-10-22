use core::{Log, Route};
use tokio_postgres::Client;
use tracing::debug;

pub async fn get_all_routes(client: &Client) -> Vec<Route> {
    let query = format!("SELECT * FROM routes");
    let rows = client
        .query(query.as_str(), &[])
        .await
        .expect("Wrong routes");

    let mut routes = Vec::new();
    for row in rows {
        let id: i32 = row.get("id");
        let src: i32 = row.get("src");
        let dst: i32 = row.get("dst");
        let next: i32 = row.get("next");
        let cost: i32 = row.get("cost");

        let route = Route::new(id, src, dst, next, cost);

        routes.push(route);
    }

    routes
}

pub async fn get_table_size(client: &Client, curr: i32) -> i64 {
    let query = format!("SELECT COUNT(*) FROM logs_{}", curr);
    let row = client
        .query_one(query.as_str(), &[])
        .await
        .expect("Wrong logs");

    let count: i64 = row.get("count");

    count
}

pub async fn get_logs(client: &Client, curr: i32) -> Vec<Log> {
    let query = format!("SELECT * FROM logs_{}", curr);
    let rows = client.query(query.as_str(), &[]).await.expect("Wrong logs");

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

pub async fn insert_log(
    client: &Client,
    curr: i32,
    flow_id: i32,
    src: i32,
    dst: i32,
    pred: i32,
    packet_size: i32,
    hop_cnt: i32,
) {
    let query = format!(
        "INSERT INTO logs_{} (flow_id, src, dst, pred, packet_size, hop_cnt) VALUES ($1, $2, $3, $4, $5, $6)",
        curr
    );

    let rows_affected = client
        .execute(
            &query,
            &[&flow_id, &src, &dst, &pred, &packet_size, &hop_cnt],
        )
        .await
        .expect("Insertion error in logs");

    assert_eq!(rows_affected, 1, "Expected exactly one row to be updated");

    debug!(
        "Inserted log into logs_{}: flow_id: {}, src: {}, dst: {}, pred: {}, packet_size: {}, hop_cnt: {}",
        curr, flow_id, src, dst, pred, packet_size, hop_cnt
    );
}

pub async fn insert_flow(client: &Client, src: i32, dst: i32) -> i32 {
    let query = "INSERT INTO flows (src, dst) VALUES ($1, $2) RETURNING id";

    let row = client
        .query_one(query, &[&src, &dst])
        .await
        .expect("Insertion error in flows");

    let flow_id: i32 = row.get("id");

    assert!(flow_id > 0, "Error: {}, src: {}, dst: {}", query, src, dst);

    debug!("Inserted flow: id: {}, src: {}, dst: {}", flow_id, src, dst);

    flow_id
}

pub async fn increment_hop_cnt(client: &Client, curr: i32, log_id: i32) {
    let query = format!(
        "UPDATE logs_{} SET hop_cnt = hop_cnt + 1, seq = nextval('log_seq') WHERE id = $1",
        curr
    );

    let rows_affected = client
        .execute(&query, &[&log_id])
        .await
        .expect("UPDATE error in logs");

    assert_eq!(rows_affected, 1, "Expected exactly one row to be updated");

    debug!("Updated log in logs_{}: id: {}", curr, log_id);
}

pub async fn update_flow(client: &Client, flow_id: i32) {
    let query = "UPDATE flows SET is_done = true WHERE id = $1";

    let rows_affected = client
        .execute(query, &[&flow_id])
        .await
        .expect("UPDATE error in flows");

    assert_eq!(rows_affected, 1, "Expected exactly one row to be updated");

    debug!("Updated flow: id: {}, is_done: true", flow_id);
}

pub async fn put_hash(client: &Client, node_id: i32, hash: [u8; 32], round: i32) {
    let query = "INSERT INTO logs_hashes (node_id, hash, round) VALUES ($1, $2, $3)";

    let rows_affected = client
        .execute(query, &[&node_id, &hash.as_ref(), &round])
        .await
        .expect("Insertion error in hashes");

    assert_eq!(rows_affected, 1, "Expected exactly one row to be updated");

    debug!(
        "Inserted/Updated hash for node_id: {}, hash: {:?}",
        node_id, hash
    );
}

pub async fn get_metadata(client: &Client, k: &str) -> i64 {
    let query = "select * from metadata where key = $1";
    let row = client
        .query_one(query, &[&k])
        .await
        .expect("metadata fetch failed");

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
