use tokio_postgres::{Client, Row};

use core::CLog;

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

// TODO: move to core module
fn row_to_clog(row: &Row) -> CLog {
    let id: i32 = row.get("id");
    let flow_id: i32 = row.get("flow_id");
    let src: i32 = row.get("src");
    let dst: i32 = row.get("dst");
    let packet_size: i32 = row.get("packet_size");
    let hop_cnt: i32 = row.get("hop_cnt");
    let version: i32 = row.get("version");

    CLog::new(id, flow_id, src, dst, packet_size, hop_cnt, version)
}
