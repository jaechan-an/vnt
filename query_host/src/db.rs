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
    let user_id: i32 = row.get("user_id");
    let hash_chain: Vec<u8> = row.get("hash_chain");

    CLog::new(id, user_id, hash_chain)
}
