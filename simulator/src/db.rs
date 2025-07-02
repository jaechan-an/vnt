use core::Route;
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

pub async fn update_flow(client: &Client, flow_id: i32) {
    let query = "UPDATE flows SET is_done = true WHERE id = $1";

    let rows_affected = client
        .execute(query, &[&flow_id])
        .await
        .expect("UPDATE error in flows");

    assert_eq!(rows_affected, 1, "Expected exactly one row to be updated");

    debug!("Updated flow: id: {}, is_done: true", flow_id);
}
