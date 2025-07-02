use tokio_postgres::{Client, Error};

/*
pub async fn collect_logs(client: &Client) -> Result<i32, Error> {
    let last_watermark_id = db::get_metadata(client, "last_flow_watermark").await?;
    // let next_watermark = collector::next_flow_watermark(&client, last_watermark_id).await;

    Ok(last_watermark_id)
}
*/
