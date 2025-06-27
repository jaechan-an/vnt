use dotenv::dotenv;
use tokio_postgres::{Error, NoTls};

pub struct Postgres {
    host: String,
    user: String,
    password: String,
    dbname: String,
}

impl Postgres {
    pub fn new() -> Self {
        dotenv().ok();

        let host = std::env::var("VNT_HOST").expect("VNT_HOST must be set");
        let user = std::env::var("VNT_USER").expect("VNT_USER must be set");
        let password = std::env::var("VNT_PASSWORD").expect("VNT_PASSWORD must be set");
        let dbname = std::env::var("VNT_DBNAME").expect("VNT_DBNAME must be set");

        Postgres {
            host: host,
            user: user,
            password: password,
            dbname: dbname,
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "host={} user={} password={} dbname={}",
            self.host, self.user, self.password, self.dbname
        )
    }

    pub async fn connect(&self) -> Result<tokio_postgres::Client, Error> {
        let database_url = self.to_string();

        info!("DB connection URL: {}", database_url);

        let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("Connection error: {}", e);
            }
        });

        Ok(client)
    }
}
