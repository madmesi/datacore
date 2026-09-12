mod compute;
mod grafana;
mod hdfs;
mod iceberg;
mod kerberos;
mod kms;
mod ldap;
mod policy;
mod portal;
mod py4j_bridge;
mod security;
mod sql_engine;
mod telemetry;
mod vault_db;
mod workflow;

use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("Bootstrapping DataCore Unified Core...");

    portal::launch_portal(8080).await?;

    Ok(())
}
