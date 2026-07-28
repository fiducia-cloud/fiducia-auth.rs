//! Disabled-by-default, non-production governance ceremony boundary.

#[path = "../model.rs"]
mod model;
#[path = "../store.rs"]
mod store;
#[path = "../supabase.rs"]
mod supabase;
#[path = "../governance_ceremony.rs"]
mod governance_ceremony;

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _telemetry = fiducia_telemetry::init("fiducia-governance-ceremony");
    let app = governance_ceremony::router_from_env()?;
    let port: u16 = std::env::var("FIDUCIA_GOVERNANCE_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8102);
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%address, "fiducia governance ceremony boundary listening");
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
