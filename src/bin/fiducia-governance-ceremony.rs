//! Disabled-by-default, non-production governance ceremony boundary.

#[path = "../governance_ceremony.rs"]
mod governance_ceremony;
#[allow(dead_code)]
#[path = "../model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../store.rs"]
mod store;
#[allow(dead_code)]
#[path = "../supabase.rs"]
mod supabase;
#[allow(dead_code)]
#[path = "../supabase_policy.rs"]
mod supabase_policy;
#[allow(dead_code)]
#[path = "../token.rs"]
mod token;

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
