//! Background sync of Supabase org/plan data into a fast in-cluster cache.
//!
//! Supabase is the durable **system of record**; this pulls org rows periodically
//! into memory so the hot path reads org metadata **locally** (~µs) instead of a
//! live Supabase round trip (~tens-hundreds of ms). Gated on
//! `SUPABASE_SERVICE_ROLE_KEY` — absent → no-op (empty cache), so the data plane
//! never depends on it. Wire `SUPABASE_URL` + the key + (optionally) the table /
//! id-column names; the sync reads via PostgREST.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::RwLock;

/// In-memory org cache: `org_id -> row`. Replaced atomically each sync.
#[derive(Default)]
pub struct OrgCache {
    orgs: RwLock<HashMap<String, Value>>,
}

impl OrgCache {
    pub async fn get(&self, org_id: &str) -> Option<Value> {
        self.orgs.read().await.get(org_id).cloned()
    }

    pub async fn len(&self) -> usize {
        self.orgs.read().await.len()
    }

    async fn replace(&self, rows: HashMap<String, Value>) {
        *self.orgs.write().await = rows;
    }
}

struct SyncConfig {
    base: String,
    service_key: String,
    table: String,
    id_column: String,
    interval: Duration,
}

impl SyncConfig {
    fn from_env() -> Option<Self> {
        let service_key = std::env::var("SUPABASE_SERVICE_ROLE_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty())?;
        let base = std::env::var("SUPABASE_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())?;
        Some(SyncConfig {
            base: base.trim_end_matches('/').to_string(),
            service_key,
            table: env_or("SUPABASE_ORGS_TABLE", "organizations"),
            id_column: env_or("SUPABASE_ORGS_ID_COLUMN", "id"),
            interval: Duration::from_secs(
                std::env::var("SUPABASE_SYNC_INTERVAL_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60),
            ),
        })
    }
}

/// Spawn the background sync if Supabase is configured; otherwise a logged no-op.
pub fn spawn(cache: Arc<OrgCache>) {
    let Some(config) = SyncConfig::from_env() else {
        tracing::info!("Supabase sync disabled (no SUPABASE_SERVICE_ROLE_KEY); org cache stays empty");
        return;
    };
    tracing::info!(table = %config.table, every_s = config.interval.as_secs(), "Supabase org sync enabled");
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        let mut tick = tokio::time::interval(config.interval);
        loop {
            tick.tick().await;
            match pull(&http, &config).await {
                Ok(rows) => {
                    let n = rows.len();
                    cache.replace(rows).await;
                    tracing::debug!(orgs = n, "Supabase org sync refreshed cache");
                }
                Err(e) => tracing::warn!(error = %e, "Supabase org sync failed (serving stale cache)"),
            }
        }
    });
}

async fn pull(http: &reqwest::Client, config: &SyncConfig) -> Result<HashMap<String, Value>, String> {
    let url = format!("{}/rest/v1/{}?select=*", config.base, config.table);
    let resp = http
        .get(&url)
        .header("apikey", &config.service_key)
        .header("authorization", format!("Bearer {}", config.service_key))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let rows: Vec<Value> = resp.json().await.map_err(|e| e.to_string())?;
    let mut out = HashMap::new();
    for row in rows {
        if let Some(id) = row.get(&config.id_column).and_then(value_as_id) {
            out.insert(id, row);
        }
    }
    Ok(out)
}

fn value_as_id(v: &Value) -> Option<String> {
    v.as_str()
        .map(String::from)
        .or_else(|| v.as_i64().map(|n| n.to_string()))
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_without_service_key() {
        std::env::remove_var("SUPABASE_SERVICE_ROLE_KEY");
        assert!(SyncConfig::from_env().is_none());
    }

    #[tokio::test]
    async fn cache_get_and_replace() {
        let c = OrgCache::default();
        assert_eq!(c.len().await, 0);
        let mut rows = HashMap::new();
        rows.insert("org_1".to_string(), serde_json::json!({ "id": "org_1", "plan": "pro" }));
        c.replace(rows).await;
        assert_eq!(c.len().await, 1);
        assert_eq!(c.get("org_1").await.unwrap()["plan"], "pro");
    }

    #[test]
    fn id_coercion_handles_string_and_int() {
        assert_eq!(value_as_id(&serde_json::json!("abc")).as_deref(), Some("abc"));
        assert_eq!(value_as_id(&serde_json::json!(42)).as_deref(), Some("42"));
        assert_eq!(value_as_id(&serde_json::json!(null)), None);
    }
}
