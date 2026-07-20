//! Background sync of Supabase org/plan data into a fast in-cluster cache.
//!
//! Supabase is the durable **system of record**; this pulls org rows periodically
//! into memory so the hot path reads org metadata **locally** (~µs) instead of a
//! live Supabase round trip (~tens-hundreds of ms). Gated on
//! `SUPABASE_SERVICE_ROLE_KEY`. Production startup requires the Supabase URL and
//! service key and completes one initial pull before serving requests, so an
//! empty cache is never mistaken for authoritative "org not found" state.

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

    #[cfg(test)]
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
    fn from_env() -> Result<Self, String> {
        let service_key = std::env::var("SUPABASE_SERVICE_ROLE_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty())
            .ok_or_else(|| "SUPABASE_SERVICE_ROLE_KEY must be configured".to_string())?;
        let base = std::env::var("SUPABASE_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| "SUPABASE_URL must be configured".to_string())?;
        Ok(SyncConfig {
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

/// Validate configuration, populate the cache once, then keep it refreshed.
/// Startup fails if the system of record is unavailable instead of serving an
/// authoritative-looking empty cache.
pub async fn start(cache: Arc<OrgCache>) -> Result<(), String> {
    let config = SyncConfig::from_env()?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| format!("Supabase HTTP client setup failed: {error}"))?;
    let initial = pull(&http, &config).await?;
    let initial_count = initial.len();
    cache.replace(initial).await;
    tracing::info!(table = %config.table, every_s = config.interval.as_secs(), "Supabase org sync enabled");
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(config.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await;
        loop {
            tick.tick().await;
            match pull(&http, &config).await {
                Ok(rows) => {
                    let n = rows.len();
                    cache.replace(rows).await;
                    tracing::debug!(orgs = n, "Supabase org sync refreshed cache");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Supabase org sync failed (serving stale cache)")
                }
            }
        }
    });
    tracing::info!(orgs = initial_count, "Supabase org cache initialized");
    Ok(())
}

async fn pull(
    http: &reqwest::Client,
    config: &SyncConfig,
) -> Result<HashMap<String, Value>, String> {
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
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env-reading tests share process-global state; serialize them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn disabled_without_service_key() {
        let _env = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SUPABASE_SERVICE_ROLE_KEY");
        assert!(SyncConfig::from_env().is_err());
    }

    /// The resilience story pinned end-to-end: one good initial pull, then the
    /// system of record goes down — the cache must keep serving the last good
    /// rows (stale beats empty for the hot auth path) instead of clearing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_cache_keeps_serving_through_a_sor_outage() {
        use axum::response::IntoResponse;
        use axum::{routing::get, Router};
        use std::sync::atomic::{AtomicU32, Ordering};

        static PULLS: AtomicU32 = AtomicU32::new(0);
        async fn orgs() -> axum::response::Response {
            if PULLS.fetch_add(1, Ordering::SeqCst) == 0 {
                axum::Json(serde_json::json!([{ "id": "org_1", "plan": "pro" }])).into_response()
            } else {
                // The outage: every refresh after the initial pull fails.
                axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
        let app = Router::new().route("/rest/v1/organizations", get(orgs));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Hold the env lock across set-vars AND the initial pull so the other
        // env-mutating test cannot interleave (block_in_place keeps the sync
        // guard legal on a multi-thread runtime).
        let cache = Arc::new(OrgCache::default());
        let started = cache.clone();
        tokio::task::block_in_place(move || {
            let _env = ENV_LOCK.lock().unwrap();
            std::env::set_var("SUPABASE_URL", &base);
            std::env::set_var("SUPABASE_SERVICE_ROLE_KEY", "test-key");
            std::env::set_var("SUPABASE_SYNC_INTERVAL_SECS", "1");
            let result = tokio::runtime::Handle::current().block_on(start(started));
            std::env::remove_var("SUPABASE_URL");
            std::env::remove_var("SUPABASE_SERVICE_ROLE_KEY");
            std::env::remove_var("SUPABASE_SYNC_INTERVAL_SECS");
            result.expect("startup completes one good pull");
        });
        assert_eq!(
            cache.get("org_1").await.unwrap()["plan"],
            "pro",
            "initial pull populated the cache"
        );

        // Wait (bounded) until at least two refreshes have FAILED.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while PULLS.load(Ordering::SeqCst) < 3 {
            assert!(
                std::time::Instant::now() < deadline,
                "refresh loop never ran against the dead SoR"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // WRONG BEHAVIOR => FAIL: the cache must still serve the stale rows.
        let row = cache
            .get("org_1")
            .await
            .expect("stale cache must keep serving through the outage");
        assert_eq!(row["plan"], "pro");
    }

    #[tokio::test]
    async fn cache_get_and_replace() {
        let c = OrgCache::default();
        assert_eq!(c.len().await, 0);
        let mut rows = HashMap::new();
        rows.insert(
            "org_1".to_string(),
            serde_json::json!({ "id": "org_1", "plan": "pro" }),
        );
        c.replace(rows).await;
        assert_eq!(c.len().await, 1);
        assert_eq!(c.get("org_1").await.unwrap()["plan"], "pro");
    }

    #[test]
    fn id_coercion_handles_string_and_int() {
        assert_eq!(
            value_as_id(&serde_json::json!("abc")).as_deref(),
            Some("abc")
        );
        assert_eq!(value_as_id(&serde_json::json!(42)).as_deref(), Some("42"));
        assert_eq!(value_as_id(&serde_json::json!(null)), None);
    }
}
