//! Supabase session verification — the **dashboard** plane.
//!
//! B2B humans log into the dashboard via Supabase Auth and send their Supabase
//! access token to fiducia-auth. We prefer offline JWT verification against the
//! project's cached JWKS. If the project still uses shared-secret signing and
//! has no public JWKS, we fall back to Supabase's `/auth/v1/user` endpoint with
//! the publishable key.

use std::{
    env, fmt,
    time::{Duration, Instant},
};

use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{OnceCell, RwLock};

use crate::model::UserCtx;

const DEFAULT_PROJECT_REF: &str = "ruxctrzdvugxztbjcpoi";
const DEFAULT_AUDIENCE: &str = "authenticated";
const DEFAULT_ORG_ID: &str = "fiducia-cloud";
const DEFAULT_JWKS_TTL_SECS: u64 = 10 * 60;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 5;

static HTTP_CLIENT: OnceCell<reqwest::Client> = OnceCell::const_new();
static JWKS_CACHE: OnceCell<RwLock<Option<CachedJwks>>> = OnceCell::const_new();

/// Verifies a Supabase Auth access token and returns the caller identity.
pub async fn verify_session(bearer_jwt: &str) -> Option<UserCtx> {
    match verify_session_inner(bearer_jwt).await {
        Ok(user) => Some(user),
        Err(err) => {
            tracing::debug!(error = %err, "supabase session rejected");
            None
        }
    }
}

async fn verify_session_inner(jwt: &str) -> Result<UserCtx, VerifyError> {
    if jwt.trim().is_empty() {
        return Err(VerifyError::InvalidToken("empty bearer token"));
    }

    let config = SupabaseConfig::from_env();
    let header = decode_header(jwt).map_err(VerifyError::Jwt)?;

    if is_asymmetric_algorithm(header.alg) && header.kid.is_some() {
        match verify_with_jwks(jwt, &config, header.alg, header.kid.as_deref().unwrap()).await {
            Ok(user) => return Ok(user),
            Err(err) if !config.allow_remote_userinfo => return Err(err),
            Err(err) => {
                tracing::debug!(error = %err, "falling back to supabase auth user endpoint");
            }
        }
    } else if !config.allow_remote_userinfo {
        return Err(VerifyError::UnsupportedAlgorithm(header.alg));
    }

    verify_with_user_endpoint(jwt, &config).await
}

async fn verify_with_jwks(
    jwt: &str,
    config: &SupabaseConfig,
    alg: Algorithm,
    kid: &str,
) -> Result<UserCtx, VerifyError> {
    let mut jwks = cached_jwks(config).await?;
    let jwk = match jwks.find(kid).cloned() {
        Some(jwk) => jwk,
        None => {
            jwks = refresh_jwks(config).await?;
            jwks.find(kid)
                .cloned()
                .ok_or_else(|| VerifyError::MissingJwk(kid.to_string()))?
        }
    };

    reject_symmetric_jwk(&jwk)?;

    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(VerifyError::Jwt)?;
    let mut validation = Validation::new(alg);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_str()]);
    validation.required_spec_claims.insert("iss".to_string());
    validation.required_spec_claims.insert("aud".to_string());
    validation.required_spec_claims.insert("sub".to_string());

    let token =
        decode::<SupabaseClaims>(jwt, &decoding_key, &validation).map_err(VerifyError::Jwt)?;
    user_ctx_from_claims(token.claims, config)
}

async fn verify_with_user_endpoint(
    jwt: &str,
    config: &SupabaseConfig,
) -> Result<UserCtx, VerifyError> {
    let publishable_key = config
        .publishable_key
        .as_deref()
        .ok_or(VerifyError::MissingPublishableKey)?;

    let response = http_client()
        .await
        .get(&config.user_url)
        .header("apikey", publishable_key)
        .bearer_auth(jwt)
        .send()
        .await
        .map_err(VerifyError::Http)?;

    match response.status() {
        StatusCode::OK => {
            let user = response
                .json::<SupabaseUser>()
                .await
                .map_err(VerifyError::Http)?;
            user_ctx_from_remote_user(user, config)
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(VerifyError::RejectedBySupabase),
        status => Err(VerifyError::SupabaseStatus(status)),
    }
}

async fn cached_jwks(config: &SupabaseConfig) -> Result<JwkSet, VerifyError> {
    let cache = JWKS_CACHE.get_or_init(|| async { RwLock::new(None) }).await;

    {
        let guard = cache.read().await;
        if let Some(cached) = guard.as_ref() {
            if cached.url == config.jwks_url && cached.fetched_at.elapsed() < config.jwks_ttl {
                return Ok(cached.jwks.clone());
            }
        }
    }

    refresh_jwks(config).await
}

async fn refresh_jwks(config: &SupabaseConfig) -> Result<JwkSet, VerifyError> {
    let jwks = http_client()
        .await
        .get(&config.jwks_url)
        .send()
        .await
        .map_err(VerifyError::Http)?
        .error_for_status()
        .map_err(VerifyError::Http)?
        .json::<JwkSet>()
        .await
        .map_err(VerifyError::Http)?;

    if jwks.keys.is_empty() {
        return Err(VerifyError::EmptyJwks);
    }

    let cache = JWKS_CACHE.get_or_init(|| async { RwLock::new(None) }).await;
    *cache.write().await = Some(CachedJwks {
        url: config.jwks_url.clone(),
        fetched_at: Instant::now(),
        jwks: jwks.clone(),
    });

    Ok(jwks)
}

async fn http_client() -> &'static reqwest::Client {
    HTTP_CLIENT
        .get_or_init(|| async {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
                .build()
                .expect("build supabase HTTP client")
        })
        .await
}

fn user_ctx_from_claims(
    claims: SupabaseClaims,
    config: &SupabaseConfig,
) -> Result<UserCtx, VerifyError> {
    if claims.role.as_deref() != Some(DEFAULT_AUDIENCE) {
        return Err(VerifyError::UnexpectedRole(claims.role));
    }
    if claims.sub.trim().is_empty() {
        return Err(VerifyError::InvalidToken("missing subject"));
    }

    Ok(UserCtx {
        user_id: claims.sub,
        email: claims.email,
        orgs: orgs_from_metadata(
            &[claims.app_metadata.as_ref(), claims.user_metadata.as_ref()],
            config,
        ),
    })
}

fn user_ctx_from_remote_user(
    user: SupabaseUser,
    config: &SupabaseConfig,
) -> Result<UserCtx, VerifyError> {
    if user
        .aud
        .as_deref()
        .is_some_and(|aud| aud != config.audience)
    {
        return Err(VerifyError::UnexpectedAudience(user.aud));
    }
    if user
        .role
        .as_deref()
        .is_some_and(|role| role != DEFAULT_AUDIENCE)
    {
        return Err(VerifyError::UnexpectedRole(user.role));
    }
    if user.id.trim().is_empty() {
        return Err(VerifyError::InvalidToken("missing user id"));
    }

    Ok(UserCtx {
        user_id: user.id,
        email: user.email,
        orgs: orgs_from_metadata(
            &[user.app_metadata.as_ref(), user.user_metadata.as_ref()],
            config,
        ),
    })
}

fn orgs_from_metadata(values: &[Option<&Value>], config: &SupabaseConfig) -> Vec<String> {
    let mut orgs = Vec::new();
    for value in values.iter().flatten() {
        for key in [
            "orgs",
            "org_ids",
            "organizations",
            "organization_ids",
            "org_id",
            "organization_id",
            "tenant_id",
        ] {
            if let Some(org_value) = value.get(key) {
                push_org_value(&mut orgs, org_value);
            }
        }
    }

    if orgs.is_empty() {
        orgs.push(config.default_org_id.clone());
    }
    orgs
}

fn push_org_value(orgs: &mut Vec<String>, value: &Value) {
    match value {
        Value::String(org) => push_org(orgs, org),
        Value::Array(values) => {
            for value in values {
                push_org_value(orgs, value);
            }
        }
        _ => {}
    }
}

fn push_org(orgs: &mut Vec<String>, org: &str) {
    let org = org.trim();
    if !org.is_empty() && !orgs.iter().any(|existing| existing == org) {
        orgs.push(org.to_string());
    }
}

fn reject_symmetric_jwk(jwk: &Jwk) -> Result<(), VerifyError> {
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        return Err(VerifyError::SymmetricJwk);
    }
    Ok(())
}

fn is_asymmetric_algorithm(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::EdDSA
    )
}

#[derive(Debug, Clone)]
struct SupabaseConfig {
    audience: String,
    default_org_id: String,
    issuer: String,
    jwks_ttl: Duration,
    jwks_url: String,
    publishable_key: Option<String>,
    user_url: String,
    allow_remote_userinfo: bool,
}

impl SupabaseConfig {
    fn from_env() -> Self {
        let project_ref = env_value("SUPABASE_PROJECT_REF")
            .or_else(|| env_value("SUPABASE_PROJECT_ID"))
            .unwrap_or_else(|| DEFAULT_PROJECT_REF.to_string());
        let url =
            env_value("SUPABASE_URL").unwrap_or_else(|| supabase_url_for_project(&project_ref));
        let url = normalize_url(&url);
        let issuer = env_value("SUPABASE_AUTH_ISSUER").unwrap_or_else(|| format!("{url}/auth/v1"));
        let jwks_url = env_value("SUPABASE_AUTH_JWKS_URL")
            .unwrap_or_else(|| format!("{issuer}/.well-known/jwks.json"));
        let user_url =
            env_value("SUPABASE_AUTH_USER_URL").unwrap_or_else(|| format!("{issuer}/user"));

        SupabaseConfig {
            audience: env_value("SUPABASE_AUTH_AUDIENCE")
                .unwrap_or_else(|| DEFAULT_AUDIENCE.to_string()),
            default_org_id: env_value("FIDUCIA_DEFAULT_ORG_ID")
                .unwrap_or_else(|| DEFAULT_ORG_ID.to_string()),
            issuer,
            jwks_ttl: Duration::from_secs(
                env_value("SUPABASE_AUTH_JWKS_TTL_SECS")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(DEFAULT_JWKS_TTL_SECS),
            ),
            jwks_url,
            publishable_key: env_value("SUPABASE_PUBLISHABLE_KEY"),
            user_url,
            allow_remote_userinfo: env_bool("SUPABASE_AUTH_ALLOW_REMOTE_USERINFO", true),
        }
    }

    #[cfg(test)]
    fn for_project(project_ref: &str) -> Self {
        let url = supabase_url_for_project(project_ref);
        let issuer = format!("{url}/auth/v1");
        SupabaseConfig {
            audience: DEFAULT_AUDIENCE.to_string(),
            default_org_id: DEFAULT_ORG_ID.to_string(),
            issuer: issuer.clone(),
            jwks_ttl: Duration::from_secs(DEFAULT_JWKS_TTL_SECS),
            jwks_url: format!("{issuer}/.well-known/jwks.json"),
            publishable_key: None,
            user_url: format!("{issuer}/user"),
            allow_remote_userinfo: true,
        }
    }
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_bool(name: &str, default: bool) -> bool {
    match env_value(name).as_deref() {
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON") => true,
        Some("0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF") => false,
        _ => default,
    }
}

fn supabase_url_for_project(project_ref: &str) -> String {
    format!("https://{}.supabase.co", project_ref.trim())
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

#[derive(Clone, Debug)]
struct CachedJwks {
    url: String,
    fetched_at: Instant,
    jwks: JwkSet,
}

#[derive(Debug, Deserialize)]
struct SupabaseClaims {
    sub: String,
    email: Option<String>,
    role: Option<String>,
    app_metadata: Option<Value>,
    user_metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct SupabaseUser {
    id: String,
    aud: Option<String>,
    email: Option<String>,
    role: Option<String>,
    app_metadata: Option<Value>,
    user_metadata: Option<Value>,
}

#[derive(Debug)]
enum VerifyError {
    EmptyJwks,
    Http(reqwest::Error),
    InvalidToken(&'static str),
    Jwt(jsonwebtoken::errors::Error),
    MissingJwk(String),
    MissingPublishableKey,
    RejectedBySupabase,
    SupabaseStatus(StatusCode),
    SymmetricJwk,
    UnexpectedAudience(Option<String>),
    UnexpectedRole(Option<String>),
    UnsupportedAlgorithm(Algorithm),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::EmptyJwks => write!(f, "supabase jwks endpoint returned no keys"),
            VerifyError::Http(err) => write!(f, "supabase http error: {err}"),
            VerifyError::InvalidToken(reason) => write!(f, "invalid token: {reason}"),
            VerifyError::Jwt(err) => write!(f, "jwt verification error: {err}"),
            VerifyError::MissingJwk(kid) => write!(f, "jwks key not found for kid {kid}"),
            VerifyError::MissingPublishableKey => {
                write!(
                    f,
                    "SUPABASE_PUBLISHABLE_KEY is required for remote auth verification"
                )
            }
            VerifyError::RejectedBySupabase => write!(f, "supabase rejected bearer token"),
            VerifyError::SupabaseStatus(status) => {
                write!(f, "supabase auth returned unexpected status {status}")
            }
            VerifyError::SymmetricJwk => write!(f, "refusing to verify JWT with symmetric jwk"),
            VerifyError::UnexpectedAudience(aud) => write!(f, "unexpected audience {aud:?}"),
            VerifyError::UnexpectedRole(role) => write!(f, "unexpected role {role:?}"),
            VerifyError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported jwt signing algorithm {alg:?}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn project_ref_builds_supabase_auth_urls() {
        let config = SupabaseConfig::for_project("ruxctrzdvugxztbjcpoi");

        assert_eq!(
            config.issuer,
            "https://ruxctrzdvugxztbjcpoi.supabase.co/auth/v1"
        );
        assert_eq!(
            config.jwks_url,
            "https://ruxctrzdvugxztbjcpoi.supabase.co/auth/v1/.well-known/jwks.json"
        );
        assert_eq!(
            config.user_url,
            "https://ruxctrzdvugxztbjcpoi.supabase.co/auth/v1/user"
        );
    }

    #[test]
    fn metadata_orgs_accept_strings_arrays_and_dedupe() {
        let config = SupabaseConfig::for_project("ruxctrzdvugxztbjcpoi");
        let app_metadata = json!({
            "orgs": ["org_a", "org_b", "org_a"],
            "tenant_id": "org_c"
        });
        let user_metadata = json!({ "org_id": "org_d" });

        assert_eq!(
            orgs_from_metadata(&[Some(&app_metadata), Some(&user_metadata)], &config),
            vec![
                "org_a".to_string(),
                "org_b".to_string(),
                "org_c".to_string(),
                "org_d".to_string()
            ]
        );
    }

    #[test]
    fn metadata_orgs_fall_back_to_default_org() {
        let config = SupabaseConfig::for_project("ruxctrzdvugxztbjcpoi");

        assert_eq!(
            orgs_from_metadata(&[Some(&json!({ "name": "alex" }))], &config),
            vec![DEFAULT_ORG_ID.to_string()]
        );
    }

    #[test]
    fn claims_must_be_authenticated_user_tokens() {
        let config = SupabaseConfig::for_project("ruxctrzdvugxztbjcpoi");
        let claims = SupabaseClaims {
            sub: "user_1".to_string(),
            email: Some("user@example.com".to_string()),
            role: Some("service_role".to_string()),
            app_metadata: None,
            user_metadata: None,
        };

        assert!(matches!(
            user_ctx_from_claims(claims, &config),
            Err(VerifyError::UnexpectedRole(Some(role))) if role == "service_role"
        ));
    }
}
