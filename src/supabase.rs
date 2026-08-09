//! Supabase session verification — the **dashboard** plane.
//!
//! B2B humans log into the dashboard via Supabase Auth and send their Supabase
//! access token to fiducia-auth. We prefer offline JWT verification against the
//! project's cached JWKS. Remote `/auth/v1/user` verification is disabled by
//! default and forbidden in production; it exists only as an explicit,
//! observable non-production migration path for shared-secret projects.

use std::{
    collections::HashMap,
    env, fmt,
    sync::OnceLock,
    time::{Duration, Instant},
};

use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use opentelemetry::{global, metrics::Counter, KeyValue};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{OnceCell, RwLock};

use crate::{
    model::{AssuranceLevel, UserCtx, ADMIN_SURFACE_AUDIENCE, CUSTOMER_SURFACE_AUDIENCE},
    supabase_policy::{
        remote_userinfo_policy_from_env, DeploymentMode, RemoteUserinfoPolicyError,
        PUBLISHABLE_KEY_ENV,
    },
};

const DEFAULT_AUDIENCE: &str = "authenticated";
/// Declarative multi-project registry. When unset, the legacy single-project
/// `SUPABASE_URL` / `SUPABASE_PROJECT_REF` configuration is used unchanged.
const PROJECTS_ENV: &str = "FIDUCIA_SUPABASE_PROJECTS";
const DEFAULT_JWKS_TTL_SECS: u64 = 10 * 60;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 5;
/// Minimum age of the cached JWKS before an unknown `kid` may force a refetch.
/// Without this floor, an unauthenticated caller can mint junk JWTs with random
/// `kid`s and turn every request into an outbound JWKS fetch (amplification and
/// upstream rate-limit exhaustion, which would also starve legitimate
/// refreshes). Real signing-key rotations still converge within this window,
/// and the remote-userinfo fallback (when enabled) keeps freshly rotated
/// tokens verifiable in the interim.
const MIN_FORCED_JWKS_REFRESH_SECS: u64 = 30;

static HTTP_CLIENT: OnceCell<reqwest::Client> = OnceCell::const_new();
static JWKS_CACHE: OnceCell<RwLock<HashMap<String, CachedJwks>>> = OnceCell::const_new();
static UNKNOWN_KID_EVENTS: OnceLock<Counter<u64>> = OnceLock::new();
static FORCED_REFRESH_EVENTS: OnceLock<Counter<u64>> = OnceLock::new();
static REMOTE_USERINFO_EVENTS: OnceLock<Counter<u64>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnknownKidStage {
    Observed,
    RefreshBlocked,
}

impl UnknownKidStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::RefreshBlocked => "refresh_blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForcedRefreshOutcome {
    Attempted,
    Succeeded,
    Failed,
    MissingAfterRefresh,
}

impl ForcedRefreshOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::MissingAfterRefresh => "missing_after_refresh",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteUserinfoOutcome {
    Attempted,
    Accepted,
    ClaimRejected,
    Rejected,
    TransportError,
    InvalidResponse,
    UpstreamStatus,
}

impl RemoteUserinfoOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Accepted => "accepted",
            Self::ClaimRejected => "claim_rejected",
            Self::Rejected => "rejected",
            Self::TransportError => "transport_error",
            Self::InvalidResponse => "invalid_response",
            Self::UpstreamStatus => "upstream_status",
        }
    }
}

fn auth_counter(
    cell: &'static OnceLock<Counter<u64>>,
    name: &'static str,
    description: &'static str,
) -> &'static Counter<u64> {
    cell.get_or_init(|| {
        global::meter("fiducia-auth")
            .u64_counter(name)
            .with_description(description)
            .with_unit("{event}")
            .build()
    })
}

fn record_unknown_kid(stage: UnknownKidStage) {
    auth_counter(
        &UNKNOWN_KID_EVENTS,
        "fiducia.auth.supabase.unknown_kid",
        "Unknown Supabase JWKS key-id events without recording the key id",
    )
    .add(1, &[KeyValue::new("stage", stage.as_str())]);
}

fn record_forced_refresh(outcome: ForcedRefreshOutcome) {
    auth_counter(
        &FORCED_REFRESH_EVENTS,
        "fiducia.auth.supabase.forced_jwks_refresh",
        "Forced Supabase JWKS refresh attempts and bounded outcomes",
    )
    .add(1, &[KeyValue::new("outcome", outcome.as_str())]);
}

fn record_remote_userinfo(outcome: RemoteUserinfoOutcome) {
    auth_counter(
        &REMOTE_USERINFO_EVENTS,
        "fiducia.auth.supabase.remote_userinfo",
        "Explicit non-production Supabase remote-userinfo compatibility events",
    )
    .add(1, &[KeyValue::new("outcome", outcome.as_str())]);
}

/// Validate the project identity at startup so a missing deployment value can
/// never silently select a real project or turn into per-request auth failure.
pub fn validate_config() -> Result<(), String> {
    ProjectRegistry::from_env()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The configured Supabase projects, routed by issuer.
///
/// The customer and admin apps normally sit on *separate* Supabase projects so
/// the signing key is itself the surface boundary. A token's unverified `iss`
/// only selects which project verifies it; that project re-pins `iss` during
/// real verification, so a forged issuer can only ever pick a verifier that
/// rejects the signature.
#[derive(Debug, Clone)]
struct ProjectRegistry {
    projects: Vec<SupabaseConfig>,
}

impl ProjectRegistry {
    fn from_env() -> Result<Self, VerifyError> {
        let Some(raw) = env_value(PROJECTS_ENV) else {
            // No registry configured: keep the single-project deployment exactly
            // as it was, including its env vars and error messages.
            return Ok(Self {
                projects: vec![SupabaseConfig::from_env()?],
            });
        };

        let specs: Vec<SupabaseProjectSpec> = serde_json::from_str(&raw).map_err(|_| {
            VerifyError::MissingConfiguration("FIDUCIA_SUPABASE_PROJECTS must be a JSON array")
        })?;
        if specs.is_empty() {
            return Err(VerifyError::MissingConfiguration(
                "FIDUCIA_SUPABASE_PROJECTS must not be empty",
            ));
        }

        let (_, allow_remote_userinfo) =
            remote_userinfo_policy_from_env().map_err(VerifyError::RemoteUserinfoPolicy)?;

        let mut projects: Vec<SupabaseConfig> = Vec::with_capacity(specs.len());
        for spec in specs {
            let project = SupabaseConfig::from_spec(spec, allow_remote_userinfo)?;
            // Two projects sharing an issuer would make routing ambiguous, and
            // the resolution would silently decide which surface a token gets.
            if projects
                .iter()
                .any(|existing| existing.issuer == project.issuer)
            {
                return Err(VerifyError::MissingConfiguration(
                    "FIDUCIA_SUPABASE_PROJECTS contains duplicate issuers",
                ));
            }
            if projects
                .iter()
                .any(|existing| existing.name == project.name)
            {
                return Err(VerifyError::MissingConfiguration(
                    "FIDUCIA_SUPABASE_PROJECTS contains duplicate project names",
                ));
            }
            if project.allow_remote_userinfo && project.publishable_key.is_none() {
                return Err(VerifyError::MissingPublishableKey);
            }
            projects.push(project);
        }
        Ok(Self { projects })
    }

    /// Select the project that owns this token's issuer. A single unbound
    /// legacy project keeps answering for every token, issuer or not.
    fn select(&self, jwt: &str) -> Result<&SupabaseConfig, VerifyError> {
        if let [only] = self.projects.as_slice() {
            if only.surfaces.is_empty() {
                return Ok(only);
            }
        }
        let issuer =
            unverified_issuer(jwt).ok_or(VerifyError::InvalidToken("missing issuer claim"))?;
        self.projects
            .iter()
            .find(|project| project.issuer == issuer)
            .ok_or(VerifyError::UnknownIssuer)
    }
}

/// Read `iss` WITHOUT verifying the signature — routing only.
fn unverified_issuer(jwt: &str) -> Option<String> {
    use base64::Engine;
    let payload = jwt.split('.').nth(1)?;
    if payload.len() > 12 * 1024 {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.get("iss")?.as_str().map(str::to_string)
}

async fn registry() -> Result<&'static ProjectRegistry, VerifyError> {
    // Built once. `validate_config` already failed startup on a bad registry,
    // so this only re-reports that same error on the request path.
    static REGISTRY: OnceCell<Result<ProjectRegistry, String>> = OnceCell::const_new();
    REGISTRY
        .get_or_init(|| async { ProjectRegistry::from_env().map_err(|error| error.to_string()) })
        .await
        .as_ref()
        .map_err(|_| VerifyError::MissingConfiguration("supabase project registry is invalid"))
}

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

    let registry = registry().await?;
    verify_session_with(jwt, registry.select(jwt)?).await
}

async fn verify_session_with(jwt: &str, config: &SupabaseConfig) -> Result<UserCtx, VerifyError> {
    let header = decode_header(jwt).map_err(VerifyError::Jwt)?;

    if is_asymmetric_algorithm(header.alg) && header.kid.is_some() {
        match verify_with_jwks(jwt, config, header.alg, header.kid.as_deref().unwrap()).await {
            Ok(user) => return Ok(user),
            Err(err) if !config.allow_remote_userinfo => return Err(err),
            Err(err) => {
                record_remote_userinfo(RemoteUserinfoOutcome::Attempted);
                tracing::debug!(error = %err, "falling back to supabase auth user endpoint");
            }
        }
    } else if !config.allow_remote_userinfo {
        return Err(VerifyError::UnsupportedAlgorithm(header.alg));
    } else {
        record_remote_userinfo(RemoteUserinfoOutcome::Attempted);
    }

    verify_with_user_endpoint(jwt, config).await
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
            record_unknown_kid(UnknownKidStage::Observed);
            // An unknown `kid` may force one refetch, but only when the cached
            // set is old enough — otherwise attacker-minted kids would turn
            // every request into an outbound JWKS fetch.
            if !forced_refresh_allowed(config).await {
                record_unknown_kid(UnknownKidStage::RefreshBlocked);
                return Err(VerifyError::MissingJwk);
            }

            record_forced_refresh(ForcedRefreshOutcome::Attempted);
            jwks = match refresh_jwks(config).await {
                Ok(jwks) => jwks,
                Err(error) => {
                    record_forced_refresh(ForcedRefreshOutcome::Failed);
                    return Err(error);
                }
            };
            match jwks.find(kid).cloned() {
                Some(jwk) => {
                    record_forced_refresh(ForcedRefreshOutcome::Succeeded);
                    jwk
                }
                None => {
                    record_forced_refresh(ForcedRefreshOutcome::MissingAfterRefresh);
                    return Err(VerifyError::MissingJwk);
                }
            }
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

    let response = match http_client()
        .await
        .get(&config.user_url)
        .header("apikey", publishable_key)
        .bearer_auth(jwt)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            record_remote_userinfo(RemoteUserinfoOutcome::TransportError);
            return Err(VerifyError::Http(error));
        }
    };

    match response.status() {
        StatusCode::OK => {
            let user = match response.json::<SupabaseUser>().await {
                Ok(user) => user,
                Err(error) => {
                    record_remote_userinfo(RemoteUserinfoOutcome::InvalidResponse);
                    return Err(VerifyError::Http(error));
                }
            };
            let result = user_ctx_from_remote_user(user, config);
            record_remote_userinfo(if result.is_ok() {
                RemoteUserinfoOutcome::Accepted
            } else {
                RemoteUserinfoOutcome::ClaimRejected
            });
            result
        }
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            record_remote_userinfo(RemoteUserinfoOutcome::Rejected);
            Err(VerifyError::RejectedBySupabase)
        }
        status => {
            record_remote_userinfo(RemoteUserinfoOutcome::UpstreamStatus);
            Err(VerifyError::SupabaseStatus(status))
        }
    }
}

async fn jwks_cache() -> &'static RwLock<HashMap<String, CachedJwks>> {
    JWKS_CACHE
        .get_or_init(|| async { RwLock::new(HashMap::new()) })
        .await
}

async fn cached_jwks(config: &SupabaseConfig) -> Result<JwkSet, VerifyError> {
    {
        let guard = jwks_cache().await.read().await;
        if let Some(cached) = guard.get(&config.jwks_url) {
            if cached.fetched_at.elapsed() < config.jwks_ttl {
                return Ok(cached.jwks.clone());
            }
        }
    }

    refresh_jwks(config).await
}

/// Whether an unknown-`kid` miss may force a refetch: only when there is no
/// cached set for this URL yet, or the cached set is older than the
/// anti-amplification floor ([`MIN_FORCED_JWKS_REFRESH_SECS`]).
///
/// The cache is keyed per project, so one project's traffic can neither evict
/// another's keys nor reset another's anti-amplification cooldown.
async fn forced_refresh_allowed(config: &SupabaseConfig) -> bool {
    let guard = jwks_cache().await.read().await;
    match guard.get(&config.jwks_url) {
        Some(cached) => forced_refresh_cooldown_elapsed(cached.fetched_at.elapsed()),
        None => true,
    }
}

fn forced_refresh_cooldown_elapsed(cached_age: Duration) -> bool {
    cached_age >= Duration::from_secs(MIN_FORCED_JWKS_REFRESH_SECS)
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

    jwks_cache().await.write().await.insert(
        config.jwks_url.clone(),
        CachedJwks {
            fetched_at: Instant::now(),
            jwks: jwks.clone(),
        },
    );

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

    let orgs = orgs_from_metadata(&[claims.app_metadata.as_ref()]);
    let roles = roles_from_metadata(&[claims.app_metadata.as_ref()]);
    let aal = assurance_level_from_claim(claims.aal.as_deref())?;
    Ok(UserCtx {
        user_id: claims.sub,
        email: claims.email,
        // Org membership MUST come only from `app_metadata` (admin-controlled).
        // `user_metadata` (raw_user_meta_data) is writable by the authenticated
        // user via `auth.updateUser({ data })`, so trusting it for org claims
        // would let any user assign themselves into a victim org (tenant takeover).
        orgs,
        roles,
        aal,
        project_surfaces: config.project_surfaces(),
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

    let orgs = orgs_from_metadata(&[user.app_metadata.as_ref()]);
    let roles = roles_from_metadata(&[user.app_metadata.as_ref()]);
    let aal = assurance_level_from_claim(user.aal.as_deref())?;
    Ok(UserCtx {
        user_id: user.id,
        email: user.email,
        // Only admin-controlled `app_metadata` — never user-writable
        // `user_metadata` — may grant org membership (see the note above).
        orgs,
        roles,
        aal,
        project_surfaces: config.project_surfaces(),
    })
}

/// Supabase encodes assurance directly in the JWT. Older tokens without the
/// claim are single-factor (`aal1`); an unfamiliar value is never treated as a
/// stronger assurance level.
fn assurance_level_from_claim(value: Option<&str>) -> Result<AssuranceLevel, VerifyError> {
    match value.unwrap_or("aal1") {
        "aal1" => Ok(AssuranceLevel::Aal1),
        "aal2" => Ok(AssuranceLevel::Aal2),
        other => Err(VerifyError::UnexpectedAssurance(other.to_string())),
    }
}

fn orgs_from_metadata(values: &[Option<&Value>]) -> Vec<String> {
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

fn roles_from_metadata(values: &[Option<&Value>]) -> Vec<String> {
    let mut roles = Vec::new();
    for value in values.iter().flatten() {
        for key in ["fiducia_roles", "roles", "role"] {
            if let Some(role_value) = value.get(key) {
                push_role_value(&mut roles, role_value);
            }
        }
    }
    roles
}

fn push_role_value(roles: &mut Vec<String>, value: &Value) {
    match value {
        Value::String(role) => {
            let role = role.trim().to_ascii_lowercase();
            if !role.is_empty() && !roles.iter().any(|existing| existing == &role) {
                roles.push(role);
            }
        }
        Value::Array(values) => {
            for value in values {
                push_role_value(roles, value);
            }
        }
        _ => {}
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
    /// Stable slug used in logs and metrics, e.g. `fiducia-customer`.
    name: String,
    /// Surfaces this project may serve. Empty means "unbound" — the legacy
    /// single-project deployment where only roles constrain the surface.
    surfaces: Vec<&'static str>,
    audience: String,
    issuer: String,
    jwks_ttl: Duration,
    jwks_url: String,
    publishable_key: Option<String>,
    user_url: String,
    allow_remote_userinfo: bool,
}

/// One entry of `FIDUCIA_SUPABASE_PROJECTS`.
///
/// Credentials are referenced by environment-variable *name*; a key value must
/// never appear in this JSON, which is carried in plain deployment config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupabaseProjectSpec {
    name: String,
    /// Surface audiences this project is allowed to authorize, e.g.
    /// `["fiducia-customer"]`. Required: an unbound project in a multi-project
    /// deployment would silently defeat the separation.
    surfaces: Vec<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    project_ref: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    jwks_url: Option<String>,
    #[serde(default)]
    user_url: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    /// Name of the env var holding this project's publishable key.
    #[serde(default)]
    publishable_key_env: Option<String>,
}

impl SupabaseConfig {
    /// Build one project from its declarative spec, deriving the Supabase URL
    /// shape from `project_ref` when the explicit URLs are omitted.
    fn from_spec(
        spec: SupabaseProjectSpec,
        allow_remote_userinfo: bool,
    ) -> Result<Self, VerifyError> {
        if spec.name.trim().is_empty() {
            return Err(VerifyError::MissingConfiguration(
                "FIDUCIA_SUPABASE_PROJECTS entries require a non-empty name",
            ));
        }
        let mut surfaces = Vec::new();
        for surface in &spec.surfaces {
            let surface = match surface.trim() {
                ADMIN_SURFACE_AUDIENCE => ADMIN_SURFACE_AUDIENCE,
                CUSTOMER_SURFACE_AUDIENCE => CUSTOMER_SURFACE_AUDIENCE,
                _ => return Err(VerifyError::MissingConfiguration(
                    "FIDUCIA_SUPABASE_PROJECTS surfaces must be fiducia-admin or fiducia-customer",
                )),
            };
            if !surfaces.contains(&surface) {
                surfaces.push(surface);
            }
        }
        if surfaces.is_empty() {
            return Err(VerifyError::MissingConfiguration(
                "FIDUCIA_SUPABASE_PROJECTS entries require at least one surface",
            ));
        }

        let url = match (spec.url.as_deref(), spec.project_ref.as_deref()) {
            (Some(url), _) => normalize_url(url),
            (None, Some(project_ref)) => supabase_url_for_project(project_ref),
            (None, None) => {
                return Err(VerifyError::MissingConfiguration(
                    "FIDUCIA_SUPABASE_PROJECTS entries require url or project_ref",
                ))
            }
        };
        let issuer = spec.issuer.unwrap_or_else(|| format!("{url}/auth/v1"));
        let jwks_url = spec
            .jwks_url
            .unwrap_or_else(|| format!("{issuer}/.well-known/jwks.json"));
        let user_url = spec.user_url.unwrap_or_else(|| format!("{issuer}/user"));
        let publishable_key = match spec.publishable_key_env.as_deref() {
            Some(name) => {
                let value = env_value(name).ok_or(VerifyError::MissingConfiguration(
                    "referenced Supabase publishable-key env var is missing or empty",
                ))?;
                Some(value)
            }
            None => None,
        };

        Ok(SupabaseConfig {
            name: spec.name.trim().to_string(),
            surfaces,
            audience: spec
                .audience
                .unwrap_or_else(|| DEFAULT_AUDIENCE.to_string()),
            issuer,
            jwks_ttl: Duration::from_secs(
                env_value("SUPABASE_AUTH_JWKS_TTL_SECS")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(DEFAULT_JWKS_TTL_SECS),
            ),
            jwks_url,
            publishable_key,
            user_url,
            allow_remote_userinfo,
        })
    }

    /// Surfaces this project may authorize, or `None` for the unbound legacy
    /// single-project deployment where only roles constrain the surface.
    fn project_surfaces(&self) -> Option<Vec<&'static str>> {
        (!self.surfaces.is_empty()).then(|| self.surfaces.clone())
    }

    fn from_env() -> Result<Self, VerifyError> {
        let url = match env_value("SUPABASE_URL") {
            Some(url) => url,
            None => {
                let project_ref = env_value("SUPABASE_PROJECT_REF")
                    .or_else(|| env_value("SUPABASE_PROJECT_ID"))
                    .ok_or(VerifyError::MissingConfiguration(
                        "SUPABASE_URL or SUPABASE_PROJECT_REF must be set",
                    ))?;
                supabase_url_for_project(&project_ref)
            }
        };
        let url = normalize_url(&url);
        let issuer = env_value("SUPABASE_AUTH_ISSUER").unwrap_or_else(|| format!("{url}/auth/v1"));
        let jwks_url = env_value("SUPABASE_AUTH_JWKS_URL")
            .unwrap_or_else(|| format!("{issuer}/.well-known/jwks.json"));
        let user_url =
            env_value("SUPABASE_AUTH_USER_URL").unwrap_or_else(|| format!("{issuer}/user"));
        let publishable_key = env_value(PUBLISHABLE_KEY_ENV);
        let (deployment_mode, allow_remote_userinfo) =
            remote_userinfo_policy_from_env().map_err(VerifyError::RemoteUserinfoPolicy)?;
        debug_assert!(
            deployment_mode != DeploymentMode::Production || !allow_remote_userinfo,
            "shared production policy must forbid remote userinfo",
        );
        debug_assert!(
            !allow_remote_userinfo || publishable_key.is_some(),
            "shared compatibility policy must require a publishable key",
        );

        Ok(SupabaseConfig {
            name: env_value("SUPABASE_PROJECT_NAME").unwrap_or_else(|| "default".to_string()),
            // Legacy single-project deployments stay unbound: both surfaces are
            // served by one project, exactly as before.
            surfaces: Vec::new(),
            audience: env_value("SUPABASE_AUTH_AUDIENCE")
                .unwrap_or_else(|| DEFAULT_AUDIENCE.to_string()),
            issuer,
            jwks_ttl: Duration::from_secs(
                env_value("SUPABASE_AUTH_JWKS_TTL_SECS")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(DEFAULT_JWKS_TTL_SECS),
            ),
            jwks_url,
            publishable_key,
            user_url,
            allow_remote_userinfo,
        })
    }

    #[cfg(test)]
    fn for_project(project_ref: &str) -> Self {
        let url = supabase_url_for_project(project_ref);
        let issuer = format!("{url}/auth/v1");
        SupabaseConfig {
            name: "default".to_string(),
            surfaces: Vec::new(),
            audience: DEFAULT_AUDIENCE.to_string(),
            issuer: issuer.clone(),
            jwks_ttl: Duration::from_secs(DEFAULT_JWKS_TTL_SECS),
            jwks_url: format!("{issuer}/.well-known/jwks.json"),
            publishable_key: None,
            user_url: format!("{issuer}/user"),
            allow_remote_userinfo: false,
        }
    }
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn supabase_url_for_project(project_ref: &str) -> String {
    format!("https://{}.supabase.co", project_ref.trim())
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

/// One project's cached key set. Keyed by JWKS URL in [`JWKS_CACHE`].
#[derive(Clone, Debug)]
struct CachedJwks {
    fetched_at: Instant,
    jwks: JwkSet,
}

#[derive(Debug, Deserialize)]
struct SupabaseClaims {
    sub: String,
    email: Option<String>,
    role: Option<String>,
    #[serde(default)]
    aal: Option<String>,
    app_metadata: Option<Value>,
    #[serde(rename = "user_metadata")]
    _user_metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct SupabaseUser {
    id: String,
    aud: Option<String>,
    email: Option<String>,
    role: Option<String>,
    #[serde(default)]
    aal: Option<String>,
    app_metadata: Option<Value>,
    #[serde(rename = "user_metadata")]
    _user_metadata: Option<Value>,
}

#[derive(Debug)]
enum VerifyError {
    EmptyJwks,
    Http(reqwest::Error),
    InvalidToken(&'static str),
    Jwt(jsonwebtoken::errors::Error),
    MissingJwk,
    MissingPublishableKey,
    MissingConfiguration(&'static str),
    RemoteUserinfoPolicy(RemoteUserinfoPolicyError),
    RejectedBySupabase,
    SupabaseStatus(StatusCode),
    SymmetricJwk,
    UnexpectedAudience(Option<String>),
    UnexpectedAssurance(String),
    UnexpectedRole(Option<String>),
    UnknownIssuer,
    UnsupportedAlgorithm(Algorithm),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::EmptyJwks => write!(f, "supabase jwks endpoint returned no keys"),
            VerifyError::Http(err) => write!(f, "supabase http error: {err}"),
            VerifyError::InvalidToken(reason) => write!(f, "invalid token: {reason}"),
            VerifyError::Jwt(err) => write!(f, "jwt verification error: {err}"),
            VerifyError::MissingJwk => write!(f, "jwks key not found"),
            VerifyError::MissingPublishableKey => {
                write!(
                    f,
                    "SUPABASE_PUBLISHABLE_KEY is required for remote auth verification"
                )
            }
            VerifyError::MissingConfiguration(message) => write!(f, "{message}"),
            VerifyError::RemoteUserinfoPolicy(error) => error.fmt(f),
            VerifyError::RejectedBySupabase => write!(f, "supabase rejected bearer token"),
            VerifyError::SupabaseStatus(status) => {
                write!(f, "supabase auth returned unexpected status {status}")
            }
            VerifyError::SymmetricJwk => write!(f, "refusing to verify JWT with symmetric jwk"),
            VerifyError::UnexpectedAudience(aud) => write!(f, "unexpected audience {aud:?}"),
            VerifyError::UnexpectedAssurance(aal) => {
                write!(f, "unexpected authenticator assurance level {aal:?}")
            }
            VerifyError::UnexpectedRole(role) => write!(f, "unexpected role {role:?}"),
            // Deliberately does not echo the issuer: it is attacker-controlled
            // and unverified at the point this is raised.
            VerifyError::UnknownIssuer => write!(f, "token issuer is not a configured project"),
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

    // ---- multi-project registry: separate Supabase instances per surface ----

    fn registry_from(specs: serde_json::Value) -> Result<ProjectRegistry, VerifyError> {
        let specs: Vec<SupabaseProjectSpec> = serde_json::from_value(specs).unwrap();
        let mut projects = Vec::new();
        for spec in specs {
            let project = SupabaseConfig::from_spec(spec, false)?;
            if projects
                .iter()
                .any(|existing: &SupabaseConfig| existing.issuer == project.issuer)
            {
                return Err(VerifyError::MissingConfiguration(
                    "FIDUCIA_SUPABASE_PROJECTS contains duplicate issuers",
                ));
            }
            projects.push(project);
        }
        Ok(ProjectRegistry { projects })
    }

    fn two_project_registry() -> ProjectRegistry {
        registry_from(json!([
            {
                "name": "fiducia-customer",
                "surfaces": ["fiducia-customer"],
                "project_ref": "customerref"
            },
            {
                "name": "fiducia-admin",
                "surfaces": ["fiducia-admin"],
                "project_ref": "adminref"
            }
        ]))
        .expect("valid two-project registry")
    }

    /// An unsigned token carrying just an `iss` — enough to exercise routing,
    /// which happens before any signature check.
    fn token_from_issuer(issuer: &str) -> String {
        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({ "iss": issuer, "sub": "u1" }).to_string());
        format!("header.{payload}.signature")
    }

    // The headline requirement: the customer app and the admin app sit on
    // different Supabase instances, and each token routes to its own project.
    #[test]
    fn tokens_route_to_their_own_supabase_instance() {
        let registry = two_project_registry();

        let customer = registry
            .select(&token_from_issuer(
                "https://customerref.supabase.co/auth/v1",
            ))
            .expect("customer token routes");
        assert_eq!(customer.name, "fiducia-customer");
        assert_eq!(
            customer.project_surfaces(),
            Some(vec![CUSTOMER_SURFACE_AUDIENCE])
        );
        assert_eq!(
            customer.jwks_url,
            "https://customerref.supabase.co/auth/v1/.well-known/jwks.json"
        );

        let admin = registry
            .select(&token_from_issuer("https://adminref.supabase.co/auth/v1"))
            .expect("admin token routes");
        assert_eq!(admin.name, "fiducia-admin");
        assert_eq!(admin.project_surfaces(), Some(vec![ADMIN_SURFACE_AUDIENCE]));
        // Distinct instances must never share a key set.
        assert_ne!(customer.jwks_url, admin.jwks_url);
    }

    #[test]
    fn a_token_from_an_unconfigured_instance_is_rejected() {
        let registry = two_project_registry();
        assert!(matches!(
            registry.select(&token_from_issuer("https://attacker.supabase.co/auth/v1")),
            Err(VerifyError::UnknownIssuer)
        ));
        assert!(matches!(
            registry.select("not-a-jwt"),
            Err(VerifyError::InvalidToken(_))
        ));
    }

    #[test]
    fn registry_rejects_ambiguous_and_unusable_configuration() {
        // Same issuer twice: routing would silently pick a surface.
        assert!(registry_from(json!([
            {"name": "a", "surfaces": ["fiducia-customer"], "project_ref": "same"},
            {"name": "b", "surfaces": ["fiducia-admin"], "project_ref": "same"}
        ]))
        .is_err());

        // A project with no surface would authorize nothing; an unknown surface
        // is a typo that must not silently fail closed at request time.
        assert!(registry_from(json!([{"name": "a", "surfaces": [], "project_ref": "r"}])).is_err());
        assert!(registry_from(
            json!([{"name": "a", "surfaces": ["fiducia-marketing"], "project_ref": "r"}])
        )
        .is_err());

        // Neither url nor project_ref: nothing to verify against.
        assert!(registry_from(json!([{"name": "a", "surfaces": ["fiducia-admin"]}])).is_err());

        // Secrets must be referenced by env-var name, never inlined.
        assert!(serde_json::from_value::<SupabaseProjectSpec>(json!({
            "name": "a", "surfaces": ["fiducia-admin"], "project_ref": "r",
            "publishable_key": "sb_publishable_inline"
        }))
        .is_err());
    }

    // A self-hosted or custom-domain instance must be configurable by URL, not
    // only by Supabase project ref.
    #[test]
    fn an_explicit_url_overrides_the_derived_supabase_domain() {
        let registry = registry_from(json!([{
            "name": "self-hosted",
            "surfaces": ["fiducia-customer"],
            "url": "https://auth.internal.example/",
            "audience": "fiducia"
        }]))
        .expect("valid url-configured project");
        let project = &registry.projects[0];
        assert_eq!(project.issuer, "https://auth.internal.example/auth/v1");
        assert_eq!(project.audience, "fiducia");
    }

    // Without the registry env var, the existing single-project deployment must
    // behave exactly as before: one unbound project answers for every token.
    #[test]
    fn a_single_unbound_project_still_answers_for_any_issuer() {
        let registry = ProjectRegistry {
            projects: vec![SupabaseConfig::for_project("legacy")],
        };
        let project = registry
            .select(&token_from_issuer("https://anything.supabase.co/auth/v1"))
            .expect("legacy project answers");
        assert_eq!(project.name, "default");
        assert_eq!(project.project_surfaces(), None);
    }

    // Two instances must not share one cache slot, or each request would evict
    // the other project's keys and force a refetch.
    #[tokio::test]
    async fn each_instance_caches_its_own_key_set() {
        let registry = two_project_registry();
        let customer = &registry.projects[0];
        let admin = &registry.projects[1];

        let mut cache = jwks_cache().await.write().await;
        for project in [customer, admin] {
            cache.insert(
                project.jwks_url.clone(),
                CachedJwks {
                    fetched_at: Instant::now(),
                    jwks: JwkSet { keys: Vec::new() },
                },
            );
        }
        assert!(cache.contains_key(&customer.jwks_url));
        assert!(cache.contains_key(&admin.jwks_url));
    }

    // End-to-end of the separation: an admin role smuggled into the customer
    // instance's app_metadata yields no admin surface and no capabilities.
    #[test]
    fn an_admin_role_on_the_customer_instance_grants_nothing() {
        let registry = two_project_registry();
        let customer = &registry.projects[0];
        let claims = SupabaseClaims {
            sub: "user_1".to_string(),
            email: Some("user@example.com".to_string()),
            role: Some(DEFAULT_AUDIENCE.to_string()),
            aal: Some("aal2".to_string()),
            app_metadata: Some(json!({ "fiducia_roles": ["admin"] })),
            _user_metadata: None,
        };

        let user = user_ctx_from_claims(claims, customer).unwrap();
        let authorization = user.authorization_context();
        assert!(
            authorization.surface_audiences.is_empty(),
            "customer-instance token must not reach the admin surface"
        );
        assert!(authorization.capabilities.is_empty());
    }

    #[test]
    fn metadata_orgs_accept_strings_arrays_and_dedupe() {
        let app_metadata = json!({
            "orgs": ["org_a", "org_b", "org_a"],
            "tenant_id": "org_c"
        });
        let user_metadata = json!({ "org_id": "org_d" });

        assert_eq!(
            orgs_from_metadata(&[Some(&app_metadata), Some(&user_metadata)]),
            vec![
                "org_a".to_string(),
                "org_b".to_string(),
                "org_c".to_string(),
                "org_d".to_string()
            ]
        );
    }

    #[test]
    fn metadata_without_org_membership_stays_empty() {
        assert_eq!(
            orgs_from_metadata(&[Some(&json!({ "name": "alex" }))]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn roles_come_only_from_trusted_app_metadata_shape() {
        let metadata = json!({
            "fiducia_roles": ["Admin", "operator", "admin"],
            "roles": "auditor",
            "role": "viewer"
        });
        assert_eq!(
            roles_from_metadata(&[Some(&metadata)]),
            vec![
                "admin".to_string(),
                "operator".to_string(),
                "auditor".to_string(),
                "viewer".to_string()
            ]
        );
    }

    #[test]
    fn verified_claims_ignore_user_writable_orgs_and_roles() {
        let claims = SupabaseClaims {
            sub: "user_1".to_string(),
            email: Some("user@example.com".to_string()),
            role: Some(DEFAULT_AUDIENCE.to_string()),
            aal: Some("aal2".to_string()),
            app_metadata: Some(json!({
                "orgs": ["org_trusted"],
                "fiducia_roles": ["operator"]
            })),
            _user_metadata: Some(json!({
                "orgs": ["org_victim"],
                "fiducia_roles": ["admin"]
            })),
        };

        let user = user_ctx_from_claims(claims, &SupabaseConfig::for_project("unbound")).unwrap();
        assert_eq!(user.orgs, vec!["org_trusted"]);
        assert_eq!(user.roles, vec!["operator"]);
        assert_eq!(user.aal, AssuranceLevel::Aal2);
    }

    #[test]
    fn claims_must_be_authenticated_user_tokens() {
        let claims = SupabaseClaims {
            sub: "user_1".to_string(),
            email: Some("user@example.com".to_string()),
            role: Some("service_role".to_string()),
            aal: None,
            app_metadata: None,
            _user_metadata: None,
        };

        assert!(matches!(
            user_ctx_from_claims(claims, &SupabaseConfig::for_project("unbound")),
            Err(VerifyError::UnexpectedRole(Some(role))) if role == "service_role"
        ));
    }

    #[test]
    fn missing_aal_is_single_factor_and_unknown_aal_is_rejected() {
        assert_eq!(
            assurance_level_from_claim(None).unwrap(),
            AssuranceLevel::Aal1,
            "older Supabase tokens without aal must never become MFA sessions"
        );
        assert_eq!(
            assurance_level_from_claim(Some("aal2")).unwrap(),
            AssuranceLevel::Aal2
        );
        assert!(matches!(
            assurance_level_from_claim(Some("aal3")),
            Err(VerifyError::UnexpectedAssurance(level)) if level == "aal3"
        ));
    }

    #[test]
    fn forced_refresh_cooldown_gates_young_caches() {
        assert!(!forced_refresh_cooldown_elapsed(Duration::from_secs(0)));
        assert!(!forced_refresh_cooldown_elapsed(Duration::from_secs(
            MIN_FORCED_JWKS_REFRESH_SECS - 1
        )));
        assert!(forced_refresh_cooldown_elapsed(Duration::from_secs(
            MIN_FORCED_JWKS_REFRESH_SECS
        )));
    }

    #[tokio::test]
    async fn unknown_kid_cannot_force_a_jwks_refetch_within_the_cooldown() {
        use axum::{extract::State, routing::get, Json, Router};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let hits = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/jwks.json",
                get(|State(hits): State<Arc<AtomicUsize>>| async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(crate::token::jwks())
                }),
            )
            .with_state(hits.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = SupabaseConfig::for_project("jwks-cooldown-test");
        config.jwks_url = format!("http://{address}/jwks.json");

        // Populate the cache once (one upstream fetch).
        refresh_jwks(&config).await.expect("initial jwks fetch");
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // A fresh cache means an attacker-controlled unknown `kid` must NOT
        // trigger another upstream fetch — it fails fast instead.
        let result = verify_with_jwks("junk-jwt", &config, Algorithm::ES256, "unknown-kid").await;
        assert!(matches!(result, Err(VerifyError::MissingJwk)));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "kid-miss within the cooldown must not refetch the JWKS"
        );

        // Once the cached set is older than the cooldown, a kid-miss may force
        // exactly one refetch again (how genuine rotations are picked up).
        {
            let mut guard = jwks_cache().await.write().await;
            let cached = guard.get_mut(&config.jwks_url).expect("cache populated");
            cached.fetched_at = Instant::now()
                .checked_sub(Duration::from_secs(MIN_FORCED_JWKS_REFRESH_SECS + 1))
                .expect("age within Instant range");
        }
        let result = verify_with_jwks("junk-jwt", &config, Algorithm::ES256, "unknown-kid").await;
        assert!(matches!(result, Err(VerifyError::MissingJwk)));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "a stale cache allows one forced refetch on kid-miss"
        );

        server.abort();
    }

    #[test]
    fn metric_dimensions_are_fixed_and_content_free() {
        assert_eq!(UnknownKidStage::Observed.as_str(), "observed");
        assert_eq!(UnknownKidStage::RefreshBlocked.as_str(), "refresh_blocked");
        assert_eq!(ForcedRefreshOutcome::Attempted.as_str(), "attempted");
        assert_eq!(ForcedRefreshOutcome::Succeeded.as_str(), "succeeded");
        assert_eq!(ForcedRefreshOutcome::Failed.as_str(), "failed");
        assert_eq!(
            ForcedRefreshOutcome::MissingAfterRefresh.as_str(),
            "missing_after_refresh",
        );
        assert_eq!(RemoteUserinfoOutcome::Attempted.as_str(), "attempted");
        assert_eq!(RemoteUserinfoOutcome::Accepted.as_str(), "accepted");
        assert_eq!(
            RemoteUserinfoOutcome::ClaimRejected.as_str(),
            "claim_rejected",
        );
        assert_eq!(RemoteUserinfoOutcome::Rejected.as_str(), "rejected");
        assert_eq!(
            RemoteUserinfoOutcome::TransportError.as_str(),
            "transport_error",
        );
        assert_eq!(
            RemoteUserinfoOutcome::InvalidResponse.as_str(),
            "invalid_response",
        );
        assert_eq!(
            RemoteUserinfoOutcome::UpstreamStatus.as_str(),
            "upstream_status",
        );
        assert_eq!(VerifyError::MissingJwk.to_string(), "jwks key not found");
    }

    #[test]
    fn normalize_url_trims_spaces_and_trailing_slashes() {
        assert_eq!(
            normalize_url("  https://example.supabase.co///  "),
            "https://example.supabase.co"
        );
    }

    #[test]
    fn symmetric_jwt_algorithms_are_not_accepted_for_offline_jwks() {
        assert!(!is_asymmetric_algorithm(Algorithm::HS256));
        assert!(is_asymmetric_algorithm(Algorithm::RS256));
        assert!(is_asymmetric_algorithm(Algorithm::EdDSA));
    }

    #[test]
    fn push_org_ignores_empty_and_duplicate_orgs() {
        let mut orgs = vec!["org_a".to_string()];

        push_org(&mut orgs, " ");
        push_org(&mut orgs, "org_a");
        push_org(&mut orgs, " org_b ");

        assert_eq!(orgs, vec!["org_a".to_string(), "org_b".to_string()]);
    }

    #[test]
    fn remote_user_must_match_supabase_audience() {
        let config = SupabaseConfig::for_project("ruxctrzdvugxztbjcpoi");
        let user = SupabaseUser {
            id: "user_1".to_string(),
            aud: Some("service_role".to_string()),
            email: Some("user@example.com".to_string()),
            role: Some(DEFAULT_AUDIENCE.to_string()),
            aal: None,
            app_metadata: None,
            _user_metadata: None,
        };

        assert!(matches!(
            user_ctx_from_remote_user(user, &config),
            Err(VerifyError::UnexpectedAudience(Some(aud))) if aud == "service_role"
        ));
    }
}
