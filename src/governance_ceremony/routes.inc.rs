#[derive(Clone)]
pub struct CeremonyAppState {
    config: GovernanceConfig,
    store: Option<Arc<CeremonyStore>>,
}

impl CeremonyAppState {
    pub fn from_env() -> Result<Self, CeremonyError> {
        let config = GovernanceConfig::from_env()?;
        if !config.enabled {
            return Ok(Self { config, store: None });
        }
        supabase::validate_config().map_err(|_| {
            CeremonyError::InvalidConfig("Supabase verification must be configured when governance is enabled")
        })?;
        let kv = Arc::new(KvClient::from_env()?);
        let store = Arc::new(CeremonyStore::new(kv, config.clone()));
        Ok(Self {
            config,
            store: Some(store),
        })
    }

    fn store(&self) -> Result<&Arc<CeremonyStore>, CeremonyError> {
        self.store.as_ref().ok_or(CeremonyError::Disabled)
    }
}

pub fn router_from_env() -> Result<Router, CeremonyError> {
    let state = Arc::new(CeremonyAppState::from_env()?);
    Ok(Router::new()
        .route("/healthz", get(health))
        .route(
            "/v1/governance/proposals/:proposal_id/approval/begin",
            post(begin_approval),
        )
        .route(
            "/internal/v1/governance/ceremonies/:ceremony_id/claim",
            post(claim_ceremony),
        )
        .route(
            "/internal/v1/governance/ceremonies/:ceremony_id/complete-verified",
            post(complete_verified),
        )
        .with_state(state))
}

async fn health(State(state): State<Arc<CeremonyAppState>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "fiducia-governance-ceremony",
        "governance_webauthn_enabled": state.config.enabled
    }))
}

async fn begin_approval(
    State(state): State<Arc<CeremonyAppState>>,
    Path(proposal_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<BeginApprovalRequest>,
) -> Response {
    let user = match require_user(&headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if user.aal != AssuranceLevel::Aal2 {
        return error_response(StatusCode::FORBIDDEN, "aal2_required");
    }
    if !user.orgs.iter().any(|org| org == &body.org_id) {
        return error_response(StatusCode::FORBIDDEN, "forbidden_tenant");
    }
    // Until the external participant registry adapter lands, the safest prototype
    // mapping is exact Supabase subject == participant id. It is intentionally
    // restrictive and cannot be widened by browser input.
    if body.participant_id != user.user_id {
        return error_response(StatusCode::FORBIDDEN, "participant_binding_required");
    }
    let idempotency_key = match parse_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return ceremony_error_response(error),
    };
    let store = match state.store() {
        Ok(store) => store,
        Err(error) => return ceremony_error_response(error),
    };
    match store
        .begin(
            &proposal_id,
            &body.participant_id,
            &body.org_id,
            &idempotency_key,
            &body,
            now_ms(),
        )
        .await
    {
        Ok(response) => {
            tracing::info!(
                outcome = if response.replayed { "replayed" } else { "created" },
                ceremony_id = %response.ceremony_id,
                "governance ceremony begin"
            );
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(error) => ceremony_error_response(error),
    }
}

async fn claim_ceremony(
    State(state): State<Arc<CeremonyAppState>>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ClaimRequest>,
) -> Response {
    if let Err(error) = require_verifier(&state.config, &headers) {
        return ceremony_error_response(error);
    }
    let store = match state.store() {
        Ok(store) => store,
        Err(error) => return ceremony_error_response(error),
    };
    match store.claim(&ceremony_id, &body, now_ms()).await {
        Ok(response) => {
            tracing::info!(
                outcome = if response.taken_over { "taken_over" } else if response.replayed { "replayed" } else { "claimed" },
                ceremony_id = %response.ceremony_id,
                "governance ceremony claim"
            );
            Json(response).into_response()
        }
        Err(error) => ceremony_error_response(error),
    }
}

async fn complete_verified(
    State(state): State<Arc<CeremonyAppState>>,
    Path(ceremony_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CompleteVerifiedRequest>,
) -> Response {
    if let Err(error) = require_verifier(&state.config, &headers) {
        return ceremony_error_response(error);
    }
    let store = match state.store() {
        Ok(store) => store,
        Err(error) => return ceremony_error_response(error),
    };
    match store.complete_verified(&ceremony_id, &body, now_ms()).await {
        Ok(response) => {
            tracing::info!(
                outcome = if response.replayed { "replayed" } else { "completed" },
                ceremony_id = %response.ceremony_id,
                "verified governance WebAuthn assertion recorded"
            );
            Json(response).into_response()
        }
        Err(error) => ceremony_error_response(error),
    }
}

async fn require_user(headers: &HeaderMap) -> Result<UserCtx, Response> {
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match bearer {
        Some(jwt) => supabase::verify_session(jwt)
            .await
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "invalid_session")),
        None => Err(error_response(
            StatusCode::UNAUTHORIZED,
            "missing_bearer_token",
        )),
    }
}

fn require_verifier(config: &GovernanceConfig, headers: &HeaderMap) -> Result<(), CeremonyError> {
    if !config.enabled {
        return Err(CeremonyError::Disabled);
    }
    let supplied = headers
        .get(VERIFIER_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(CeremonyError::Unauthorized)?;
    if !constant_time_secret_matches(config.verifier_secret()?, supplied) {
        return Err(CeremonyError::Unauthorized);
    }
    Ok(())
}

fn constant_time_secret_matches(expected: &str, supplied: &str) -> bool {
    let expected_digest = Sha256::digest(expected.as_bytes());
    let supplied_digest = Sha256::digest(supplied.as_bytes());
    expected_digest
        .iter()
        .zip(supplied_digest.iter())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<String, CeremonyError> {
    let value = headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .ok_or(CeremonyError::InvalidRequest("idempotency_key_required"))?;
    if value.len() < 16
        || value.len() > 128
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CeremonyError::InvalidRequest("invalid_idempotency_key"));
    }
    Ok(value.to_string())
}

fn ceremony_error_response(error: CeremonyError) -> Response {
    match error {
        CeremonyError::Disabled => error_response(StatusCode::NOT_FOUND, "governance_disabled"),
        CeremonyError::Unauthorized => error_response(StatusCode::UNAUTHORIZED, "unauthorized"),
        CeremonyError::NotFound => error_response(StatusCode::NOT_FOUND, "ceremony_not_found"),
        CeremonyError::Conflict
        | CeremonyError::AlreadyClaimed
        | CeremonyError::ClaimMismatch
        | CeremonyError::NotClaimed => {
            error_response(StatusCode::CONFLICT, "ceremony_conflict")
        }
        CeremonyError::Expired => error_response(StatusCode::GONE, "ceremony_expired"),
        CeremonyError::StaleFencing => {
            error_response(StatusCode::CONFLICT, "stale_fencing_token")
        }
        CeremonyError::InvalidRequest(_) => {
            error_response(StatusCode::BAD_REQUEST, "invalid_request")
        }
        CeremonyError::Webauthn(_) => {
    error_response(StatusCode::BAD_REQUEST, "webauthn_verification_failed")
}
CeremonyError::ProtectedState(_) => error_response(
    StatusCode::SERVICE_UNAVAILABLE,
    "protected_ceremony_state_unavailable",
),
        CeremonyError::Store(_) | CeremonyError::CasRetriesExhausted => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "ceremony_store_unavailable")
        }
        CeremonyError::MissingConfig(_)
        | CeremonyError::WeakSecret(_)
        | CeremonyError::InvalidConfig(_)
        | CeremonyError::Json(_) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "governance_configuration_error")
        }
    }
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn validate_identifier(value: &str, _field: &'static str) -> Result<(), CeremonyError> {
    if value.is_empty()
        || value.len() > 160
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(CeremonyError::InvalidRequest("invalid_identifier"));
    }
    Ok(())
}

fn validate_sha256_urn(value: &str, _field: &'static str) -> Result<(), CeremonyError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CeremonyError::InvalidRequest("invalid_sha256_urn"));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CeremonyError::InvalidRequest("invalid_sha256_urn"));
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), CeremonyError> {
    if value.len() < 16
        || value.len() > 128
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CeremonyError::InvalidRequest("invalid_idempotency_key"));
    }
    Ok(())
}

fn ceremony_id(tenant_id: &str, participant_id: &str, proposal_id: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    for value in [tenant_id, participant_id, proposal_id, key] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("gcer_{}", hex_lower(&hasher.finalize()))
}

fn ceremony_path(ceremony_id: &str) -> String {
    format!("__auth/governance/ceremonies/{ceremony_id}")
}

fn derive_challenge(
    secret: &[u8],
    ceremony_id: &str,
    binding_hash: &str,
) -> Result<String, CeremonyError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| CeremonyError::InvalidConfig("invalid ceremony HMAC key"))?;
    mac.update(b"fiducia-governance-ceremony-v1\0");
    mac.update(&(ceremony_id.len() as u64).to_be_bytes());
    mac.update(ceremony_id.as_bytes());
    mac.update(&(binding_hash.len() as u64).to_be_bytes());
    mac.update(binding_hash.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String, CeremonyError> {
    Ok(sha256_bytes(&serde_json::to_vec(value)?))
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(value)))
}

fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

