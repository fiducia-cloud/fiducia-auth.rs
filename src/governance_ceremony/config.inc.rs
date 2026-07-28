#[derive(Debug, Clone)]
pub struct GovernanceConfig {
    pub enabled: bool,
    pub rp_id: Option<String>,
    pub origin: Option<String>,
    pub allowed_tenants: BTreeSet<String>,
    pub ttl_ms: u64,
    ceremony_secret: Option<Vec<u8>>,
    verifier_secret: Option<String>,
}

impl GovernanceConfig {
    pub fn from_env() -> Result<Self, CeremonyError> {
        let enabled = parse_strict_bool(
            std::env::var("FIDUCIA_GOVERNANCE_WEBAUTHN_ENABLED")
                .ok()
                .as_deref(),
        )?;
        let ttl_secs = parse_ttl_secs(
            std::env::var("FIDUCIA_GOVERNANCE_CEREMONY_TTL_SECS")
                .ok()
                .as_deref(),
        )?;

        if !enabled {
            return Ok(Self {
                enabled,
                rp_id: None,
                origin: None,
                allowed_tenants: BTreeSet::new(),
                ttl_ms: ttl_secs * 1000,
                ceremony_secret: None,
                verifier_secret: None,
            });
        }

        let rp_id = required_env("FIDUCIA_GOVERNANCE_RP_ID")?;
        let origin = required_env("FIDUCIA_GOVERNANCE_ORIGIN")?;
        validate_rp_origin(&rp_id, &origin)?;
        let allowed_tenants = parse_tenants(&required_env("FIDUCIA_GOVERNANCE_TENANTS")?)?;
        let ceremony_secret = validate_secret(
            "FIDUCIA_GOVERNANCE_CEREMONY_SECRET",
            required_env("FIDUCIA_GOVERNANCE_CEREMONY_SECRET")?,
        )?
        .into_bytes();
        let verifier_secret = validate_secret(
            "FIDUCIA_GOVERNANCE_VERIFIER_SECRET",
            required_env("FIDUCIA_GOVERNANCE_VERIFIER_SECRET")?,
        )?;

        Ok(Self {
            enabled,
            rp_id: Some(rp_id),
            origin: Some(origin),
            allowed_tenants,
            ttl_ms: ttl_secs * 1000,
            ceremony_secret: Some(ceremony_secret),
            verifier_secret: Some(verifier_secret),
        })
    }

    fn ceremony_secret(&self) -> Result<&[u8], CeremonyError> {
        self.ceremony_secret
            .as_deref()
            .ok_or(CeremonyError::Disabled)
    }

    fn verifier_secret(&self) -> Result<&str, CeremonyError> {
        self.verifier_secret
            .as_deref()
            .ok_or(CeremonyError::Disabled)
    }

    fn rp_id(&self) -> Result<&str, CeremonyError> {
        self.rp_id.as_deref().ok_or(CeremonyError::Disabled)
    }

    fn origin(&self) -> Result<&str, CeremonyError> {
        self.origin.as_deref().ok_or(CeremonyError::Disabled)
    }
}

fn parse_strict_bool(value: Option<&str>) -> Result<bool, CeremonyError> {
    match value.map(str::trim) {
        None | Some("") | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(_) => Err(CeremonyError::InvalidConfig(
            "FIDUCIA_GOVERNANCE_WEBAUTHN_ENABLED must be true, false, 1, or 0",
        )),
    }
}

fn parse_ttl_secs(value: Option<&str>) -> Result<u64, CeremonyError> {
    let ttl = match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => DEFAULT_TTL_SECS,
        Some(value) => value.parse().map_err(|_| {
            CeremonyError::InvalidConfig(
                "FIDUCIA_GOVERNANCE_CEREMONY_TTL_SECS must be an integer",
            )
        })?,
    };
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl) {
        return Err(CeremonyError::InvalidConfig(
            "FIDUCIA_GOVERNANCE_CEREMONY_TTL_SECS must be between 60 and 900",
        ));
    }
    Ok(ttl)
}

fn required_env(name: &'static str) -> Result<String, CeremonyError> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(CeremonyError::MissingConfig(name))
}

fn validate_secret(name: &'static str, value: String) -> Result<String, CeremonyError> {
    if value.len() < 32
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CeremonyError::WeakSecret(name));
    }
    Ok(value)
}

fn parse_tenants(value: &str) -> Result<BTreeSet<String>, CeremonyError> {
    let mut tenants = BTreeSet::new();
    for tenant in value.split(',').map(str::trim).filter(|tenant| !tenant.is_empty()) {
        validate_identifier(tenant, "tenant_id")?;
        tenants.insert(tenant.to_string());
    }
    if tenants.is_empty() {
        return Err(CeremonyError::InvalidConfig(
            "FIDUCIA_GOVERNANCE_TENANTS must contain at least one tenant",
        ));
    }
    Ok(tenants)
}

fn validate_rp_origin(rp_id: &str, origin: &str) -> Result<(), CeremonyError> {
    validate_identifier(rp_id, "rp_id")?;
    let parsed = reqwest::Url::parse(origin)
        .map_err(|_| CeremonyError::InvalidConfig("FIDUCIA_GOVERNANCE_ORIGIN is invalid"))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(CeremonyError::InvalidConfig(
            "FIDUCIA_GOVERNANCE_ORIGIN must contain only scheme, host, and optional port",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or(CeremonyError::InvalidConfig("FIDUCIA_GOVERNANCE_ORIGIN needs a host"))?;
    let rp_matches = host == rp_id || host.ends_with(&format!(".{rp_id}"));
    if !rp_matches {
        return Err(CeremonyError::InvalidConfig(
            "FIDUCIA_GOVERNANCE_RP_ID must equal or be a registrable suffix of the origin host",
        ));
    }
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if parsed.scheme() != "https" && !(cfg!(debug_assertions) && parsed.scheme() == "http" && loopback)
    {
        return Err(CeremonyError::InvalidConfig(
            "FIDUCIA_GOVERNANCE_ORIGIN must use HTTPS outside loopback debug builds",
        ));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum CeremonyError {
    #[error("governance WebAuthn is disabled")]
    Disabled,
    #[error("missing configuration: {0}")]
    MissingConfig(&'static str),
    #[error("weak secret: {0}")]
    WeakSecret(&'static str),
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("ceremony not found")]
    NotFound,
    #[error("ceremony binding or idempotency conflict")]
    Conflict,
    #[error("ceremony is expired")]
    Expired,
    #[error("stale fencing token")]
    StaleFencing,
    #[error("ceremony is claimed by another worker")]
    AlreadyClaimed,
    #[error("ceremony is not claimed")]
    NotClaimed,
    #[error("ceremony claim does not match")]
    ClaimMismatch,
    #[error("authorization failed")]
    Unauthorized,
    #[error("durable ceremony CAS retries exhausted")]
    CasRetriesExhausted,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

