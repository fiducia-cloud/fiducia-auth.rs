//! Durable, proposal-bound governance ceremony lifecycle for DEN-475.
//!
//! This module delegates WebAuthn cryptography to the reviewed `webauthn-rs`
//! safe API. Registration and authentication state is persisted only inside an
//! authenticated encrypted server-side envelope; browser state is never trusted
//! as a substitute for the durable ceremony record or final governance policy.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    model::{AssuranceLevel, UserCtx},
    store::{CasOutcome, KvClient, StoreError},
    supabase,
};

type HmacSha256 = Hmac<Sha256>;

const CONTRACT_VERSION: &str = "1.0";
const OBJECT_KIND: &str = "governance_webauthn_ceremony";
const VERIFIER_HEADER: &str = "x-fiducia-governance-verifier-auth";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const DEFAULT_TTL_SECS: u64 = 300;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 900;
const MAX_CAS_ATTEMPTS: usize = 8;

include!("governance_ceremony/config.inc.rs");
include!("governance_ceremony/model.inc.rs");
#[allow(dead_code)]
mod webauthn;
include!("governance_ceremony/persistence.inc.rs");
include!("governance_ceremony/routes.inc.rs");
include!("governance_ceremony/tests.inc.rs");
