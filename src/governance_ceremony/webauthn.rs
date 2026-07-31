//! Reviewed WebAuthn safe-API adapter and protected server-side ceremony bundles.
//!
//! `webauthn-rs` deliberately disables serialisation of registration and
//! authentication state by default because placing that state in a browser cookie
//! permits replay. Fiducia enables only `danger-allow-state-serialisation` so the
//! browser options and matching opaque state can be stored together inside one
//! authenticated encrypted envelope in the server-side Fiducia KV namespace.
//! The envelope is never a client authority.

use std::{collections::BTreeMap, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    Key, KeyInit, XChaCha20Poly1305, XNonce,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder,
};

use super::{sha256_bytes, CeremonyError};

const PROTECTED_STATE_CONTRACT_VERSION: &str = "1.0";
const PROTECTED_STATE_OBJECT_KIND: &str = "governance_webauthn_protected_bundle";
const PROTECTED_STATE_ALGORITHM: &str = "xchacha20poly1305";
const XCHACHA_NONCE_BYTES: usize = 24;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedStateKind {
    PasskeyRegistration,
    PasskeyAuthentication,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedStateContext {
    pub tenant_id: String,
    pub ceremony_id: String,
    pub binding_hash: String,
    pub state_kind: ProtectedStateKind,
    pub expires_at_ms: u64,
}

impl ProtectedStateContext {
    fn validate(&self) -> Result<(), CeremonyError> {
        if self.tenant_id.is_empty() || self.ceremony_id.is_empty() {
            return Err(CeremonyError::ProtectedState(
                "tenant and ceremony identifiers are required",
            ));
        }
        super::validate_sha256_urn(&self.binding_hash, "binding_hash")?;
        if self.expires_at_ms == 0 {
            return Err(CeremonyError::ProtectedState(
                "protected state expiry must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedCeremonyState {
    pub contract_version: String,
    pub object_kind: String,
    pub algorithm: String,
    pub key_id: String,
    pub keyring_version: u64,
    pub state_kind: ProtectedStateKind,
    pub nonce: String,
    pub ciphertext: String,
    pub associated_data_hash: String,
}

#[derive(Clone)]
pub struct ProtectedStateCodec {
    active_key_id: Arc<str>,
    keyring_version: u64,
    keys: Arc<BTreeMap<String, [u8; 32]>>,
}

impl ProtectedStateCodec {
    pub fn new(
        active_key_id: impl Into<String>,
        keyring_version: u64,
        keys: BTreeMap<String, [u8; 32]>,
    ) -> Result<Self, CeremonyError> {
        let active_key_id = active_key_id.into();
        if keyring_version == 0 {
            return Err(CeremonyError::ProtectedState(
                "protected-state keyring version must be positive",
            ));
        }
        if active_key_id.is_empty() || !keys.contains_key(&active_key_id) {
            return Err(CeremonyError::ProtectedState(
                "active protected-state key is missing",
            ));
        }
        if keys.is_empty()
            || keys.keys().any(|key_id| {
                key_id.is_empty()
                    || key_id.len() > 128
                    || key_id
                        .chars()
                        .any(|character| character.is_whitespace() || character.is_control())
            })
        {
            return Err(CeremonyError::ProtectedState(
                "protected-state key identifiers are invalid",
            ));
        }
        Ok(Self {
            active_key_id: Arc::from(active_key_id),
            keyring_version,
            keys: Arc::new(keys),
        })
    }

    pub fn from_base64_keys(
        active_key_id: impl Into<String>,
        keyring_version: u64,
        encoded_keys: BTreeMap<String, String>,
    ) -> Result<Self, CeremonyError> {
        let mut keys = BTreeMap::new();
        for (key_id, encoded) in encoded_keys {
            let decoded = URL_SAFE_NO_PAD
                .decode(encoded.as_bytes())
                .map_err(|_| CeremonyError::ProtectedState("invalid state-key encoding"))?;
            let key: [u8; 32] = decoded
                .try_into()
                .map_err(|_| CeremonyError::ProtectedState("state key must be 32 bytes"))?;
            keys.insert(key_id, key);
        }
        Self::new(active_key_id, keyring_version, keys)
    }

    pub fn active_key_id(&self) -> &str {
        self.active_key_id.as_ref()
    }

    pub fn keyring_version(&self) -> u64 {
        self.keyring_version
    }

    pub fn seal<T: Serialize>(
        &self,
        context: &ProtectedStateContext,
        value: &T,
    ) -> Result<ProtectedCeremonyState, CeremonyError> {
        context.validate()?;
        let key =
            self.keys
                .get(self.active_key_id.as_ref())
                .ok_or(CeremonyError::ProtectedState(
                    "active protected-state key is unavailable",
                ))?;
        let associated_data =
            associated_data(context, self.active_key_id.as_ref(), self.keyring_version)?;
        let plaintext = serde_json::to_vec(value)?;
        let mut nonce = [0_u8; XCHACHA_NONCE_BYTES];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| CeremonyError::ProtectedState("nonce generation failed"))?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| CeremonyError::ProtectedState("state encryption failed"))?;

        Ok(ProtectedCeremonyState {
            contract_version: PROTECTED_STATE_CONTRACT_VERSION.to_string(),
            object_kind: PROTECTED_STATE_OBJECT_KIND.to_string(),
            algorithm: PROTECTED_STATE_ALGORITHM.to_string(),
            key_id: self.active_key_id.to_string(),
            keyring_version: self.keyring_version,
            state_kind: context.state_kind,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            associated_data_hash: sha256_bytes(&associated_data),
        })
    }

    pub fn open<T: DeserializeOwned>(
        &self,
        context: &ProtectedStateContext,
        envelope: &ProtectedCeremonyState,
    ) -> Result<T, CeremonyError> {
        context.validate()?;
        if envelope.contract_version != PROTECTED_STATE_CONTRACT_VERSION
            || envelope.object_kind != PROTECTED_STATE_OBJECT_KIND
            || envelope.algorithm != PROTECTED_STATE_ALGORITHM
            || envelope.keyring_version == 0
            || envelope.state_kind != context.state_kind
        {
            return Err(CeremonyError::ProtectedState(
                "protected-state envelope metadata mismatch",
            ));
        }
        let key = self
            .keys
            .get(&envelope.key_id)
            .ok_or(CeremonyError::ProtectedState(
                "protected-state key is unavailable",
            ))?;
        let associated_data = associated_data(context, &envelope.key_id, envelope.keyring_version)?;
        if envelope.associated_data_hash != sha256_bytes(&associated_data) {
            return Err(CeremonyError::ProtectedState(
                "protected-state associated data mismatch",
            ));
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(envelope.nonce.as_bytes())
            .map_err(|_| CeremonyError::ProtectedState("invalid protected-state nonce"))?;
        let nonce: [u8; XCHACHA_NONCE_BYTES] = nonce
            .try_into()
            .map_err(|_| CeremonyError::ProtectedState("invalid protected-state nonce"))?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|_| CeremonyError::ProtectedState("invalid protected-state ciphertext"))?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| CeremonyError::ProtectedState("protected-state authentication failed"))?;
        serde_json::from_slice(&plaintext).map_err(CeremonyError::from)
    }
}

fn associated_data(
    context: &ProtectedStateContext,
    key_id: &str,
    keyring_version: u64,
) -> Result<Vec<u8>, CeremonyError> {
    #[derive(Serialize)]
    struct AssociatedData<'a> {
        contract_version: &'static str,
        object_kind: &'static str,
        algorithm: &'static str,
        key_id: &'a str,
        keyring_version: u64,
        context: &'a ProtectedStateContext,
    }

    Ok(serde_json::to_vec(&AssociatedData {
        contract_version: PROTECTED_STATE_CONTRACT_VERSION,
        object_kind: PROTECTED_STATE_OBJECT_KIND,
        algorithm: PROTECTED_STATE_ALGORITHM,
        key_id,
        keyring_version,
        context,
    })?)
}

#[derive(Serialize, Deserialize)]
struct RegistrationBundle {
    client_options: Value,
    state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
struct AuthenticationBundle {
    client_options: Value,
    state: PasskeyAuthentication,
}

#[derive(Clone)]
pub struct GovernanceWebauthn {
    webauthn: Arc<Webauthn>,
    protected_state: ProtectedStateCodec,
}

impl GovernanceWebauthn {
    pub fn new(
        rp_id: &str,
        rp_origin: &str,
        protected_state: ProtectedStateCodec,
    ) -> Result<Self, CeremonyError> {
        let origin = Url::parse(rp_origin)
            .map_err(|_| CeremonyError::InvalidConfig("invalid governance WebAuthn origin"))?;
        let builder = WebauthnBuilder::new(rp_id, &origin)?;
        let webauthn = builder.build()?;
        Ok(Self {
            webauthn: Arc::new(webauthn),
            protected_state,
        })
    }

    pub fn start_registration(
        &self,
        context: &ProtectedStateContext,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, ProtectedCeremonyState), CeremonyError> {
        require_kind(context, ProtectedStateKind::PasskeyRegistration)?;
        let (challenge, state) = self.webauthn.start_passkey_registration(
            user_unique_id,
            user_name,
            user_display_name,
            exclude_credentials,
        )?;
        let bundle = RegistrationBundle {
            client_options: serde_json::to_value(&challenge)?,
            state,
        };
        let envelope = self.protected_state.seal(context, &bundle)?;
        Ok((challenge, envelope))
    }

    pub fn finish_registration(
        &self,
        context: &ProtectedStateContext,
        envelope: &ProtectedCeremonyState,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, CeremonyError> {
        require_kind(context, ProtectedStateKind::PasskeyRegistration)?;
        let bundle: RegistrationBundle = self.protected_state.open(context, envelope)?;
        Ok(self
            .webauthn
            .finish_passkey_registration(credential, &bundle.state)?)
    }

    pub fn start_authentication(
        &self,
        context: &ProtectedStateContext,
        passkeys: &[Passkey],
    ) -> Result<(RequestChallengeResponse, ProtectedCeremonyState), CeremonyError> {
        require_kind(context, ProtectedStateKind::PasskeyAuthentication)?;
        if passkeys.is_empty() {
            return Err(CeremonyError::InvalidRequest(
                "at least one active passkey is required",
            ));
        }
        let (challenge, state) = self.webauthn.start_passkey_authentication(passkeys)?;
        let bundle = AuthenticationBundle {
            client_options: serde_json::to_value(&challenge)?,
            state,
        };
        let envelope = self.protected_state.seal(context, &bundle)?;
        Ok((challenge, envelope))
    }

    pub fn finish_authentication(
        &self,
        context: &ProtectedStateContext,
        envelope: &ProtectedCeremonyState,
        credential: &PublicKeyCredential,
    ) -> Result<AuthenticationResult, CeremonyError> {
        require_kind(context, ProtectedStateKind::PasskeyAuthentication)?;
        let bundle: AuthenticationBundle = self.protected_state.open(context, envelope)?;
        Ok(self
            .webauthn
            .finish_passkey_authentication(credential, &bundle.state)?)
    }

    pub fn recover_client_options(
        &self,
        context: &ProtectedStateContext,
        envelope: &ProtectedCeremonyState,
    ) -> Result<Value, CeremonyError> {
        match context.state_kind {
            ProtectedStateKind::PasskeyRegistration => {
                let bundle: RegistrationBundle = self.protected_state.open(context, envelope)?;
                Ok(bundle.client_options)
            }
            ProtectedStateKind::PasskeyAuthentication => {
                let bundle: AuthenticationBundle = self.protected_state.open(context, envelope)?;
                Ok(bundle.client_options)
            }
        }
    }
}

fn require_kind(
    context: &ProtectedStateContext,
    required: ProtectedStateKind,
) -> Result<(), CeremonyError> {
    if context.state_kind != required {
        return Err(CeremonyError::ProtectedState(
            "protected-state ceremony kind mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(active: &str, version: u64) -> ProtectedStateCodec {
        ProtectedStateCodec::new(
            active,
            version,
            BTreeMap::from([
                ("key-1".to_string(), [1_u8; 32]),
                ("key-2".to_string(), [2_u8; 32]),
            ]),
        )
        .expect("valid test keyring")
    }

    fn context(kind: ProtectedStateKind) -> ProtectedStateContext {
        ProtectedStateContext {
            tenant_id: "company-123".to_string(),
            ceremony_id: "ceremony-123".to_string(),
            binding_hash: format!("sha256:{}", "a".repeat(64)),
            state_kind: kind,
            expires_at_ms: 2_000_000_000_000,
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct ExampleState {
        challenge_id: String,
        generation: u64,
    }

    #[test]
    fn protected_state_round_trips_and_detects_binding_mutation() {
        let codec = keys("key-1", 1);
        let original = ExampleState {
            challenge_id: "challenge-1".to_string(),
            generation: 7,
        };
        let context = context(ProtectedStateKind::PasskeyRegistration);
        let envelope = codec.seal(&context, &original).expect("seal state");
        assert_eq!(
            codec
                .open::<ExampleState>(&context, &envelope)
                .expect("open state"),
            original
        );

        let mut changed = context.clone();
        changed.binding_hash = format!("sha256:{}", "b".repeat(64));
        assert!(codec.open::<ExampleState>(&changed, &envelope).is_err());
    }

    #[test]
    fn key_rotation_reads_old_state_and_writes_with_the_active_version() {
        let old_codec = keys("key-1", 1);
        let new_codec = keys("key-2", 2);
        let context = context(ProtectedStateKind::PasskeyAuthentication);
        let value = ExampleState {
            challenge_id: "challenge-2".to_string(),
            generation: 8,
        };
        let old_envelope = old_codec.seal(&context, &value).expect("seal old state");
        assert_eq!(old_envelope.key_id, "key-1");
        assert_eq!(old_envelope.keyring_version, 1);
        assert_eq!(
            new_codec
                .open::<ExampleState>(&context, &old_envelope)
                .expect("read old key after rotation"),
            value
        );

        let new_envelope = new_codec.seal(&context, &value).expect("seal new state");
        assert_eq!(new_envelope.key_id, "key-2");
        assert_eq!(new_envelope.keyring_version, 2);
    }

    #[test]
    fn missing_key_ciphertext_and_keyring_mutation_fail_closed() {
        let codec = keys("key-1", 1);
        let context = context(ProtectedStateKind::PasskeyRegistration);
        let value = ExampleState {
            challenge_id: "challenge-3".to_string(),
            generation: 9,
        };
        let envelope = codec.seal(&context, &value).expect("seal state");

        let only_new_key = ProtectedStateCodec::new(
            "key-2",
            2,
            BTreeMap::from([("key-2".to_string(), [2_u8; 32])]),
        )
        .expect("valid test keyring");
        assert!(only_new_key
            .open::<ExampleState>(&context, &envelope)
            .is_err());

        let mut corrupted = envelope.clone();
        corrupted.ciphertext.push('A');
        assert!(codec.open::<ExampleState>(&context, &corrupted).is_err());

        let mut wrong_version = envelope;
        wrong_version.keyring_version += 1;
        assert!(codec
            .open::<ExampleState>(&context, &wrong_version)
            .is_err());
    }

    #[test]
    fn safe_api_registration_options_and_state_share_one_encrypted_bundle() {
        let adapter = GovernanceWebauthn::new(
            "fiducia.test",
            "https://auth.fiducia.test",
            keys("key-1", 1),
        )
        .expect("valid WebAuthn adapter");
        let context = context(ProtectedStateKind::PasskeyRegistration);
        let (challenge, envelope) = adapter
            .start_registration(&context, Uuid::new_v4(), "founder-a", "Founder A", None)
            .expect("start registration");
        let recovered = adapter
            .recover_client_options(&context, &envelope)
            .expect("recover original client options");
        assert_eq!(recovered, serde_json::to_value(challenge).unwrap());
        assert_eq!(envelope.state_kind, ProtectedStateKind::PasskeyRegistration);
        assert_eq!(envelope.algorithm, PROTECTED_STATE_ALGORITHM);
        assert!(!envelope.ciphertext.is_empty());

        let persisted = serde_json::to_string(&envelope).unwrap();
        assert!(!persisted.contains("publicKey"));
        assert!(!persisted.contains("founder-a"));
    }
}
