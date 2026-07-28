//! One fail-closed policy for every Supabase verification entrypoint.
//!
//! Both the production wrapper and the core verifier compile this file.
//! Keeping deployment-mode parsing and remote-userinfo eligibility here
//! prevents the container guard and the server from drifting apart.

use std::{env, fmt};

pub const DEPLOYMENT_MODE_ENV: &str = "FIDUCIA_DEPLOYMENT_MODE";
pub const REMOTE_USERINFO_ENV: &str = "SUPABASE_AUTH_ALLOW_REMOTE_USERINFO";
pub const PUBLISHABLE_KEY_ENV: &str = "SUPABASE_PUBLISHABLE_KEY";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentMode {
    Production,
    Staging,
    Development,
    Test,
}

impl DeploymentMode {
    fn parse(value: Option<&str>) -> Result<Self, RemoteUserinfoPolicyError> {
        match value
            .unwrap_or("production")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "production" | "prod" => Ok(Self::Production),
            "staging" | "stage" => Ok(Self::Staging),
            "development" | "dev" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            other => Err(RemoteUserinfoPolicyError::InvalidDeploymentMode(
                other.to_string(),
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Staging => "staging",
            Self::Development => "development",
            Self::Test => "test",
        }
    }
}

pub fn remote_userinfo_policy_from_env(
) -> Result<(DeploymentMode, bool), RemoteUserinfoPolicyError> {
    let deployment_mode = env_value(DEPLOYMENT_MODE_ENV);
    let requested_remote_userinfo = env_value(REMOTE_USERINFO_ENV);
    remote_userinfo_policy_from_values(
        deployment_mode.as_deref(),
        requested_remote_userinfo.as_deref(),
        env_value(PUBLISHABLE_KEY_ENV).is_some(),
    )
}

pub fn remote_userinfo_policy_from_values(
    deployment_mode: Option<&str>,
    requested_remote_userinfo: Option<&str>,
    has_publishable_key: bool,
) -> Result<(DeploymentMode, bool), RemoteUserinfoPolicyError> {
    let mode = DeploymentMode::parse(deployment_mode)?;
    let requested = parse_optional_bool(REMOTE_USERINFO_ENV, requested_remote_userinfo)?;
    let allow_remote_userinfo = requested.unwrap_or(false);

    if mode == DeploymentMode::Production && allow_remote_userinfo {
        return Err(RemoteUserinfoPolicyError::ForbiddenInProduction);
    }
    if allow_remote_userinfo && !has_publishable_key {
        return Err(RemoteUserinfoPolicyError::MissingPublishableKey);
    }

    Ok((mode, allow_remote_userinfo))
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_optional_bool(
    name: &'static str,
    value: Option<&str>,
) -> Result<Option<bool>, RemoteUserinfoPolicyError> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        other => Err(RemoteUserinfoPolicyError::InvalidBoolean {
            name,
            value: other.to_string(),
        }),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RemoteUserinfoPolicyError {
    InvalidDeploymentMode(String),
    InvalidBoolean {
        name: &'static str,
        value: String,
    },
    ForbiddenInProduction,
    MissingPublishableKey,
}

impl fmt::Display for RemoteUserinfoPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeploymentMode(value) => write!(
                formatter,
                "{DEPLOYMENT_MODE_ENV} must be production, staging, development, or test; got {value:?}",
            ),
            Self::InvalidBoolean { name, value } => {
                write!(formatter, "{name} has invalid boolean value {value:?}")
            }
            Self::ForbiddenInProduction => write!(
                formatter,
                "{REMOTE_USERINFO_ENV}=true is forbidden when {DEPLOYMENT_MODE_ENV}=production; migrate to asymmetric JWKS signing or use a non-production migration environment",
            ),
            Self::MissingPublishableKey => write!(
                formatter,
                "{PUBLISHABLE_KEY_ENV} is required when remote userinfo compatibility is explicitly enabled",
            ),
        }
    }
}

impl std::error::Error for RemoteUserinfoPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_mode_defaults_to_production() {
        assert_eq!(
            remote_userinfo_policy_from_values(None, None, false).unwrap(),
            (DeploymentMode::Production, false),
        );
        assert_eq!(
            remote_userinfo_policy_from_values(Some("prod"), Some("false"), false)
                .unwrap(),
            (DeploymentMode::Production, false),
        );
    }

    #[test]
    fn production_rejects_remote_userinfo_even_with_a_publishable_key() {
        assert_eq!(
            remote_userinfo_policy_from_values(
                Some("production"),
                Some("true"),
                true,
            ),
            Err(RemoteUserinfoPolicyError::ForbiddenInProduction),
        );
    }

    #[test]
    fn non_production_requires_explicit_opt_in_and_publishable_key() {
        for mode in ["staging", "development", "test"] {
            assert_eq!(
                remote_userinfo_policy_from_values(Some(mode), None, false).unwrap(),
                (DeploymentMode::parse(Some(mode)).unwrap(), false),
            );
            assert_eq!(
                remote_userinfo_policy_from_values(Some(mode), Some("true"), false),
                Err(RemoteUserinfoPolicyError::MissingPublishableKey),
            );
            assert_eq!(
                remote_userinfo_policy_from_values(Some(mode), Some("true"), true)
                    .unwrap(),
                (DeploymentMode::parse(Some(mode)).unwrap(), true),
            );
        }
    }

    #[test]
    fn malformed_values_fail_closed() {
        assert!(matches!(
            remote_userinfo_policy_from_values(Some("maybe-production"), None, false),
            Err(RemoteUserinfoPolicyError::InvalidDeploymentMode(_)),
        ));
        assert!(matches!(
            remote_userinfo_policy_from_values(
                Some("staging"),
                Some("sometimes"),
                true,
            ),
            Err(RemoteUserinfoPolicyError::InvalidBoolean { .. }),
        ));
    }
}
