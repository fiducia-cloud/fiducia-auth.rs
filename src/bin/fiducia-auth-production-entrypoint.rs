//! Production container guard for Supabase session verification.
//!
//! The main auth binary still supports an explicitly configured remote
//! `/auth/v1/user` compatibility path for shared-secret projects. Production
//! containers execute through this wrapper so that compatibility mode cannot be
//! enabled accidentally or inherited from a stale environment value.

use std::{env, fmt, process::Command};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const AUTH_BINARY: &str = "/usr/local/bin/fiducia-auth";
const DEPLOYMENT_MODE_ENV: &str = "FIDUCIA_DEPLOYMENT_MODE";
const REMOTE_USERINFO_ENV: &str = "SUPABASE_AUTH_ALLOW_REMOTE_USERINFO";
const PUBLISHABLE_KEY_ENV: &str = "SUPABASE_PUBLISHABLE_KEY";

fn main() {
    if let Err(error) = run() {
        eprintln!("fiducia-auth startup configuration rejected: {error}");
        std::process::exit(78);
    }
}

fn run() -> Result<(), StartupPolicyError> {
    let mode = DeploymentMode::parse(env_value(DEPLOYMENT_MODE_ENV).as_deref())?;
    let requested_remote_userinfo = parse_optional_bool(
        REMOTE_USERINFO_ENV,
        env_value(REMOTE_USERINFO_ENV).as_deref(),
    )?;
    let has_publishable_key = env_value(PUBLISHABLE_KEY_ENV).is_some();
    let policy = resolve_policy(mode, requested_remote_userinfo, has_publishable_key)?;

    let mut command = Command::new(AUTH_BINARY);
    command.env(DEPLOYMENT_MODE_ENV, policy.mode.as_str()).env(
        REMOTE_USERINFO_ENV,
        if policy.allow_remote_userinfo {
            "true"
        } else {
            "false"
        },
    );

    #[cfg(unix)]
    {
        Err(StartupPolicyError::Exec(command.exec()))
    }

    #[cfg(not(unix))]
    {
        let status = command.status().map_err(StartupPolicyError::Exec)?;
        if status.success() {
            Ok(())
        } else {
            Err(StartupPolicyError::ChildExit(status.code()))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeploymentMode {
    Production,
    Staging,
    Development,
    Test,
}

impl DeploymentMode {
    fn parse(value: Option<&str>) -> Result<Self, StartupPolicyError> {
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
            other => Err(StartupPolicyError::InvalidDeploymentMode(other.to_string())),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Staging => "staging",
            Self::Development => "development",
            Self::Test => "test",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartupPolicy {
    mode: DeploymentMode,
    allow_remote_userinfo: bool,
}

fn resolve_policy(
    mode: DeploymentMode,
    requested_remote_userinfo: Option<bool>,
    has_publishable_key: bool,
) -> Result<StartupPolicy, StartupPolicyError> {
    let allow_remote_userinfo = requested_remote_userinfo.unwrap_or(false);

    if mode == DeploymentMode::Production && allow_remote_userinfo {
        return Err(StartupPolicyError::RemoteUserinfoForbiddenInProduction);
    }
    if allow_remote_userinfo && !has_publishable_key {
        return Err(StartupPolicyError::RemoteUserinfoMissingPublishableKey);
    }

    Ok(StartupPolicy {
        mode,
        allow_remote_userinfo,
    })
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
) -> Result<Option<bool>, StartupPolicyError> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        other => Err(StartupPolicyError::InvalidBoolean {
            name,
            value: other.to_string(),
        }),
    }
}

#[derive(Debug)]
enum StartupPolicyError {
    InvalidDeploymentMode(String),
    InvalidBoolean {
        name: &'static str,
        value: String,
    },
    RemoteUserinfoForbiddenInProduction,
    RemoteUserinfoMissingPublishableKey,
    Exec(std::io::Error),
    #[cfg(not(unix))]
    ChildExit(Option<i32>),
}

impl fmt::Display for StartupPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeploymentMode(value) => write!(
                formatter,
                "{DEPLOYMENT_MODE_ENV} must be production, staging, development, or test; got {value:?}",
            ),
            Self::InvalidBoolean { name, value } => {
                write!(formatter, "{name} has invalid boolean value {value:?}")
            }
            Self::RemoteUserinfoForbiddenInProduction => write!(
                formatter,
                "{REMOTE_USERINFO_ENV}=true is forbidden when {DEPLOYMENT_MODE_ENV}=production; migrate the project to asymmetric JWKS signing or use a non-production migration environment",
            ),
            Self::RemoteUserinfoMissingPublishableKey => write!(
                formatter,
                "{PUBLISHABLE_KEY_ENV} is required when remote userinfo compatibility is explicitly enabled",
            ),
            Self::Exec(error) => write!(formatter, "could not execute {AUTH_BINARY}: {error}"),
            #[cfg(not(unix))]
            Self::ChildExit(code) => write!(
                formatter,
                "{AUTH_BINARY} exited unsuccessfully with status {code:?}",
            ),
        }
    }
}

impl std::error::Error for StartupPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_mode_defaults_to_production() {
        assert_eq!(
            DeploymentMode::parse(None).unwrap(),
            DeploymentMode::Production
        );
        assert_eq!(
            DeploymentMode::parse(Some("prod")).unwrap(),
            DeploymentMode::Production
        );
    }

    #[test]
    fn production_defaults_remote_userinfo_off() {
        assert_eq!(
            resolve_policy(DeploymentMode::Production, None, false).unwrap(),
            StartupPolicy {
                mode: DeploymentMode::Production,
                allow_remote_userinfo: false,
            },
        );
    }

    #[test]
    fn production_rejects_remote_userinfo_even_with_a_publishable_key() {
        assert!(matches!(
            resolve_policy(DeploymentMode::Production, Some(true), true),
            Err(StartupPolicyError::RemoteUserinfoForbiddenInProduction),
        ));
    }

    #[test]
    fn staging_requires_an_explicit_opt_in_and_publishable_key() {
        assert_eq!(
            resolve_policy(DeploymentMode::Staging, None, false).unwrap(),
            StartupPolicy {
                mode: DeploymentMode::Staging,
                allow_remote_userinfo: false,
            },
        );
        assert!(matches!(
            resolve_policy(DeploymentMode::Staging, Some(true), false),
            Err(StartupPolicyError::RemoteUserinfoMissingPublishableKey),
        ));
        assert!(
            resolve_policy(DeploymentMode::Staging, Some(true), true)
                .unwrap()
                .allow_remote_userinfo,
        );
    }

    #[test]
    fn invalid_modes_and_boolean_values_fail_closed() {
        assert!(matches!(
            DeploymentMode::parse(Some("maybe-production")),
            Err(StartupPolicyError::InvalidDeploymentMode(_)),
        ));
        assert!(matches!(
            parse_optional_bool(REMOTE_USERINFO_ENV, Some("sometimes")),
            Err(StartupPolicyError::InvalidBoolean { .. }),
        ));
    }
}
