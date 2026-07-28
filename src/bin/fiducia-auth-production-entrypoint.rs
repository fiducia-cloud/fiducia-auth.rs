//! Production container guard for Supabase session verification.
//!
//! The wrapper and core verifier compile the same policy module. The
//! wrapper resolves and normalizes the environment before replacing
//! itself with the auth server; the server independently validates the
//! same policy before binding traffic.

use std::{fmt, process::Command};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[path = "../supabase_policy.rs"]
mod supabase_policy;

use supabase_policy::{
    remote_userinfo_policy_from_env, RemoteUserinfoPolicyError, DEPLOYMENT_MODE_ENV,
    REMOTE_USERINFO_ENV,
};

const AUTH_BINARY: &str = "/usr/local/bin/fiducia-auth";

fn main() {
    if let Err(error) = run() {
        eprintln!("fiducia-auth startup configuration rejected: {error}");
        std::process::exit(78);
    }
}

fn run() -> Result<(), StartupPolicyError> {
    let (mode, allow_remote_userinfo) = remote_userinfo_policy_from_env()?;

    let mut command = Command::new(AUTH_BINARY);
    command.env(DEPLOYMENT_MODE_ENV, mode.as_str()).env(
        REMOTE_USERINFO_ENV,
        if allow_remote_userinfo {
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

#[derive(Debug)]
enum StartupPolicyError {
    Policy(RemoteUserinfoPolicyError),
    Exec(std::io::Error),
    #[cfg(not(unix))]
    ChildExit(Option<i32>),
}

impl From<RemoteUserinfoPolicyError> for StartupPolicyError {
    fn from(error: RemoteUserinfoPolicyError) -> Self {
        Self::Policy(error)
    }
}

impl fmt::Display for StartupPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => error.fmt(formatter),
            Self::Exec(error) => {
                write!(formatter, "could not execute {AUTH_BINARY}: {error}")
            }
            #[cfg(not(unix))]
            Self::ChildExit(code) => write!(
                formatter,
                "{AUTH_BINARY} exited unsuccessfully with status {code:?}",
            ),
        }
    }
}

impl std::error::Error for StartupPolicyError {}
