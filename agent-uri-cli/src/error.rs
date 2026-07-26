//! Errors, and the exit codes they map to.
//!
//! Every error carries three things: a stable machine-readable `kind`, a
//! statement of *what failed*, and a *remedy* telling the operator what to do
//! about it. There are no bare `Debug` dumps anywhere in the output path.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | Success; for `attest verify`, the token verified |
//! | 1 | Refused: an invalid URI, or a token that failed verification |
//! | 2 | Usage error (emitted by the argument parser) |
//! | 3 | I/O or key error |
//!
//! The dividing line between 1 and 2: a malformed *knob* (`--ttl bogus`) is a
//! usage error, caught by the argument parser. Bad *content* that the command
//! exists to judge (a URI, a token) is a refusal, and carries a diagnosis.

use std::fmt;
use std::io;
use std::path::Path;

/// Exit code for a refused URI or token.
pub const EXIT_REFUSED: u8 = 1;

/// Exit code for an I/O or key error.
pub const EXIT_FAULT: u8 = 3;

/// A structured failure: what happened, and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    /// Stable slug identifying the failure, e.g. `token_expired`.
    pub kind: &'static str,
    /// What failed.
    pub message: String,
    /// What the operator should do about it.
    pub remedy: String,
}

impl Diagnosis {
    /// Builds a diagnosis.
    pub fn new(kind: &'static str, message: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            remedy: remedy.into(),
        }
    }
}

/// Anything that can end a command early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// The URI or token was understood and judged unacceptable. Exit 1.
    Refused(Diagnosis),
    /// The environment got in the way: a missing key, bad permissions, failed
    /// write. Exit 3.
    Fault(Diagnosis),
}

impl CliError {
    /// Builds a refusal (exit 1).
    pub fn refused(
        kind: &'static str,
        message: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self::Refused(Diagnosis::new(kind, message, remedy))
    }

    /// Builds a fault (exit 3).
    pub fn fault(
        kind: &'static str,
        message: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self::Fault(Diagnosis::new(kind, message, remedy))
    }

    /// Wraps an I/O error against the path that provoked it.
    pub fn io(path: &Path, action: &str, source: &io::Error) -> Self {
        Self::fault(
            "io_error",
            format!("cannot {action} '{}': {source}", path.display()),
            "check the path exists and that you have permission to use it",
        )
    }

    /// The diagnosis behind this error.
    pub const fn diagnosis(&self) -> &Diagnosis {
        match self {
            Self::Refused(d) | Self::Fault(d) => d,
        }
    }

    /// The process exit code for this error.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Refused(_) => EXIT_REFUSED,
            Self::Fault(_) => EXIT_FAULT,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.diagnosis().message)
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_exits_one() {
        let error = CliError::refused("invalid_uri", "bad", "fix it");
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn fault_exits_three() {
        let error = CliError::fault("io_error", "bad", "fix it");
        assert_eq!(error.exit_code(), 3);
    }

    #[test]
    fn diagnosis_carries_kind_message_and_remedy() {
        let error = CliError::refused("token_expired", "expired at T", "issue a new one");
        let diagnosis = error.diagnosis();

        assert_eq!(diagnosis.kind, "token_expired");
        assert_eq!(diagnosis.message, "expired at T");
        assert_eq!(diagnosis.remedy, "issue a new one");
    }

    #[test]
    fn display_shows_the_message_not_debug() {
        let error = CliError::refused("invalid_uri", "not an agent:// URI", "check the scheme");
        assert_eq!(error.to_string(), "not an agent:// URI");
    }

    #[test]
    fn io_error_names_the_path_and_action() {
        let source = io::Error::new(io::ErrorKind::NotFound, "no such file");
        let error = CliError::io(Path::new("/tmp/k.key"), "read key file", &source);

        assert_eq!(error.exit_code(), 3);
        assert!(error.to_string().contains("/tmp/k.key"));
        assert!(error.to_string().contains("read key file"));
    }
}
