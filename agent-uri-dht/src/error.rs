//! Custom error types for DHT operations.

use std::fmt;

/// Errors that can occur during DHT operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtError {
    /// The agent is not registered.
    NotFound {
        /// The agent URI that was not found
        agent_uri: String,
    },
    /// The registration already exists.
    AlreadyRegistered {
        /// The agent URI that was already registered
        agent_uri: String,
    },
    /// The registration has expired.
    Expired {
        /// The agent URI whose registration expired
        agent_uri: String,
    },
    /// The attestation is invalid or missing.
    InvalidAttestation {
        /// The agent URI with invalid attestation
        agent_uri: String,
        /// Reason the attestation is invalid
        reason: String,
    },
    /// The capability path does not match the attestation.
    CapabilityMismatch {
        /// The claimed capability path
        claimed: String,
        /// The attested capability path
        attested: String,
    },
    /// Maximum registrations per key exceeded.
    KeyCapacityExceeded {
        /// The DHT key that is at capacity
        key: String,
        /// Maximum allowed registrations
        max: usize,
    },
    /// The endpoints list is empty.
    NoEndpoints,
    /// Internal error (should not happen in production).
    Internal {
        /// Error message
        message: String,
    },
}

impl fmt::Display for DhtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { agent_uri } => {
                write!(
                    f,
                    "agent '{agent_uri}' not found in DHT; verify the URI is correct and the agent is registered"
                )
            }
            Self::AlreadyRegistered { agent_uri } => {
                write!(
                    f,
                    "agent '{agent_uri}' is already registered; use update_endpoint to modify the registration"
                )
            }
            Self::Expired { agent_uri } => {
                write!(
                    f,
                    "registration for agent '{agent_uri}' has expired; re-register to restore"
                )
            }
            Self::InvalidAttestation { agent_uri, reason } => {
                write!(f, "invalid attestation for agent '{agent_uri}': {reason}")
            }
            Self::CapabilityMismatch { claimed, attested } => {
                write!(
                    f,
                    "capability mismatch: claimed path '{claimed}' is not covered by attested path '{attested}'"
                )
            }
            Self::KeyCapacityExceeded { key, max } => {
                write!(
                    f,
                    "DHT key '{key}' has reached maximum capacity of {max} registrations"
                )
            }
            Self::NoEndpoints => {
                write!(f, "registration must have at least one endpoint")
            }
            Self::Internal { message } => {
                write!(f, "internal DHT error: {message}")
            }
        }
    }
}

impl std::error::Error for DhtError {}

impl DhtError {
    /// Creates a `NotFound` error.
    #[must_use]
    pub fn not_found(agent_uri: impl Into<String>) -> Self {
        Self::NotFound {
            agent_uri: agent_uri.into(),
        }
    }

    /// Creates an `AlreadyRegistered` error.
    #[must_use]
    pub fn already_registered(agent_uri: impl Into<String>) -> Self {
        Self::AlreadyRegistered {
            agent_uri: agent_uri.into(),
        }
    }

    /// Creates an `Expired` error.
    #[must_use]
    pub fn expired(agent_uri: impl Into<String>) -> Self {
        Self::Expired {
            agent_uri: agent_uri.into(),
        }
    }

    /// Creates an `InvalidAttestation` error.
    #[must_use]
    pub fn invalid_attestation(agent_uri: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidAttestation {
            agent_uri: agent_uri.into(),
            reason: reason.into(),
        }
    }

    /// Creates a `CapabilityMismatch` error.
    #[must_use]
    pub fn capability_mismatch(claimed: impl Into<String>, attested: impl Into<String>) -> Self {
        Self::CapabilityMismatch {
            claimed: claimed.into(),
            attested: attested.into(),
        }
    }

    /// Creates a `KeyCapacityExceeded` error.
    #[must_use]
    pub fn key_capacity_exceeded(key: impl Into<String>, max: usize) -> Self {
        Self::KeyCapacityExceeded {
            key: key.into(),
            max,
        }
    }

    /// Creates an `Internal` error.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Returns true if this error indicates the agent was not found.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Returns true if this error indicates the registration expired.
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        matches!(self, Self::Expired { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_error_display() {
        let err = DhtError::not_found("agent://example.com/test/agent_123");
        assert!(err.to_string().contains("not found"));
        assert!(err.is_not_found());
    }

    #[test]
    fn already_registered_error_display() {
        let err = DhtError::already_registered("agent://example.com/test/agent_123");
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn expired_error_display() {
        let err = DhtError::expired("agent://example.com/test/agent_123");
        assert!(err.to_string().contains("expired"));
        assert!(err.is_expired());
    }

    #[test]
    fn no_endpoints_error_display() {
        let err = DhtError::NoEndpoints;
        assert!(err.to_string().contains("at least one endpoint"));
    }

    #[test]
    fn key_capacity_exceeded_error_display() {
        let err = DhtError::key_capacity_exceeded("abc123...", 20);
        assert!(err.to_string().contains("maximum capacity"));
        assert!(err.to_string().contains("20"));
    }
}
