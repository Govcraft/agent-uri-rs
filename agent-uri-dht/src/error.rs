//! Custom error types for DHT operations.

use std::fmt;
use std::time::Duration;

use crate::MutationKind;

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
    /// An existing agent identifier was presented under a different capability path.
    IdentityCapabilityConflict {
        /// Stable trust-root and agent-ID identity key
        identity: String,
        /// Capability path already bound to the identity
        existing_path: String,
        /// New conflicting capability path
        requested_path: String,
    },
    /// Too many agents already hold the capability path being registered.
    ///
    /// The key named is the one the registration derives from its own path.
    /// A crowded ancestor never produces this: an agent is charged for the key
    /// it chose, not for the subtree it happens to fall inside.
    KeyCapacityExceeded {
        /// The DHT key that is at capacity
        key: String,
        /// Maximum allowed registrations
        max: usize,
    },
    /// The endpoints list is empty.
    NoEndpoints,
    /// The write presented no valid proof that the agent's key holder
    /// authorized it.
    Unauthorized {
        /// The agent URI whose record the write targeted
        agent_uri: String,
        /// The operation that was refused
        operation: MutationKind,
    },
    /// The attestation names a different agent key than the registration.
    AgentKeyMismatch {
        /// The agent URI whose registration was refused
        agent_uri: String,
    },
    /// A node refused to store the record.
    ///
    /// Distinct from the variants that name a specific defect. A distributed
    /// backend applies checks the in-process index has no reason to: whether a
    /// record's lifetime is one this node will hold, whether its encoding is
    /// one this node speaks. Collapsing those into `InvalidAttestation` would
    /// send an operator looking at trust roots for a clock problem.
    Rejected {
        /// The agent URI whose record was refused
        agent_uri: String,
        /// Why the node refused it
        reason: String,
    },
    /// The write's sequence number did not advance past the record's.
    ///
    /// Either the write is a replay of one already applied, or two writers are
    /// racing against the same record.
    StaleSequence {
        /// The agent URI whose record the write targeted
        agent_uri: String,
        /// The sequence number the write presented
        presented: u64,
        /// The sequence number the record already holds
        current: u64,
    },
    /// The operation did not complete within its deadline.
    Timeout {
        /// The operation that timed out
        operation: &'static str,
        /// How long the operation was given
        after: Duration,
    },
    /// Too few replicas answered to satisfy the requested quorum.
    QuorumFailed {
        /// Replicas that answered
        achieved: usize,
        /// Replicas the requested quorum needed
        required: usize,
    },
    /// The node is not connected to any peer that can serve the operation.
    NoPeers,
    /// The local node cannot serve the request at all.
    ///
    /// Distinct from [`DhtError::NoPeers`], which describes the overlay. This
    /// describes the node the caller is holding: it has shut down, or its own
    /// store will not take the record. Retrying against the same handle will
    /// fail the same way.
    Unavailable {
        /// What is wrong with this node
        reason: String,
    },
}

impl fmt::Display for DhtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { agent_uri } => write!(
                f,
                "agent '{agent_uri}' not found in DHT; verify the URI is correct and the agent \
                 is registered"
            ),
            Self::AlreadyRegistered { agent_uri } => write!(
                f,
                "agent '{agent_uri}' is already registered; use update_endpoint to modify the \
                 registration"
            ),
            Self::Expired { agent_uri } => write!(
                f,
                "registration for agent '{agent_uri}' has expired; re-register to restore"
            ),
            Self::InvalidAttestation { agent_uri, reason } => {
                write!(f, "invalid attestation for agent '{agent_uri}': {reason}")
            }
            Self::IdentityCapabilityConflict {
                identity,
                existing_path,
                requested_path,
            } => write!(
                f,
                "agent identity '{identity}' is already bound to capability path \
                 '{existing_path}' and cannot be reused at '{requested_path}'; mint a new agent ID"
            ),
            Self::KeyCapacityExceeded { key, max } => write!(
                f,
                "DHT key '{key}' has reached maximum capacity of {max} registrations"
            ),
            Self::NoEndpoints => write!(f, "registration must have at least one endpoint"),
            Self::Unauthorized {
                agent_uri,
                operation,
            } => write!(
                f,
                "{operation} on agent '{agent_uri}' was not authorized by the agent key bound \
                 to its registration; the proof must be signed by that key over this exact \
                 operation"
            ),
            Self::AgentKeyMismatch { agent_uri } => write!(
                f,
                "the attestation presented for agent '{agent_uri}' attests a different key \
                 than the registration names; a token attests one agent's key and cannot be \
                 presented for another"
            ),
            Self::Rejected { agent_uri, reason } => write!(
                f,
                "a node refused to store the record for agent '{agent_uri}': {reason}"
            ),
            Self::StaleSequence {
                agent_uri,
                presented,
                current,
            } => write!(
                f,
                "write to agent '{agent_uri}' presented sequence {presented}, which does not \
                 advance past the record's {current}; re-read the registration and sign a \
                 higher sequence"
            ),
            Self::Timeout { operation, after } => write!(
                f,
                "{operation} did not complete within {after:?}; the network may be slow or \
                 partitioned, and the operation may still have taken effect"
            ),
            Self::QuorumFailed { achieved, required } => write!(
                f,
                "only {achieved} of the {required} replicas required by the requested quorum \
                 responded; the operation may have partially applied"
            ),
            Self::NoPeers => write!(
                f,
                "not connected to any peer; bootstrap against a known peer before issuing \
                 operations"
            ),
            Self::Unavailable { reason } => {
                write!(f, "this DHT node cannot serve the request: {reason}")
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

    /// Creates an `Unavailable` error.
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    /// Creates a `Rejected` error.
    #[must_use]
    pub fn rejected(agent_uri: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Rejected {
            agent_uri: agent_uri.into(),
            reason: reason.into(),
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

    /// Returns true if retrying the operation could plausibly succeed.
    ///
    /// Transient failures describe the network, not the request: the same call
    /// against a healthier overlay may succeed. Every other variant rejects the
    /// request itself and will keep rejecting it.
    ///
    /// A transient failure is not proof the operation did not take effect. A
    /// write that timed out may have reached some replicas, so retries must be
    /// safe to repeat.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. } | Self::QuorumFailed { .. } | Self::NoPeers
        )
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

    #[test]
    fn timeout_error_display_warns_the_write_may_have_landed() {
        let err = DhtError::Timeout {
            operation: "register",
            after: Duration::from_secs(30),
        };
        let shown = err.to_string();
        assert!(shown.contains("register"));
        assert!(shown.contains("may still have taken effect"));
    }

    #[test]
    fn quorum_failed_error_reports_both_counts() {
        let err = DhtError::QuorumFailed {
            achieved: 3,
            required: 11,
        };
        let shown = err.to_string();
        assert!(shown.contains('3'));
        assert!(shown.contains("11"));
    }

    #[test]
    fn no_peers_error_points_at_bootstrap() {
        assert!(DhtError::NoPeers.to_string().contains("bootstrap"));
    }

    #[test]
    fn network_failures_are_transient() {
        assert!(
            DhtError::Timeout {
                operation: "lookup",
                after: Duration::from_secs(1)
            }
            .is_transient()
        );
        assert!(
            DhtError::QuorumFailed {
                achieved: 1,
                required: 2
            }
            .is_transient()
        );
        assert!(DhtError::NoPeers.is_transient());
    }

    #[test]
    fn request_rejections_are_not_transient() {
        // Retrying these is pure waste: the request itself is the problem.
        assert!(!DhtError::NoEndpoints.is_transient());
        assert!(!DhtError::not_found("agent://a.com/b/c_1").is_transient());
        assert!(!DhtError::already_registered("agent://a.com/b/c_1").is_transient());
        assert!(!DhtError::expired("agent://a.com/b/c_1").is_transient());
        assert!(!DhtError::invalid_attestation("agent://a.com/b/c_1", "bad").is_transient());
        assert!(!DhtError::key_capacity_exceeded("k", 1).is_transient());
        // A node that refused a record refuses it again: the record is the
        // problem, not the path to the node.
        assert!(!DhtError::rejected("agent://a.com/b/c_1", "expiry too far ahead").is_transient());
        // A node that has shut down does not come back; the caller needs a new
        // one, not another attempt against this one.
        assert!(!DhtError::unavailable("the node has shut down").is_transient());
        assert!(
            !DhtError::AgentKeyMismatch {
                agent_uri: "agent://a.com/b/c_1".to_string()
            }
            .is_transient()
        );
        // Retrying an unauthorized write with the same proof is pure waste, and
        // a stale sequence needs a fresh signature rather than a repeat.
        assert!(
            !DhtError::Unauthorized {
                agent_uri: "agent://a.com/b/c_1".to_string(),
                operation: MutationKind::Deregister,
            }
            .is_transient()
        );
        assert!(
            !DhtError::StaleSequence {
                agent_uri: "agent://a.com/b/c_1".to_string(),
                presented: 1,
                current: 4,
            }
            .is_transient()
        );
    }

    #[test]
    fn unauthorized_error_names_the_refused_operation() {
        let err = DhtError::Unauthorized {
            agent_uri: "agent://a.com/b/c_1".to_string(),
            operation: MutationKind::UpdateEndpoint,
        };
        let shown = err.to_string();
        assert!(shown.contains("update_endpoint"));
        assert!(shown.contains("agent://a.com/b/c_1"));
        assert!(shown.contains("agent key"));
    }

    #[test]
    fn agent_key_mismatch_error_says_the_token_is_someone_elses() {
        let err = DhtError::AgentKeyMismatch {
            agent_uri: "agent://a.com/b/c_1".to_string(),
        };
        let shown = err.to_string();
        assert!(shown.contains("agent://a.com/b/c_1"));
        assert!(shown.contains("different key"));
    }

    #[test]
    fn rejected_error_carries_the_nodes_reason() {
        let err = DhtError::rejected("agent://a.com/b/c_1", "record expiry is in the past");
        let shown = err.to_string();
        assert!(shown.contains("agent://a.com/b/c_1"));
        assert!(shown.contains("record expiry is in the past"));
    }

    #[test]
    fn unavailable_error_names_the_local_node_not_the_overlay() {
        let err = DhtError::unavailable("the node has shut down");
        assert!(err.to_string().contains("this DHT node"));
        assert!(err.to_string().contains("shut down"));
    }

    #[test]
    fn stale_sequence_error_reports_both_sequences() {
        let err = DhtError::StaleSequence {
            agent_uri: "agent://a.com/b/c_1".to_string(),
            presented: 3,
            current: 9,
        };
        let shown = err.to_string();
        assert!(shown.contains('3'));
        assert!(shown.contains('9'));
    }
}
