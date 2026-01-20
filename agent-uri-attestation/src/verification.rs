//! Pure verification functions for formal verification support.
//!
//! This module contains pure functions that implement the core verification
//! logic for attestation tokens. These functions are designed to be:
//!
//! - **Deterministic**: Same inputs always produce the same output
//! - **Side-effect free**: No I/O, no mutation of external state
//! - **Individually verifiable**: Small enough for formal verification tools
//!
//! # Design Rationale
//!
//! By extracting verification logic into pure functions, we enable:
//! - Unit testing without mocks or test fixtures
//! - Formal verification with tools like Kani
//! - Clear documentation of security invariants
//!
//! # Security Properties
//!
//! | Function | Property Verified |
//! |----------|-------------------|
//! | [`validate_issuer`] | Token issuer equals URI trust root (exact match) |
//! | [`validate_subject`] | Token subject equals presented URI (exact match) |
//! | [`check_expiration`] | Current time is strictly less than expiration |
//! | [`capability_covers`] | Attested capability is prefix of or equals required |

use chrono::{DateTime, Utc};

use agent_uri::CapabilityPath;

use crate::error::AttestationError;

/// Pure function: checks if any attested capability covers the required path.
///
/// A capability covers a required path if:
/// - The capability exactly equals the required path, OR
/// - The capability is a prefix of the required path (hierarchical coverage)
///
/// # Arguments
///
/// * `attested_capabilities` - The capabilities granted in the attestation token
/// * `required` - The capability path required for the operation
///
/// # Returns
///
/// `true` if any attested capability covers the required path, `false` otherwise
///
/// # Examples
///
/// ```
/// use agent_uri::CapabilityPath;
/// use agent_uri_attestation::capability_covers;
///
/// let attested = vec!["workflow".to_string(), "assistant/chat".to_string()];
/// let required = CapabilityPath::parse("workflow/approval").unwrap();
///
/// // "workflow" is a prefix of "workflow/approval"
/// assert!(capability_covers(&attested, &required));
///
/// // Exact match also works
/// let exact = CapabilityPath::parse("assistant/chat").unwrap();
/// assert!(capability_covers(&attested, &exact));
/// ```
#[must_use]
pub fn capability_covers(attested_capabilities: &[String], required: &CapabilityPath) -> bool {
    attested_capabilities.iter().any(|cap| {
        let required_str = required.as_str();
        // Capability covers required if:
        // 1. They are exactly equal, OR
        // 2. Capability is a proper prefix (required starts with cap + "/")
        required_str == cap || required_str.starts_with(&format!("{cap}/"))
    })
}

/// Pure function: validates that the token issuer matches the URI trust root.
///
/// # Arguments
///
/// * `uri_trust_root` - The trust root extracted from the agent URI
/// * `token_issuer` - The issuer claim from the token
///
/// # Returns
///
/// `Ok(())` if the issuer matches, or `Err(AttestationError::TrustRootMismatch)` otherwise
///
/// # Errors
///
/// Returns `AttestationError::TrustRootMismatch` if `uri_trust_root` does not equal `token_issuer`.
///
/// # Examples
///
/// ```
/// use agent_uri_attestation::validate_issuer;
///
/// assert!(validate_issuer("acme.com", "acme.com").is_ok());
/// assert!(validate_issuer("acme.com", "evil.com").is_err());
/// ```
pub fn validate_issuer(
    uri_trust_root: &str,
    token_issuer: &str,
) -> Result<(), AttestationError> {
    if uri_trust_root == token_issuer {
        Ok(())
    } else {
        Err(AttestationError::TrustRootMismatch {
            token_root: token_issuer.to_string(),
            expected_root: uri_trust_root.to_string(),
        })
    }
}

/// Pure function: validates that the token subject matches the presented URI.
///
/// # Arguments
///
/// * `presented_uri` - The agent URI being verified, as a string
/// * `token_subject` - The `agent_uri` claim from the token
///
/// # Returns
///
/// `Ok(())` if they match, or `Err(AttestationError::UriMismatch)` otherwise
///
/// # Errors
///
/// Returns `AttestationError::UriMismatch` if `presented_uri` does not equal `token_subject`.
///
/// # Examples
///
/// ```
/// use agent_uri_attestation::validate_subject;
///
/// let uri = "agent://acme.com/workflow/agent_01h455vb4pex5vsknk084sn02q";
/// assert!(validate_subject(uri, uri).is_ok());
/// assert!(validate_subject(uri, "agent://evil.com/test/agent_xyz").is_err());
/// ```
pub fn validate_subject(
    presented_uri: &str,
    token_subject: &str,
) -> Result<(), AttestationError> {
    if presented_uri == token_subject {
        Ok(())
    } else {
        Err(AttestationError::UriMismatch {
            token_uri: token_subject.to_string(),
            expected_uri: presented_uri.to_string(),
        })
    }
}

/// Pure function: checks if a token has expired at a given time.
///
/// # Arguments
///
/// * `exp` - The expiration time from the token
/// * `now` - The current time to check against
///
/// # Returns
///
/// `Ok(())` if the token is still valid (now < exp), or
/// `Err(AttestationError::TokenExpired)` if expired (now >= exp)
///
/// # Errors
///
/// Returns `AttestationError::TokenExpired` if `now >= exp`.
///
/// # Examples
///
/// ```
/// use chrono::{Utc, Duration};
/// use agent_uri_attestation::check_expiration;
///
/// let now = Utc::now();
/// let future = now + Duration::hours(1);
/// let past = now - Duration::hours(1);
///
/// assert!(check_expiration(future, now).is_ok());
/// assert!(check_expiration(past, now).is_err());
/// assert!(check_expiration(now, now).is_err()); // Boundary: now >= exp is expired
/// ```
pub fn check_expiration(exp: DateTime<Utc>, now: DateTime<Utc>) -> Result<(), AttestationError> {
    if now < exp {
        Ok(())
    } else {
        Err(AttestationError::TokenExpired {
            expired_at: exp.to_rfc3339(),
        })
    }
}

/// Pure function: checks capability coverage and returns a structured error if insufficient.
///
/// # Arguments
///
/// * `attested_capabilities` - The capabilities from the token
/// * `required` - The required capability path
///
/// # Returns
///
/// `Ok(())` if capabilities are sufficient, or
/// `Err(AttestationError::InsufficientCapabilities)` if not
///
/// # Errors
///
/// Returns `AttestationError::InsufficientCapabilities` if no attested capability covers
/// the required path.
///
/// # Examples
///
/// ```
/// use agent_uri::CapabilityPath;
/// use agent_uri_attestation::check_capability_coverage;
///
/// let attested = vec!["workflow".to_string()];
/// let required = CapabilityPath::parse("workflow/approval").unwrap();
/// assert!(check_capability_coverage(&attested, &required).is_ok());
///
/// let unrelated = CapabilityPath::parse("assistant/chat").unwrap();
/// assert!(check_capability_coverage(&attested, &unrelated).is_err());
/// ```
pub fn check_capability_coverage(
    attested_capabilities: &[String],
    required: &CapabilityPath,
) -> Result<(), AttestationError> {
    if capability_covers(attested_capabilities, required) {
        Ok(())
    } else {
        Err(AttestationError::InsufficientCapabilities {
            required: required.to_string(),
            attested: attested_capabilities.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod capability_covers_tests {
        use super::*;

        #[test]
        fn exact_match_is_covered() {
            let attested = vec!["workflow/approval".to_string()];
            let required = CapabilityPath::parse("workflow/approval").unwrap();
            assert!(capability_covers(&attested, &required));
        }

        #[test]
        fn prefix_covers_child_path() {
            let attested = vec!["workflow".to_string()];
            let required = CapabilityPath::parse("workflow/approval").unwrap();
            assert!(capability_covers(&attested, &required));
        }

        #[test]
        fn prefix_covers_grandchild_path() {
            let attested = vec!["workflow".to_string()];
            let required = CapabilityPath::parse("workflow/approval/invoice").unwrap();
            assert!(capability_covers(&attested, &required));
        }

        #[test]
        fn sibling_path_not_covered() {
            let attested = vec!["workflow/approval".to_string()];
            let required = CapabilityPath::parse("workflow/rejection").unwrap();
            assert!(!capability_covers(&attested, &required));
        }

        #[test]
        fn unrelated_path_not_covered() {
            let attested = vec!["assistant/chat".to_string()];
            let required = CapabilityPath::parse("workflow/approval").unwrap();
            assert!(!capability_covers(&attested, &required));
        }

        #[test]
        fn empty_capabilities_cover_nothing() {
            let attested: Vec<String> = vec![];
            let required = CapabilityPath::parse("workflow").unwrap();
            assert!(!capability_covers(&attested, &required));
        }

        #[test]
        fn reverse_prefix_not_covered() {
            // "workflow/approval" does NOT cover "workflow"
            let attested = vec!["workflow/approval".to_string()];
            let required = CapabilityPath::parse("workflow").unwrap();
            assert!(!capability_covers(&attested, &required));
        }

        #[test]
        fn partial_segment_match_not_covered() {
            // "work" should NOT cover "workflow"
            let attested = vec!["work".to_string()];
            let required = CapabilityPath::parse("workflow").unwrap();
            assert!(!capability_covers(&attested, &required));
        }

        #[test]
        fn multiple_capabilities_any_covers() {
            let attested = vec![
                "assistant/chat".to_string(),
                "workflow".to_string(),
                "storage/read".to_string(),
            ];
            let required = CapabilityPath::parse("workflow/approval").unwrap();
            assert!(capability_covers(&attested, &required));
        }
    }

    mod issuer_validation_tests {
        use super::*;

        #[test]
        fn exact_match_succeeds() {
            assert!(validate_issuer("acme.com", "acme.com").is_ok());
        }

        #[test]
        fn mismatch_fails() {
            let result = validate_issuer("acme.com", "evil.com");
            assert!(matches!(
                result,
                Err(AttestationError::TrustRootMismatch { .. })
            ));
        }

        #[test]
        fn case_difference_fails() {
            // Issuers are case-sensitive
            let result = validate_issuer("acme.com", "ACME.COM");
            assert!(matches!(
                result,
                Err(AttestationError::TrustRootMismatch { .. })
            ));
        }

        #[test]
        fn with_port_exact_match() {
            assert!(validate_issuer("localhost:8472", "localhost:8472").is_ok());
        }
    }

    mod subject_validation_tests {
        use super::*;

        #[test]
        fn exact_match_succeeds() {
            let uri = "agent://acme.com/workflow/agent_01h455vb4pex5vsknk084sn02q";
            assert!(validate_subject(uri, uri).is_ok());
        }

        #[test]
        fn mismatch_fails() {
            let presented = "agent://acme.com/workflow/agent_01h455vb4pex5vsknk084sn02q";
            let token_sub = "agent://acme.com/other/agent_01h455vb4pex5vsknk084sn02q";
            let result = validate_subject(presented, token_sub);
            assert!(matches!(result, Err(AttestationError::UriMismatch { .. })));
        }
    }

    mod expiration_tests {
        use super::*;
        use chrono::Duration;

        #[test]
        fn future_expiration_is_valid() {
            let now = Utc::now();
            let exp = now + Duration::hours(1);
            assert!(check_expiration(exp, now).is_ok());
        }

        #[test]
        fn exact_expiration_is_expired() {
            let now = Utc::now();
            let result = check_expiration(now, now);
            assert!(matches!(result, Err(AttestationError::TokenExpired { .. })));
        }

        #[test]
        fn past_expiration_is_expired() {
            let now = Utc::now();
            let exp = now - Duration::hours(1);
            let result = check_expiration(exp, now);
            assert!(matches!(result, Err(AttestationError::TokenExpired { .. })));
        }

        #[test]
        fn one_second_before_expiration_is_valid() {
            let exp = Utc::now() + Duration::seconds(1);
            let now = exp - Duration::seconds(1);
            assert!(check_expiration(exp, now).is_ok());
        }
    }

    mod check_capability_coverage_tests {
        use super::*;

        #[test]
        fn returns_ok_when_covered() {
            let attested = vec!["workflow".to_string()];
            let required = CapabilityPath::parse("workflow/approval").unwrap();
            assert!(check_capability_coverage(&attested, &required).is_ok());
        }

        #[test]
        fn returns_err_with_details_when_not_covered() {
            let attested = vec!["assistant/chat".to_string()];
            let required = CapabilityPath::parse("workflow/approval").unwrap();
            let result = check_capability_coverage(&attested, &required);
            match result {
                Err(AttestationError::InsufficientCapabilities {
                    required: req,
                    attested: att,
                }) => {
                    assert_eq!(req, "workflow/approval");
                    assert_eq!(att, vec!["assistant/chat".to_string()]);
                }
                _ => panic!("Expected InsufficientCapabilities error"),
            }
        }
    }
}
