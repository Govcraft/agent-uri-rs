//! Integration tests for verification functions.
//!
//! These tests verify the pure verification functions and their integration
//! with the Verifier through `verify_for_capability`.

use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri::CapabilityPath;
use agent_uri_attestation::{
    capability_covers, check_capability_coverage, check_expiration, validate_issuer,
    validate_subject, AttestationClaimsBuilder, AttestationError, Issuer, SigningKey, Verifier,
};
use chrono::{Duration as ChronoDuration, Utc};

// =============================================================================
// capability_covers tests
// =============================================================================

mod capability_coverage_tests {
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

    #[test]
    fn single_segment_exact_match() {
        let attested = vec!["workflow".to_string()];
        let required = CapabilityPath::parse("workflow").unwrap();
        assert!(capability_covers(&attested, &required));
    }

    #[test]
    fn deeply_nested_path_covered_by_root() {
        let attested = vec!["api".to_string()];
        let required = CapabilityPath::parse("api/v1/users/admin/settings").unwrap();
        assert!(capability_covers(&attested, &required));
    }
}

// =============================================================================
// check_capability_coverage tests
// =============================================================================

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

    #[test]
    fn empty_capabilities_returns_err() {
        let attested: Vec<String> = vec![];
        let required = CapabilityPath::parse("workflow").unwrap();
        let result = check_capability_coverage(&attested, &required);
        assert!(matches!(
            result,
            Err(AttestationError::InsufficientCapabilities { .. })
        ));
    }
}

// =============================================================================
// validate_issuer tests
// =============================================================================

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

    #[test]
    fn subdomain_not_equivalent() {
        // "api.acme.com" is not the same as "acme.com"
        let result = validate_issuer("acme.com", "api.acme.com");
        assert!(matches!(
            result,
            Err(AttestationError::TrustRootMismatch { .. })
        ));
    }

    #[test]
    fn error_contains_both_roots() {
        let result = validate_issuer("acme.com", "evil.com");
        match result {
            Err(AttestationError::TrustRootMismatch {
                token_root,
                expected_root,
            }) => {
                assert_eq!(token_root, "evil.com");
                assert_eq!(expected_root, "acme.com");
            }
            _ => panic!("Expected TrustRootMismatch error"),
        }
    }
}

// =============================================================================
// validate_subject tests
// =============================================================================

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

    #[test]
    fn different_agent_ids_fail() {
        let presented = "agent://acme.com/workflow/agent_01h455vb4pex5vsknk084sn02q";
        let token_sub = "agent://acme.com/workflow/agent_01h455vb4pex5vsknk084sn02r";
        let result = validate_subject(presented, token_sub);
        assert!(matches!(result, Err(AttestationError::UriMismatch { .. })));
    }

    #[test]
    fn different_trust_roots_fail() {
        let presented = "agent://acme.com/workflow/agent_01h455vb4pex5vsknk084sn02q";
        let token_sub = "agent://evil.com/workflow/agent_01h455vb4pex5vsknk084sn02q";
        let result = validate_subject(presented, token_sub);
        assert!(matches!(result, Err(AttestationError::UriMismatch { .. })));
    }

    #[test]
    fn error_contains_both_uris() {
        let presented = "agent://acme.com/workflow/agent_01h455vb4pex5vsknk084sn02q";
        let token_sub = "agent://evil.com/test/agent_xyz";
        let result = validate_subject(presented, token_sub);
        match result {
            Err(AttestationError::UriMismatch {
                token_uri,
                expected_uri,
            }) => {
                assert_eq!(token_uri, token_sub);
                assert_eq!(expected_uri, presented);
            }
            _ => panic!("Expected UriMismatch error"),
        }
    }
}

// =============================================================================
// check_expiration tests
// =============================================================================

mod expiration_tests {
    use super::*;

    #[test]
    fn future_expiration_is_valid() {
        let now = Utc::now();
        let exp = now + ChronoDuration::hours(1);
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
        let exp = now - ChronoDuration::hours(1);
        let result = check_expiration(exp, now);
        assert!(matches!(result, Err(AttestationError::TokenExpired { .. })));
    }

    #[test]
    fn one_second_before_expiration_is_valid() {
        let exp = Utc::now() + ChronoDuration::seconds(1);
        let now = exp - ChronoDuration::seconds(1);
        assert!(check_expiration(exp, now).is_ok());
    }

    #[test]
    fn one_millisecond_before_expiration_is_valid() {
        let exp = Utc::now() + ChronoDuration::milliseconds(1);
        let now = exp - ChronoDuration::milliseconds(1);
        assert!(check_expiration(exp, now).is_ok());
    }

    #[test]
    fn error_contains_expiration_time() {
        let now = Utc::now();
        let exp = now - ChronoDuration::hours(1);
        let result = check_expiration(exp, now);
        match result {
            Err(AttestationError::TokenExpired { expired_at }) => {
                // Verify the expired_at is an RFC 3339 string
                assert!(expired_at.contains("T"));
                assert!(expired_at.ends_with('Z') || expired_at.contains('+'));
            }
            _ => panic!("Expected TokenExpired error"),
        }
    }
}

// =============================================================================
// is_expired_at tests
// =============================================================================

mod is_expired_at_tests {
    use super::*;

    #[test]
    fn not_expired_at_current_time() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .ttl(Duration::from_secs(3600))
            .build()
            .unwrap();

        let now = Utc::now();
        assert!(!claims.is_expired_at(now));
    }

    #[test]
    fn expired_at_exact_expiration() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .ttl(Duration::from_secs(3600))
            .build()
            .unwrap();

        assert!(claims.is_expired_at(claims.exp));
    }

    #[test]
    fn expired_at_future_time() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .ttl(Duration::from_secs(3600))
            .build()
            .unwrap();

        let future = claims.exp + ChronoDuration::hours(1);
        assert!(claims.is_expired_at(future));
    }

    #[test]
    fn not_expired_one_second_before() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .ttl(Duration::from_secs(3600))
            .build()
            .unwrap();

        let one_second_before = claims.exp - ChronoDuration::seconds(1);
        assert!(!claims.is_expired_at(one_second_before));
    }
}

// =============================================================================
// verify_for_capability integration tests
// =============================================================================

mod verify_for_capability_tests {
    use super::*;

    fn test_uri() -> AgentUri {
        AgentUri::parse("agent://acme.com/workflow/approval/agent_01h455vb4pex5vsknk084sn02q")
            .unwrap()
    }

    #[test]
    fn succeeds_with_covering_capability() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec!["workflow".into()]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let required = CapabilityPath::parse("workflow/approval").unwrap();
        let result = verifier.verify_for_capability(&token, &uri, &required);

        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.iss, "acme.com");
    }

    #[test]
    fn succeeds_with_exact_capability() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = test_uri();

        let token = issuer
            .issue(&uri, vec!["workflow/approval".into()])
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let required = CapabilityPath::parse("workflow/approval").unwrap();
        let result = verifier.verify_for_capability(&token, &uri, &required);

        assert!(result.is_ok());
    }

    #[test]
    fn fails_with_insufficient_capability() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = test_uri();

        // Token only has "assistant/chat" capability
        let token = issuer.issue(&uri, vec!["assistant/chat".into()]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        // But we require "workflow/approval"
        let required = CapabilityPath::parse("workflow/approval").unwrap();
        let result = verifier.verify_for_capability(&token, &uri, &required);

        assert!(matches!(
            result,
            Err(AttestationError::InsufficientCapabilities { .. })
        ));
    }

    #[test]
    fn fails_with_no_capabilities() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec![]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let required = CapabilityPath::parse("workflow").unwrap();
        let result = verifier.verify_for_capability(&token, &uri, &required);

        assert!(matches!(
            result,
            Err(AttestationError::InsufficientCapabilities { .. })
        ));
    }

    #[test]
    fn expired_token_fails_before_capability_check() {
        let signing_key = SigningKey::generate();
        // Very short TTL
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_millis(1));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec!["workflow".into()]).unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(50));

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let required = CapabilityPath::parse("workflow").unwrap();
        let result = verifier.verify_for_capability(&token, &uri, &required);

        // Should fail with TokenExpired, not InsufficientCapabilities
        assert!(matches!(result, Err(AttestationError::TokenExpired { .. })));
    }

    #[test]
    fn uri_mismatch_fails_before_capability_check() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
        let uri1 = test_uri();
        let uri2 =
            AgentUri::parse("agent://acme.com/other/path/agent_01h455vb4pex5vsknk084sn02q")
                .unwrap();

        let token = issuer.issue(&uri1, vec!["workflow".into()]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        // Try to verify for different URI
        let required = CapabilityPath::parse("workflow").unwrap();
        let result = verifier.verify_for_capability(&token, &uri2, &required);

        // Should fail with UriMismatch, not InsufficientCapabilities
        assert!(matches!(result, Err(AttestationError::UriMismatch { .. })));
    }

    #[test]
    fn untrusted_issuer_fails_before_capability_check() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec!["workflow".into()]).unwrap();

        // Verifier has no trusted roots
        let verifier = Verifier::new();

        let required = CapabilityPath::parse("workflow").unwrap();
        let result = verifier.verify_for_capability(&token, &uri, &required);

        assert!(matches!(
            result,
            Err(AttestationError::UntrustedIssuer { .. })
        ));
    }

    #[test]
    fn multiple_capabilities_first_matching() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = test_uri();

        let token = issuer
            .issue(
                &uri,
                vec![
                    "storage/read".into(),
                    "workflow".into(),
                    "assistant/chat".into(),
                ],
            )
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let required = CapabilityPath::parse("workflow/approval").unwrap();
        let result = verifier.verify_for_capability(&token, &uri, &required);

        assert!(result.is_ok());
    }

    #[test]
    fn child_capability_does_not_cover_parent() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = test_uri();

        // Token has specific capability
        let token = issuer
            .issue(&uri, vec!["workflow/approval/specific".into()])
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        // Require broader capability
        let required = CapabilityPath::parse("workflow/approval").unwrap();
        let result = verifier.verify_for_capability(&token, &uri, &required);

        assert!(matches!(
            result,
            Err(AttestationError::InsufficientCapabilities { .. })
        ));
    }
}
