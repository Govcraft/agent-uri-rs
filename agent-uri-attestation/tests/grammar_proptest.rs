//! Property-based tests validating grammar.abnf specification.
//!
//! These tests generate random valid claims and verify they round-trip
//! through issue/verify, ensuring the grammar accurately describes
//! all valid tokens.
//!
//! # Integration Roundtrip Tests
//!
//! This module also includes integration tests that verify the full
//! issue/verify roundtrip with randomly generated valid agent URIs
//! and capabilities. These tests ensure the proven verification logic
//! composes correctly with real PASETO crypto.

use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::{
    AttestationClaimsBuilder, AttestationError, Issuer, SigningKey, Verifier,
};
use proptest::prelude::*;

// ============================================================================
// STRATEGY DEFINITIONS
// ============================================================================

/// Generate valid capability strings per grammar.abnf
///
/// Grammar: cap-start cap-char{0,126} [cap-end]
/// - cap-start = LOWER
/// - cap-char = LOWER / DIGIT / "." / "-" / "_" / ":"
/// - cap-end = LOWER / DIGIT
fn capability_strategy() -> impl Strategy<Value = String> {
    // Generate capabilities with format: lowercase start, valid middle chars, valid end
    prop::string::string_regex("[a-z][a-z0-9._:-]{0,125}[a-z0-9]?")
        .expect("valid regex")
        .prop_filter("capability must be 1-128 chars", |s| {
            !s.is_empty() && s.len() <= 128
        })
}

/// Generate valid trust root strings per grammar.abnf (simple domains)
fn trust_root_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z]{2,10}\\.[a-z]{2,4}").expect("valid regex")
}

/// Generate valid agent URI path segments
fn path_segment_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9-]{0,30}")
        .expect("valid regex")
        .prop_filter("segment must be 1-64 chars", |s| {
            !s.is_empty() && s.len() <= 64
        })
}

/// Generate valid audience strings per grammar.abnf
fn audience_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z]{2,10}\\.[a-z]{2,10}").expect("valid regex")
}

// ============================================================================
// INTEGRATION TEST STRATEGIES
// ============================================================================

/// Generate a valid parsed AgentUri instance.
///
/// Uses simpler strategies than the exhaustive grammar tests to:
/// 1. Reduce test case rejection rate
/// 2. Focus on integration testing, not grammar edge cases
/// 3. Keep test execution time reasonable
fn valid_agent_uri_strategy() -> impl Strategy<Value = AgentUri> {
    // Simple domain: 2-8 lowercase letters + TLD
    let domain = prop::string::string_regex("[a-z]{2,8}\\.[a-z]{2,4}").expect("valid regex");

    // Capability path: 1-4 segments, each 2-8 chars
    let segment = prop::string::string_regex("[a-z][a-z0-9-]{1,7}").expect("valid regex");
    let path = prop::collection::vec(segment, 1..=4).prop_map(|segs| segs.join("/"));

    // Agent ID: valid type class + TypeID suffix
    // TypeID suffix: first char 0-7, rest are base32 (excludes i, l, o, u)
    let type_class = prop::sample::select(vec![
        "llm", "rule", "human", "composite", "sensor", "actuator",
    ]);
    let suffix =
        prop::string::string_regex("[0-7][0-9a-hjkmnp-tv-z]{25}").expect("valid base32 suffix");
    let agent_id = (type_class, suffix).prop_map(|(cls, suf)| format!("{cls}_{suf}"));

    (domain, path, agent_id).prop_filter_map("URI must parse", |(d, p, id)| {
        let uri_str = format!("agent://{d}/{p}/{id}");
        AgentUri::parse(&uri_str).ok()
    })
}

/// Generate optional additional (non-covering) capabilities.
///
/// These capabilities use a distinctive prefix ("zzz") that will not
/// accidentally match typical test URIs, ensuring they don't affect
/// capability coverage tests.
fn noise_capabilities() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop::string::string_regex("zzz[a-z]{2,5}[0-9]{1,2}").expect("valid noise capability"),
        0..3,
    )
}

/// Build a capability list that covers the path at the given prefix depth.
///
/// Given a URI with capability path "a/b/c" and prefix_depth=2,
/// this returns ["a/b"] plus any noise capabilities.
///
/// # Arguments
///
/// * `uri` - The agent URI whose capability path should be covered
/// * `prefix_depth` - How many segments of the path to include (1 = root only)
/// * `noise` - Additional non-covering capabilities to include
fn build_covering_capabilities(
    uri: &AgentUri,
    prefix_depth: usize,
    noise: Vec<String>,
) -> Vec<String> {
    let segments: Vec<&str> = uri
        .capability_path()
        .segments()
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Clamp prefix_depth to valid range
    let depth = prefix_depth.min(segments.len()).max(1);
    let prefix = segments[..depth].join("/");

    let mut caps = vec![prefix];
    caps.extend(noise);
    caps
}

// ============================================================================
// PROPTEST TESTS
// ============================================================================

proptest! {
    /// Tokens with random valid capabilities round-trip through issue/verify
    #[test]
    fn token_roundtrip_with_random_capabilities(
        caps in prop::collection::vec(capability_strategy(), 0..10)
    ) {
        // Setup
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("test.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = AgentUri::parse(
            "agent://test.com/test/service/llm_01h455vb4pex5vsknk084sn02q"
        ).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("test.com", signing_key.verifying_key());

        // Issue token
        let token = issuer.issue(&uri, caps.clone()).unwrap();

        // Verify token starts with correct header (per grammar: paseto-header = "v4.public")
        prop_assert!(token.starts_with("v4.public."), "token must start with v4.public.");

        // Verify round-trip
        let claims = verifier.verify(&token).unwrap();
        prop_assert_eq!(claims.capabilities, caps);
    }

    /// Capability strings match grammar format
    #[test]
    fn capability_format_matches_grammar(cap in capability_strategy()) {
        // Per grammar: cap-start cap-char{0,126} [cap-end]
        prop_assert!(!cap.is_empty(), "capability must not be empty");
        prop_assert!(cap.len() <= 128, "capability max 128 chars");

        // First char must be lowercase letter (cap-start = LOWER)
        let first = cap.chars().next().unwrap();
        prop_assert!(first.is_ascii_lowercase(), "must start with lowercase");

        // All chars must be valid cap-char (LOWER / DIGIT / "." / "-" / "_" / ":")
        for ch in cap.chars() {
            prop_assert!(
                ch.is_ascii_lowercase() || ch.is_ascii_digit()
                || ch == '.' || ch == '-' || ch == '_' || ch == ':',
                "invalid char in capability: {}", ch
            );
        }
    }

    /// Empty capabilities array is valid per grammar
    #[test]
    fn empty_capabilities_roundtrip(_seed in 0u32..1000) {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("test.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = AgentUri::parse(
            "agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q"
        ).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("test.com", signing_key.verifying_key());

        let token = issuer.issue(&uri, vec![]).unwrap();
        let claims = verifier.verify(&token).unwrap();

        prop_assert!(claims.capabilities.is_empty());
    }

    /// Tokens with audience claim round-trip correctly
    #[test]
    fn token_with_audience_roundtrip(aud in audience_strategy()) {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("test.com", signing_key.clone(), Duration::from_secs(3600));

        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("test.com")
            .audience(&aud)
            .build()
            .unwrap();

        let token = issuer.issue_claims(&claims).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("test.com", signing_key.verifying_key());

        let verified = verifier.verify(&token).unwrap();
        prop_assert_eq!(verified.aud, Some(aud));
    }

    /// Issuer matches trust root in agent_uri
    #[test]
    fn issuer_matches_uri_trust_root(
        domain in trust_root_strategy(),
        segment in path_segment_strategy()
    ) {
        let uri_str = format!(
            "agent://{}/{}/llm_01h455vb4pex5vsknk084sn02q",
            domain, segment
        );

        // Parse to validate format
        if let Ok(uri) = AgentUri::parse(&uri_str) {
            let signing_key = SigningKey::generate();
            let issuer = Issuer::new(&domain, signing_key.clone(), Duration::from_secs(3600));

            let token = issuer.issue(&uri, vec![]).unwrap();

            let mut verifier = Verifier::new();
            verifier.add_trusted_root(&domain, signing_key.verifying_key());

            let claims = verifier.verify(&token).unwrap();
            prop_assert_eq!(&claims.iss, &domain);
            prop_assert_eq!(claims.trust_root(), Some(domain.as_str()));
        }
    }

    /// Multiple capabilities with various formats round-trip
    #[test]
    fn multiple_capability_formats_roundtrip(
        simple in "[a-z]{3,10}",
        dotted in "[a-z]{2,8}\\.[a-z]{2,8}\\.[a-z]{2,8}",
        with_digits in "[a-z]{2,5}[0-9]{1,3}",
    ) {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("test.com", signing_key.clone(), Duration::from_secs(3600));
        let uri = AgentUri::parse(
            "agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q"
        ).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("test.com", signing_key.verifying_key());

        let caps = vec![simple, dotted, with_digits];
        let token = issuer.issue(&uri, caps.clone()).unwrap();
        let claims = verifier.verify(&token).unwrap();

        prop_assert_eq!(claims.capabilities, caps);
    }
}

// ============================================================================
// NON-PROPTEST GRAMMAR VALIDATION TESTS
// ============================================================================

/// Validates token header format per grammar: paseto-header = "v4.public"
#[test]
fn token_header_format_is_v4_public() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("test.com", signing_key, Duration::from_secs(3600));
    let uri =
        AgentUri::parse("agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();

    let token = issuer.issue(&uri, vec![]).unwrap();

    // Per grammar: attestation-token = paseto-header "." payload [ "." footer ]
    // paseto-header = "v4.public"
    assert!(token.starts_with("v4.public."));

    // Token has at least 3 parts (v4.public.payload)
    let parts: Vec<&str> = token.split('.').collect();
    assert!(
        parts.len() >= 3,
        "token must have at least 3 dot-separated parts"
    );
    assert_eq!(parts[0], "v4");
    assert_eq!(parts[1], "public");
}

/// Validates timestamp format is ISO 8601 per grammar
#[test]
fn timestamp_format_is_iso8601() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("test.com", signing_key.clone(), Duration::from_secs(3600));
    let uri =
        AgentUri::parse("agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("test.com", signing_key.verifying_key());

    let token = issuer.issue(&uri, vec![]).unwrap();
    let claims = verifier.verify(&token).unwrap();

    // Verify iat and exp are valid timestamps
    let iat_str = claims.iat.to_rfc3339();
    let exp_str = claims.exp.to_rfc3339();

    // Per grammar: iso8601-timestamp = full-date "T" full-time
    assert!(iat_str.contains('T'), "iat must contain T separator");
    assert!(exp_str.contains('T'), "exp must contain T separator");

    // Timestamps should end with Z or have offset
    assert!(
        iat_str.ends_with('Z') || iat_str.contains('+') || iat_str.contains('-'),
        "iat must have timezone"
    );
}

/// Validates agent_uri field format matches agent-uri ABNF
#[test]
fn agent_uri_field_format() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("test.com", signing_key.clone(), Duration::from_secs(3600));
    let uri = AgentUri::parse(
        "agent://test.com/workflow/approval/rule_fsm_01h455vb4pex5vsknk084sn02q",
    )
    .unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("test.com", signing_key.verifying_key());

    let token = issuer.issue(&uri, vec![]).unwrap();
    let claims = verifier.verify(&token).unwrap();

    // agent_uri must start with "agent://" per agent-uri ABNF
    assert!(claims.agent_uri.starts_with("agent://"));

    // Must be parseable as AgentUri
    let parsed = AgentUri::parse(&claims.agent_uri).unwrap();
    assert_eq!(parsed.to_string(), claims.agent_uri);
}

/// Validates maximum capabilities per grammar constraint (64 items)
#[test]
fn max_capabilities_accepted() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("test.com", signing_key.clone(), Duration::from_secs(3600));
    let uri =
        AgentUri::parse("agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("test.com", signing_key.verifying_key());

    // Per grammar: 64 items practical limit
    let caps: Vec<String> = (0..64).map(|i| format!("cap{i}")).collect();

    let token = issuer.issue(&uri, caps.clone()).unwrap();
    let claims = verifier.verify(&token).unwrap();

    assert_eq!(claims.capabilities.len(), 64);
}

/// Validates capability string edge cases per grammar
#[test]
fn capability_string_edge_cases() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("test.com", signing_key.clone(), Duration::from_secs(3600));
    let uri =
        AgentUri::parse("agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("test.com", signing_key.verifying_key());

    // Test various valid capability formats per grammar
    let caps = vec![
        "a".to_string(),                           // Minimum: single lowercase
        "read".to_string(),                        // Simple word
        "workflow.approval.read".to_string(),      // Dotted namespace
        "admin:users:write".to_string(),           // Colon-separated
        "file-upload".to_string(),                 // Hyphenated
        "task_queue".to_string(),                  // Underscored
        "v2".to_string(),                          // Letter + digit
        "cap123".to_string(),                      // Letters + digits
        "a.b.c.d.e.f.g".to_string(),               // Deep nesting
    ];

    let token = issuer.issue(&uri, caps.clone()).unwrap();
    let claims = verifier.verify(&token).unwrap();

    assert_eq!(claims.capabilities, caps);
}

/// Validates payload uses base64url encoding per grammar
#[test]
fn token_payload_is_base64url() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("test.com", signing_key, Duration::from_secs(3600));
    let uri =
        AgentUri::parse("agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();

    let token = issuer.issue(&uri, vec!["read".into()]).unwrap();

    // Extract payload (third dot-separated part)
    let parts: Vec<&str> = token.split('.').collect();
    let payload = parts[2];

    // Per grammar: base64url-char = ALPHA / DIGIT / "-" / "_"
    // No padding characters allowed
    for ch in payload.chars() {
        assert!(
            ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
            "invalid base64url char: {ch}"
        );
    }

    // Should not contain standard base64 padding
    assert!(!payload.contains('='), "payload should not have padding");
}

/// Validates issuer matches trust root per grammar
#[test]
fn issuer_equals_trust_root() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
    let uri = AgentUri::parse(
        "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q",
    )
    .unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key.verifying_key());

    let token = issuer.issue(&uri, vec![]).unwrap();
    let claims = verifier.verify(&token).unwrap();

    // Per grammar: issuer = trust-root
    assert_eq!(claims.iss, "acme.com");
    assert_eq!(claims.trust_root(), Some("acme.com"));
}

/// Validates localhost with port as trust root
#[test]
fn localhost_with_port_trust_root() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("localhost:8472", signing_key.clone(), Duration::from_secs(3600));
    let uri = AgentUri::parse(
        "agent://localhost:8472/debug/test/llm_01h455vb4pex5vsknk084sn02q",
    )
    .unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("localhost:8472", signing_key.verifying_key());

    let token = issuer.issue(&uri, vec![]).unwrap();
    let claims = verifier.verify(&token).unwrap();

    assert_eq!(claims.iss, "localhost:8472");
    assert_eq!(claims.trust_root(), Some("localhost:8472"));
}

// ============================================================================
// INTEGRATION ROUNDTRIP TESTS
// ============================================================================
//
// These tests verify the full issue/verify roundtrip with randomly generated
// valid agent URIs and capabilities. They test that the proven verification
// logic composes correctly with real PASETO crypto.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Full integration roundtrip with real PASETO crypto.
    ///
    /// Properties verified:
    /// 1. Token issuance succeeds for valid URIs
    /// 2. Token starts with correct PASETO header
    /// 3. Verification succeeds with correct key
    /// 4. Claims match issued data
    #[test]
    fn integration_roundtrip(uri in valid_agent_uri_strategy()) {
        // Setup: generate fresh keypair
        let signing_key = SigningKey::generate();
        let trust_root = uri.trust_root().as_str().to_string();

        // Issuer bound to URI's trust root
        let issuer = Issuer::new(&trust_root, signing_key.clone(), Duration::from_secs(3600));

        // Issue token with URI's capability path as capability
        let capability = uri.capability_path().as_str().to_string();
        let token = issuer.issue(&uri, vec![capability.clone()]).unwrap();

        // Token format check
        prop_assert!(token.starts_with("v4.public."));

        // Verifier with matching trust root
        let mut verifier = Verifier::new();
        verifier.add_trusted_root(&trust_root, signing_key.verifying_key());

        // Verify succeeds
        let claims = verifier.verify(&token).unwrap();

        // Claims match
        prop_assert_eq!(claims.agent_uri, uri.to_string());
        prop_assert_eq!(claims.iss, trust_root);
        prop_assert_eq!(claims.capabilities, vec![capability]);
    }

    /// Integration roundtrip with capability coverage verification.
    ///
    /// Tests verify_for_capability with randomly generated covering capabilities.
    /// Capability coverage uses prefix semantics: a capability C covers path P if
    /// C == P or P.starts_with(C + "/").
    #[test]
    fn integration_roundtrip_with_coverage(
        uri in valid_agent_uri_strategy(),
        prefix_depth in 1usize..=4,
        noise in noise_capabilities(),
    ) {
        let signing_key = SigningKey::generate();
        let trust_root = uri.trust_root().as_str().to_string();
        let depth = uri.capability_path().depth();

        // Clamp prefix_depth to valid range for this URI
        let actual_depth = prefix_depth.min(depth);
        let capabilities = build_covering_capabilities(&uri, actual_depth, noise);

        let issuer = Issuer::new(&trust_root, signing_key.clone(), Duration::from_secs(3600));
        let token = issuer.issue(&uri, capabilities.clone()).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root(&trust_root, signing_key.verifying_key());

        // Basic verify succeeds
        let claims = verifier.verify(&token).unwrap();
        prop_assert_eq!(claims.capabilities, capabilities);

        // verify_for_uri succeeds
        let uri_claims = verifier.verify_for_uri(&token, &uri).unwrap();
        prop_assert_eq!(uri_claims.agent_uri, uri.to_string());

        // verify_for_capability succeeds (capabilities cover the path)
        let required = uri.capability_path().clone();
        let cap_claims = verifier.verify_for_capability(&token, &uri, &required).unwrap();
        prop_assert_eq!(cap_claims.iss, trust_root);
    }

    /// Verifies capability coverage at each prefix depth.
    ///
    /// For a path like "a/b/c", tests coverage with:
    /// - depth 1: "a" covers "a/b/c"
    /// - depth 2: "a/b" covers "a/b/c"
    /// - depth 3: "a/b/c" covers "a/b/c" (exact match)
    #[test]
    fn prefix_coverage_all_depths(uri in valid_agent_uri_strategy()) {
        let signing_key = SigningKey::generate();
        let trust_root = uri.trust_root().as_str().to_string();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root(&trust_root, signing_key.verifying_key());

        let segments: Vec<&str> = uri
            .capability_path()
            .segments()
            .iter()
            .map(|s| s.as_str())
            .collect();

        // Test each prefix depth
        for prefix_depth in 1..=segments.len() {
            let prefix = segments[..prefix_depth].join("/");
            let issuer = Issuer::new(&trust_root, signing_key.clone(), Duration::from_secs(3600));
            let token = issuer.issue(&uri, vec![prefix]).unwrap();

            // Must succeed - prefix always covers path
            let required = uri.capability_path().clone();
            let result = verifier.verify_for_capability(&token, &uri, &required);
            prop_assert!(
                result.is_ok(),
                "Prefix depth {} should cover path: {:?}",
                prefix_depth,
                result
            );
        }
    }

    /// Verifies that non-covering capabilities are rejected.
    ///
    /// Properties:
    /// - Token issuance and basic verify succeed
    /// - verify_for_capability fails with InsufficientCapabilities
    #[test]
    fn non_covering_capabilities_rejected(uri in valid_agent_uri_strategy()) {
        let signing_key = SigningKey::generate();
        let trust_root = uri.trust_root().as_str().to_string();

        // Issue with unrelated capability
        let issuer = Issuer::new(&trust_root, signing_key.clone(), Duration::from_secs(3600));
        let token = issuer.issue(&uri, vec!["zzz-unrelated".to_string()]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root(&trust_root, signing_key.verifying_key());

        // Basic verify succeeds
        prop_assert!(verifier.verify(&token).is_ok());

        // But capability check fails
        let required = uri.capability_path().clone();
        let result = verifier.verify_for_capability(&token, &uri, &required);
        prop_assert!(
            matches!(result, Err(AttestationError::InsufficientCapabilities { .. })),
            "Expected InsufficientCapabilities, got: {:?}",
            result
        );
    }

    /// Verifies that URI mismatch is detected.
    ///
    /// Issue token for URI A, verify against URI B -> should fail.
    #[test]
    fn uri_mismatch_detected(
        uri_a in valid_agent_uri_strategy(),
        uri_b in valid_agent_uri_strategy(),
    ) {
        // Skip if URIs happen to be identical
        prop_assume!(uri_a.to_string() != uri_b.to_string());

        let signing_key = SigningKey::generate();
        // Use uri_a's trust root for issuer
        let trust_root_a = uri_a.trust_root().as_str().to_string();
        let trust_root_b = uri_b.trust_root().as_str().to_string();

        // Both trust roots must be registered for fair test
        let mut verifier = Verifier::new();
        verifier.add_trusted_root(&trust_root_a, signing_key.verifying_key());
        if trust_root_a != trust_root_b {
            verifier.add_trusted_root(&trust_root_b, signing_key.verifying_key());
        }

        let issuer = Issuer::new(&trust_root_a, signing_key.clone(), Duration::from_secs(3600));
        let token = issuer.issue(&uri_a, vec![]).unwrap();

        // Verify against different URI should fail
        let result = verifier.verify_for_uri(&token, &uri_b);

        // Either UriMismatch or TrustRootMismatch if trust roots differ
        prop_assert!(
            matches!(
                result,
                Err(AttestationError::UriMismatch { .. })
                    | Err(AttestationError::TrustRootMismatch { .. })
            ),
            "Expected mismatch error, got: {:?}",
            result
        );
    }

    /// Verifies that wrong signing key is rejected.
    #[test]
    fn wrong_key_rejected(uri in valid_agent_uri_strategy()) {
        let signing_key_1 = SigningKey::generate();
        let signing_key_2 = SigningKey::generate();
        let trust_root = uri.trust_root().as_str().to_string();

        // Issue with key 1
        let issuer = Issuer::new(&trust_root, signing_key_1, Duration::from_secs(3600));
        let token = issuer.issue(&uri, vec![]).unwrap();

        // Verify with key 2
        let mut verifier = Verifier::new();
        verifier.add_trusted_root(&trust_root, signing_key_2.verifying_key());

        let result = verifier.verify(&token);
        prop_assert!(
            matches!(
                result,
                Err(AttestationError::InvalidSignature)
                    | Err(AttestationError::InvalidTokenFormat { .. })
            ),
            "Expected signature error, got: {:?}",
            result
        );
    }
}
