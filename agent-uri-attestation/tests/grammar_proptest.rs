//! Property-based tests validating grammar.abnf specification.
//!
//! These tests generate random valid claims and verify they round-trip
//! through issue/verify, ensuring the grammar accurately describes
//! all valid tokens.

use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::{AttestationClaimsBuilder, Issuer, SigningKey, Verifier};
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
