//! Integration tests for agent-uri-attestation.

use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::{
    AttestationClaimsBuilder, AttestationError, Issuer, SigningKey, Verifier, VerifyingKey,
};

fn test_uri() -> AgentUri {
    AgentUri::parse("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q").unwrap()
}

#[test]
fn round_trip_issue_and_verify() {
    // Arrange
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
    let uri = test_uri();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key.verifying_key());

    // Act
    let token = issuer
        .issue(&uri, vec!["workflow.approval.read".into()])
        .unwrap();
    let claims = verifier.verify(&token).unwrap();

    // Assert
    assert_eq!(claims.agent_uri, uri.to_string());
    assert_eq!(claims.iss, "acme.com");
    assert_eq!(claims.capabilities, vec!["workflow.approval.read"]);
    assert!(!claims.is_expired());
}

#[test]
fn verify_for_uri_matches() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
    let uri = test_uri();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key.verifying_key());

    let token = issuer.issue(&uri, vec![]).unwrap();
    let claims = verifier.verify_for_uri(&token, &uri).unwrap();

    assert_eq!(claims.agent_uri, uri.to_string());
}

#[test]
fn verify_for_uri_rejects_mismatch() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
    let uri1 = test_uri();
    let uri2 =
        AgentUri::parse("agent://acme.com/workflow/other/rule_01h455vb4pex5vsknk084sn02q").unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key.verifying_key());

    let token = issuer.issue(&uri1, vec![]).unwrap();
    let result = verifier.verify_for_uri(&token, &uri2);

    assert!(matches!(result, Err(AttestationError::UriMismatch { .. })));
}

#[test]
fn rejects_untrusted_issuer() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("evil.com", signing_key.clone(), Duration::from_secs(3600));
    let uri = AgentUri::parse("agent://evil.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q")
        .unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key.verifying_key());

    let token = issuer.issue(&uri, vec![]).unwrap();
    let result = verifier.verify(&token);

    // Token signed by key we know, but issuer claim doesn't match
    assert!(matches!(
        result,
        Err(AttestationError::TrustRootMismatch { .. })
    ));
}

#[test]
fn rejects_invalid_signature() {
    let signing_key1 = SigningKey::generate();
    let signing_key2 = SigningKey::generate();

    let issuer = Issuer::new("acme.com", signing_key1, Duration::from_secs(3600));
    let uri = test_uri();

    let mut verifier = Verifier::new();
    // Register different key than what signed the token
    verifier.add_trusted_root("acme.com", signing_key2.verifying_key());

    let token = issuer.issue(&uri, vec![]).unwrap();
    let result = verifier.verify(&token);

    // Wrong key should result in either InvalidSignature or InvalidTokenFormat
    // (depending on how PASETO reports the error)
    assert!(
        matches!(
            result,
            Err(AttestationError::InvalidSignature) | Err(AttestationError::InvalidTokenFormat { .. })
        ),
        "Expected InvalidSignature or InvalidTokenFormat, got {:?}",
        result
    );
}

#[test]
fn expired_token_rejected() {
    let signing_key = SigningKey::generate();
    // Issue with very short TTL
    let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_millis(1));
    let uri = test_uri();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key.verifying_key());

    let token = issuer.issue(&uri, vec![]).unwrap();

    // Small delay to ensure expiration
    std::thread::sleep(Duration::from_millis(50));

    let result = verifier.verify(&token);

    assert!(
        matches!(result, Err(AttestationError::TokenExpired { .. })),
        "Expected TokenExpired, got {:?}",
        result
    );
}

#[test]
fn claims_builder_requires_agent_uri() {
    let result = AttestationClaimsBuilder::new().issuer("acme.com").build();

    assert!(matches!(
        result,
        Err(AttestationError::MissingField { field: "agent_uri" })
    ));
}

#[test]
fn claims_builder_requires_issuer() {
    let result = AttestationClaimsBuilder::new()
        .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
        .build();

    assert!(matches!(
        result,
        Err(AttestationError::MissingField { field: "issuer" })
    ));
}

#[test]
fn multiple_capabilities() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
    let uri = test_uri();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key.verifying_key());

    let capabilities = vec![
        "workflow.approval.read".to_string(),
        "workflow.approval.execute".to_string(),
        "workflow.approval.admin".to_string(),
    ];

    let token = issuer.issue(&uri, capabilities.clone()).unwrap();
    let claims = verifier.verify(&token).unwrap();

    assert_eq!(claims.capabilities, capabilities);
}

#[test]
fn signing_key_generates_valid_verifying_key() {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Should be able to roundtrip through bytes
    let bytes = verifying_key.to_bytes();
    let recovered = VerifyingKey::from_bytes(&bytes).unwrap();

    assert_eq!(verifying_key, recovered);
}

#[test]
fn signing_key_from_bytes_roundtrip() {
    let signing_key = SigningKey::generate();
    let bytes = signing_key.to_bytes();
    let recovered = SigningKey::from_bytes(&bytes).unwrap();

    // Verify they produce the same public key
    assert_eq!(
        signing_key.verifying_key().to_bytes(),
        recovered.verifying_key().to_bytes()
    );
}

#[test]
fn token_with_audience() {
    let signing_key = SigningKey::generate();
    let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));

    let claims = AttestationClaimsBuilder::new()
        .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
        .issuer("acme.com")
        .audience("api.acme.com")
        .build()
        .unwrap();

    let token = issuer.issue_claims(&claims).unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key.verifying_key());

    let verified_claims = verifier.verify(&token).unwrap();

    assert_eq!(verified_claims.aud, Some("api.acme.com".to_string()));
}

#[test]
fn issuer_generate_creates_working_issuer() {
    let issuer = Issuer::generate("acme.com", Duration::from_secs(3600));
    let uri = test_uri();

    let token = issuer.issue(&uri, vec!["read".into()]).unwrap();

    // Should be able to verify with the issuer's own public key
    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", issuer.verifying_key());

    let claims = verifier.verify(&token).unwrap();
    assert_eq!(claims.agent_uri, uri.to_string());
}

#[test]
fn multiple_trusted_roots() {
    let signing_key1 = SigningKey::generate();
    let signing_key2 = SigningKey::generate();

    let issuer1 = Issuer::new("acme.com", signing_key1.clone(), Duration::from_secs(3600));
    let issuer2 = Issuer::new("other.com", signing_key2.clone(), Duration::from_secs(3600));

    let uri1 = test_uri();
    let uri2 =
        AgentUri::parse("agent://other.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();

    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", signing_key1.verifying_key());
    verifier.add_trusted_root("other.com", signing_key2.verifying_key());

    // Both tokens should verify
    let token1 = issuer1.issue(&uri1, vec![]).unwrap();
    let token2 = issuer2.issue(&uri2, vec![]).unwrap();

    assert!(verifier.verify(&token1).is_ok());
    assert!(verifier.verify(&token2).is_ok());
}

#[test]
fn trust_root_extraction_from_claims() {
    let claims = AttestationClaimsBuilder::new()
        .agent_uri("agent://acme.com:8080/test/agent_01h455vb4pex5vsknk084sn02q")
        .issuer("acme.com:8080")
        .build()
        .unwrap();

    assert_eq!(claims.trust_root(), Some("acme.com:8080"));
}

#[test]
fn verifier_tracks_trusted_root_count() {
    let mut verifier = Verifier::new();
    assert_eq!(verifier.trusted_root_count(), 0);

    verifier.add_trusted_root("acme.com", SigningKey::generate().verifying_key());
    assert_eq!(verifier.trusted_root_count(), 1);

    verifier.add_trusted_root("other.com", SigningKey::generate().verifying_key());
    assert_eq!(verifier.trusted_root_count(), 2);
}

#[test]
fn verifier_checks_trusted_root_existence() {
    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", SigningKey::generate().verifying_key());

    assert!(verifier.has_trusted_root("acme.com"));
    assert!(!verifier.has_trusted_root("other.com"));
}
