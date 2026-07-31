//! Conformance suite over the canonical test vectors' attestation sections.
//!
//! `test-vectors.json` at the workspace root is the artifact third parties
//! validate their implementations against. This suite runs `capability_coverage`
//! and `attestation_verification` against this crate's verification functions,
//! so the file and the code cannot drift apart unnoticed.
//!
//! # What these vectors do and do not cover
//!
//! The vectors carry claim sets and a `current_time`, not signed tokens, so the
//! subject here is claim verification: the checks [`Verifier`] performs once a
//! signature has been established, in the order it performs them, at the instant
//! each vector names. Signature verification has no vector to check against —
//! there is no key material in the file — and is covered by this crate's own
//! suite. Driving the checks from the vector's `current_time` rather than the
//! wall clock is what makes an expiry boundary testable at all.
//!
//! [`Verifier`]: agent_uri_attestation::Verifier

use agent_uri::{AgentUri, CapabilityPath};
use agent_uri_attestation::{
    AttestationClaims, AttestationError, VerifyingKey, capability_covers,
    check_capability_coverage, check_validity_window, validate_audience, validate_capability_scope,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors.json");
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("cannot parse {path}: {error}"))
}

fn section<'a>(doc: &'a Value, name: &str) -> &'a [Value] {
    let section = doc[name]
        .as_array()
        .unwrap_or_else(|| panic!("section '{name}' is missing or not an array"));
    assert!(!section.is_empty(), "section '{name}' is empty");
    section
}

fn report(name: &str, failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} vector(s) in section '{name}' disagree with this crate:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

#[test]
fn capability_coverage_vectors() {
    let doc = load();
    let mut failures = Vec::new();

    for case in section(&doc, "capability_coverage") {
        let id = case["id"].as_str().unwrap_or("<no id>");
        let (Some(path), Some(expected)) = (case["path"].as_str(), case["covered"].as_bool())
        else {
            failures.push(format!("{id}: needs path and covered"));
            continue;
        };
        let Some(capabilities) = case["capabilities"].as_array() else {
            failures.push(format!("{id}: needs capabilities"));
            continue;
        };
        let capabilities: Vec<String> = capabilities
            .iter()
            .filter_map(|c| c.as_str().map(str::to_string))
            .collect();

        let Ok(required) = CapabilityPath::parse(path) else {
            failures.push(format!("{id}: path {path:?} does not parse"));
            continue;
        };

        let covered = capability_covers(&capabilities, &required);
        if covered != expected {
            failures.push(format!(
                "{id}: covered={covered}, expected {expected} ({})",
                case["description"].as_str().unwrap_or("")
            ));
        }
        // The structured check must agree with the predicate it wraps.
        if check_capability_coverage(&capabilities, &required).is_ok() != covered {
            failures.push(format!("{id}: check_capability_coverage disagrees"));
        }
    }

    report("capability_coverage", &failures);
}

/// The vocabulary the vectors use for a rejection, mapped onto this crate's
/// errors.
fn error_type_of(error: &AttestationError) -> &'static str {
    match error {
        AttestationError::MissingField { .. } => "missing_claim",
        AttestationError::InvalidClaims { .. } => "invalid_claims",
        AttestationError::InvalidKeyFormat { .. } => "invalid_key_format",
        AttestationError::TrustRootMismatch { .. }
        | AttestationError::IssuerNamespaceMismatch { .. } => "issuer_mismatch",
        AttestationError::UriMismatch { .. } => "subject_mismatch",
        AttestationError::TokenExpired { .. } => "expired",
        AttestationError::TokenNotYetValid { .. } => "not_yet_valid",
        AttestationError::AudienceMismatch { .. } => "audience_mismatch",
        AttestationError::CapabilityOutsideIdentity { .. } => "capability_outside_identity",
        AttestationError::InsufficientCapabilities { .. } => "capability_not_covered",
        _ => "other",
    }
}

/// Runs the claim checks in the order `Verifier` runs them.
///
/// Order is part of the contract: when an input has more than one fault, the
/// one reported is the one the first failing check names.
fn verify_claims(
    claims: &Value,
    presented_uri: &str,
    verifier_audience: &str,
    now: DateTime<Utc>,
) -> Result<(), AttestationError> {
    // A claim set that does not deserialize is missing a REQUIRED claim or
    // carries one of the wrong shape.
    let claims: AttestationClaims = serde_json::from_value(claims.clone()).map_err(|error| {
        let reason = error.to_string();
        if let Some(field) = missing_field_name(&reason) {
            AttestationError::MissingField { field }
        } else {
            AttestationError::InvalidClaims { reason }
        }
    })?;

    // Callers act on the attested key, so it has to be a key.
    VerifyingKey::from_base64(&claims.agent_key)?;

    // The issuer must own the namespace of the URI it attests.
    if claims.trust_root() != Some(claims.iss.as_str()) {
        return Err(AttestationError::IssuerNamespaceMismatch {
            issuer: claims.iss.clone(),
            uri_trust_root: claims.trust_root().unwrap_or_default().to_string(),
        });
    }

    validate_capability_scope(&claims.agent_uri, &claims.capabilities)?;
    validate_audience(claims.aud.as_deref(), Some(verifier_audience))?;
    check_validity_window(claims.iat, claims.exp, now, Duration::zero())?;

    // Subject match is against the canonical form of both URIs, so a presented
    // URI that differs only where case folds still names the same agent.
    let presented =
        AgentUri::parse(presented_uri).map_err(|error| AttestationError::InvalidClaims {
            reason: format!("invalid presented URI: {error}"),
        })?;
    let subject =
        AgentUri::parse(&claims.agent_uri).map_err(|error| AttestationError::InvalidClaims {
            reason: format!("invalid agent_uri claim: {error}"),
        })?;
    if presented.canonical() != subject.canonical() {
        return Err(AttestationError::UriMismatch {
            token_uri: claims.agent_uri.clone(),
            expected_uri: presented.canonical(),
        });
    }

    check_capability_coverage(&claims.capabilities, presented.capability_path())
}

/// Recovers the field name from serde's "missing field `x`" message.
///
/// Claims are a fixed struct, so an absent REQUIRED claim reaches us as a
/// deserialization error rather than as a typed one.
fn missing_field_name(reason: &str) -> Option<&'static str> {
    const FIELDS: [&str; 6] = [
        "agent_uri",
        "agent_key",
        "capabilities",
        "iss",
        "iat",
        "exp",
    ];
    FIELDS
        .into_iter()
        .find(|field| reason.starts_with(&format!("missing field `{field}`")))
}

#[test]
fn attestation_verification_vectors() {
    let doc = load();
    let mut failures = Vec::new();

    for case in section(&doc, "attestation_verification") {
        let id = case["id"].as_str().unwrap_or("<no id>");
        let (Some(uri), Some(verifier), Some(expect_valid)) = (
            case["agent_uri"].as_str(),
            case["verifier"].as_str(),
            case["valid"].as_bool(),
        ) else {
            failures.push(format!("{id}: needs agent_uri, verifier, and valid"));
            continue;
        };
        let Some(now) = case["current_time"]
            .as_str()
            .and_then(|t| t.parse::<DateTime<Utc>>().ok())
        else {
            failures.push(format!("{id}: needs an RFC 3339 current_time"));
            continue;
        };
        if case["claims"].is_null() {
            failures.push(format!("{id}: needs claims"));
            continue;
        }

        match (
            verify_claims(&case["claims"], uri, verifier, now),
            expect_valid,
        ) {
            (Ok(()), true) => {}
            (Err(error), false) => {
                let expected = case["error_type"].as_str().unwrap_or("<none>");
                let actual = error_type_of(&error);
                if actual != expected {
                    failures.push(format!("{id}: {actual} != expected {expected} ({error})"));
                }
            }
            (Ok(()), false) => failures.push(format!("{id}: accepted, expected rejection")),
            (Err(error), true) => failures.push(format!("{id}: rejected ({error})")),
        }
    }

    report("attestation_verification", &failures);
}
