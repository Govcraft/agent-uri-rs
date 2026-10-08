//! Minting reads no clock.
//!
//! A token carries its claims and nothing else, so a caller on a simulated
//! clock, or one replaying a run, mints the same token from the same claims
//! and key every time, and a build for a target with no clock can mint at all.

use std::path::Path;
use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::{
    AcceptAll, AttestationClaims, AttestationError, Issuer, SigningKey, Verifier,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};

const ROOT: &str = "acme.com";

fn test_uri() -> AgentUri {
    AgentUri::parse("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q").unwrap()
}

fn root_key() -> SigningKey {
    SigningKey::from_bytes(&[3; 32]).unwrap()
}

fn issued() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()
}

/// Claims with nothing left to chance: a fixed `jti`, agent key and instant.
fn claims(audience: Option<&str>) -> AttestationClaims {
    let mut builder = AttestationClaims::builder()
        .jti("01h455vb4pex5vsknk084sn02q")
        .agent_uri(test_uri().canonical())
        .agent_key(&SigningKey::from_bytes(&[5; 32]).unwrap().verifying_key())
        .issuer(ROOT)
        .add_capability("workflow/approval")
        .ttl(Duration::from_hours(1));
    if let Some(audience) = audience {
        builder = builder.audience(audience);
    }
    builder.build_at(issued()).unwrap()
}

fn mint(claims: &AttestationClaims) -> String {
    Issuer::new(ROOT, root_key(), Duration::from_hours(1))
        .issue_claims(claims)
        .unwrap()
}

/// The JSON payload a v4.public token carries: the bytes before its 64-byte
/// signature.
fn payload(token: &str) -> serde_json::Value {
    let body = token.strip_prefix("v4.public.").expect("a v4.public token");
    let signed = URL_SAFE_NO_PAD.decode(body).expect("base64url");
    serde_json::from_slice(&signed[..signed.len() - 64]).expect("a JSON payload")
}

#[test]
fn the_same_claims_and_key_mint_the_same_token() {
    for audience in [None, Some("api.acme.com")] {
        let claims = claims(audience);
        let first = mint(&claims);
        // Long enough for a clock that a mint read to have moved on, even a
        // coarse one.
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(mint(&claims), first);
        assert_eq!(
            Issuer::new(ROOT, root_key(), Duration::from_secs(1))
                .issue_claims(&claims)
                .unwrap(),
            first,
            "the token is the claims and the key, not the issuer's default TTL"
        );
    }
}

#[test]
fn a_minted_token_carries_its_claims_and_no_nbf() {
    for (audience, fields) in [
        (
            None,
            &[
                "agent_key",
                "agent_uri",
                "capabilities",
                "exp",
                "iat",
                "iss",
                "jti",
            ][..],
        ),
        (
            Some("api.acme.com"),
            &[
                "agent_key",
                "agent_uri",
                "aud",
                "capabilities",
                "exp",
                "iat",
                "iss",
                "jti",
            ][..],
        ),
    ] {
        let payload = payload(&mint(&claims(audience)));
        let names: Vec<&str> = payload
            .as_object()
            .expect("a JSON object")
            .keys()
            .map(String::as_str)
            .collect();

        assert_eq!(names, fields);
        assert_eq!(payload["iat"], "2030-01-01T00:00:00.000Z");
        assert_eq!(payload["exp"], "2030-01-01T01:00:00.000Z");
    }
}

#[test]
fn a_minted_token_verifies_at_a_supplied_instant_until_it_expires() {
    let claims = claims(None);
    let token = mint(&claims);
    let mut verifier = Verifier::with_leeway(Duration::ZERO).with_revocation(AcceptAll);
    verifier.add_trusted_root(ROOT, root_key().verifying_key());

    for inside in [
        issued(),
        issued() + ChronoDuration::minutes(30),
        claims.exp - ChronoDuration::milliseconds(1),
    ] {
        assert_eq!(
            verifier
                .verify_for_uri_at(&token, &test_uri(), inside)
                .unwrap(),
            claims,
            "at {inside}"
        );
    }

    for outside in [claims.exp, claims.exp + ChronoDuration::days(1)] {
        assert!(
            matches!(
                verifier.verify_for_uri_at(&token, &test_uri(), outside),
                Err(AttestationError::TokenExpired { .. })
            ),
            "at {outside}"
        );
    }
}

/// `rusty_paseto`'s prelude builder and parser read the host clock as soon as
/// they are made: `PasetoBuilder::default()` stamps `nbf`, `iat` and `exp`
/// from it, and `PasetoParser::default()` checks against it. On
/// wasm32-unknown-unknown that read panics, and anywhere else it puts the
/// minting instant into the token. This crate signs and verifies with the
/// core `Paseto` type instead, and this guard keeps it that way.
#[test]
fn no_source_file_uses_the_clock_reading_paseto_builder_or_parser() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for (index, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            if ["PasetoBuilder", "PasetoParser", "now_utc"]
                .iter()
                .any(|name| code.contains(name))
            {
                found.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
            }
        }
    }

    assert!(found.is_empty(), "{}", found.join("\n"));
}
