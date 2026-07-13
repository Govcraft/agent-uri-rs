//! Decoding a PASETO v4.public token *without* verifying its signature.
//!
//! # Security
//!
//! The claims this module returns are **attacker-controlled**. Anyone can mint a
//! token carrying any claims they like; only a signature check by
//! [`agent_uri_attestation::Verifier`] makes claims trustworthy.
//!
//! These claims are used for exactly two things, neither of which is a trust
//! decision:
//!
//! 1. `attest inspect`, whose entire job is to describe a token nobody trusts.
//! 2. *Explaining* a refusal that the verifier already returned. The verifier
//!    reports `TokenExpired` without the expiry instant; decoding the payload
//!    recovers it so the operator is told "expired at T (3 days ago)" instead of
//!    "expired". The verdict is always the verifier's; only the prose is ours.
//!
//! Nothing here may ever be used to *reach* a verdict.

use agent_uri_attestation::AttestationClaims;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::CliError;

/// Length of the Ed25519 signature appended to a v4.public payload.
const SIGNATURE_LEN: usize = 64;

/// The header every token this tool understands must carry.
const EXPECTED_VERSION: &str = "v4";
const EXPECTED_PURPOSE: &str = "public";

/// Decodes the claims of a PASETO v4.public token without verifying its signature.
///
/// See the module docs before calling this: the result is not authenticated.
///
/// # Errors
///
/// Returns [`CliError::Refused`] when the token is not a structurally valid
/// v4.public token carrying attestation claims.
pub fn decode_unverified(token: &str) -> Result<AttestationClaims, CliError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(CliError::refused(
            "malformed_token",
            "no token supplied",
            "pass the token as an argument, or '-' to read it from stdin",
        ));
    }

    let parts: Vec<&str> = token.split('.').collect();
    // v4 . public . payload [ . footer ]
    if !matches!(parts.len(), 3 | 4) {
        return Err(CliError::refused(
            "malformed_token",
            format!(
                "token has {} dot-separated parts; a PASETO token has 3 (or 4 with a footer)",
                parts.len()
            ),
            "check the token was copied whole and not truncated or wrapped",
        ));
    }

    if parts[0] != EXPECTED_VERSION || parts[1] != EXPECTED_PURPOSE {
        return Err(CliError::refused(
            "unsupported_token",
            format!(
                "token is '{}.{}'; this tool only handles v4.public attestations",
                parts[0], parts[1]
            ),
            "supply a token minted by 'agent-uri attest issue'",
        ));
    }

    let raw = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|source| {
        CliError::refused(
            "malformed_token",
            format!("token payload is not valid base64url: {source}"),
            "check the token was copied whole, with no added whitespace or line breaks",
        )
    })?;

    // The payload is the claims JSON followed by a 64-byte Ed25519 signature.
    let claims_len = raw.len().checked_sub(SIGNATURE_LEN).filter(|len| *len > 0).ok_or_else(|| {
        CliError::refused(
            "malformed_token",
            format!(
                "token payload is {} bytes; too short to hold claims plus a {SIGNATURE_LEN}-byte signature",
                raw.len()
            ),
            "check the token was copied whole and not truncated",
        )
    })?;

    serde_json::from_slice::<AttestationClaims>(&raw[..claims_len]).map_err(|source| {
        CliError::refused(
            "invalid_claims",
            format!("token payload is not valid attestation claims: {source}"),
            "the token is a v4.public PASETO but does not carry agent attestation claims",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agent_uri::AgentUri;
    use agent_uri_attestation::{Issuer, SigningKey};

    use super::*;

    const URI: &str = "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q";

    fn mint(ttl: Duration) -> String {
        let issuer = Issuer::new("acme.com", SigningKey::generate(), ttl);
        let uri = AgentUri::parse(URI).unwrap();
        issuer
            .issue(&uri, vec!["workflow/approval/read".into()])
            .unwrap()
    }

    #[test]
    fn decodes_claims_from_a_real_token() {
        let claims = decode_unverified(&mint(Duration::from_hours(1))).unwrap();

        assert_eq!(claims.agent_uri, URI);
        assert_eq!(claims.iss, "acme.com");
        assert_eq!(claims.capabilities, vec!["workflow/approval/read"]);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn decodes_an_expired_token() {
        // The property that distinguishes inspect from verify: an expired token
        // still decodes, so the operator can see *why* it was refused.
        let claims = decode_unverified(&mint(Duration::from_secs(1))).unwrap();
        assert_eq!(claims.iss, "acme.com");
    }

    #[test]
    fn decodes_a_token_signed_by_an_unknown_key() {
        // Decoding proves nothing about trust; that is the whole point.
        let claims = decode_unverified(&mint(Duration::from_hours(1))).unwrap();
        assert_eq!(claims.agent_uri, URI);
    }

    #[test]
    fn tolerates_surrounding_whitespace() {
        let token = mint(Duration::from_hours(1));
        let padded = format!("  {token}\n");
        assert_eq!(
            decode_unverified(&padded).unwrap().iss,
            decode_unverified(&token).unwrap().iss
        );
    }

    #[test]
    fn rejects_empty_input() {
        let error = decode_unverified("   ").unwrap_err();
        assert_eq!(error.diagnosis().kind, "malformed_token");
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn rejects_a_non_token() {
        let error = decode_unverified("notatoken").unwrap_err();
        assert_eq!(error.diagnosis().kind, "malformed_token");
    }

    #[test]
    fn rejects_the_wrong_version() {
        let error = decode_unverified("v2.public.aaaa").unwrap_err();
        assert_eq!(error.diagnosis().kind, "unsupported_token");
    }

    #[test]
    fn rejects_the_wrong_purpose() {
        let error = decode_unverified("v4.local.aaaa").unwrap_err();
        assert_eq!(error.diagnosis().kind, "unsupported_token");
    }

    #[test]
    fn rejects_bad_base64() {
        let error = decode_unverified("v4.public.!!!not-base64!!!").unwrap_err();
        assert_eq!(error.diagnosis().kind, "malformed_token");
    }

    #[test]
    fn rejects_a_payload_too_short_to_hold_a_signature() {
        let payload = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let error = decode_unverified(&format!("v4.public.{payload}")).unwrap_err();

        assert_eq!(error.diagnosis().kind, "malformed_token");
        assert!(error.to_string().contains("too short"));
    }

    #[test]
    fn rejects_valid_base64_that_is_not_claims_json() {
        let mut raw = b"this is not json".to_vec();
        raw.extend_from_slice(&[0u8; SIGNATURE_LEN]);
        let payload = URL_SAFE_NO_PAD.encode(&raw);

        let error = decode_unverified(&format!("v4.public.{payload}")).unwrap_err();
        assert_eq!(error.diagnosis().kind, "invalid_claims");
    }

    #[test]
    fn accepts_a_token_with_a_footer() {
        let token = mint(Duration::from_hours(1));
        let footer = URL_SAFE_NO_PAD.encode(b"kid-1");
        let with_footer = format!("{token}.{footer}");

        assert_eq!(decode_unverified(&with_footer).unwrap().iss, "acme.com");
    }
}
