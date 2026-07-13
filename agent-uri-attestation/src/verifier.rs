//! Token verifier for validating attestations.

use std::collections::HashMap;

use agent_uri::AgentUri;
use chrono::Utc;
use rusty_paseto::core::{Paseto, PasetoError};
use rusty_paseto::prelude::*;

use agent_uri::CapabilityPath;

use crate::claims::AttestationClaims;
use crate::error::AttestationError;
use crate::keys::VerifyingKey;
use crate::verification;

/// Verifies attestation tokens for agent URIs.
///
/// The verifier maintains a set of trusted roots and their public keys,
/// validating that tokens were issued by authorized parties.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{Issuer, Verifier, SigningKey};
/// use agent_uri::AgentUri;
/// use std::time::Duration;
///
/// // Create an issuer
/// let signing_key = SigningKey::generate();
/// let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
///
/// // Issue a token
/// let uri = AgentUri::parse(
///     "agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q"
/// ).unwrap();
/// let token = issuer.issue(&uri, vec!["test".into()]).unwrap();
///
/// // Create a verifier with the issuer's public key
/// let mut verifier = Verifier::new();
/// verifier.add_trusted_root("acme.com", signing_key.verifying_key());
///
/// // Verify the token
/// let claims = verifier.verify(&token).unwrap();
/// assert_eq!(claims.iss, "acme.com");
/// ```
#[derive(Debug, Clone, Default)]
pub struct Verifier {
    trusted_roots: HashMap<String, VerifyingKey>,
}

impl Verifier {
    /// Creates a new verifier with no trusted roots.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a trusted root and its public key.
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The trust root identifier (e.g., "acme.com")
    /// * `public_key` - The Ed25519 public key for this trust root
    pub fn add_trusted_root(&mut self, trust_root: impl Into<String>, public_key: VerifyingKey) {
        self.trusted_roots.insert(trust_root.into(), public_key);
    }

    /// Returns true if the given trust root is registered.
    #[must_use]
    pub fn has_trusted_root(&self, trust_root: &str) -> bool {
        self.trusted_roots.contains_key(trust_root)
    }

    /// Returns the number of registered trusted roots.
    #[must_use]
    pub fn trusted_root_count(&self) -> usize {
        self.trusted_roots.len()
    }

    /// Verifies an attestation token and returns its claims.
    ///
    /// This method:
    /// 1. Parses the PASETO token
    /// 2. Verifies the signature using the issuer's public key
    /// 3. Checks expiration
    /// 4. Validates the issuer is trusted
    /// 5. Binds the authenticated issuer to the attested URI's namespace
    ///
    /// # Issuer/namespace binding
    ///
    /// Step 5 is the security-critical check. Authenticating `iss` (steps 2-4)
    /// only proves *which trusted key* signed the token; it does not stop a key
    /// trusted for one authority from minting an attestation for a URI rooted at
    /// a *different* authority. This method therefore requires that `iss` equals
    /// the trust root (authority) parsed from the `agent_uri` claim, and fails
    /// closed (rejects) if that authority cannot be parsed. Because every
    /// higher-level verification path funnels through `verify`, this binding is
    /// enforced uniformly.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if verification fails for any reason:
    /// - `InvalidSignature` - Signature doesn't match any trusted key
    /// - `TokenExpired` - Token has passed its expiration time
    /// - `UntrustedIssuer` - Issuer is not in the trusted roots set
    /// - `IssuerNamespaceMismatch` - Issuer does not own the URI's namespace
    /// - `InvalidTokenFormat` - Token is malformed
    /// - `InvalidClaims` - Claims cannot be parsed
    pub fn verify(&self, token: &str) -> Result<AttestationClaims, AttestationError> {
        self.verify_with_audience_context(token, None)
    }

    /// Verifies a token for a specific verifier audience.
    ///
    /// Audience-restricted tokens are accepted only when `verifier_audience`
    /// exactly matches their `aud` claim. Unrestricted tokens are accepted for
    /// any audience.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::verify`], plus
    /// [`AttestationError::AudienceMismatch`] for a non-matching audience.
    pub fn verify_for_audience(
        &self,
        token: &str,
        verifier_audience: &str,
    ) -> Result<AttestationClaims, AttestationError> {
        self.verify_with_audience_context(token, Some(verifier_audience))
    }

    fn verify_with_audience_context(
        &self,
        token: &str,
        verifier_audience: Option<&str>,
    ) -> Result<AttestationClaims, AttestationError> {
        if self.trusted_roots.is_empty() {
            return Err(AttestationError::UntrustedIssuer {
                issuer: "unknown".to_string(),
            });
        }

        // Try each trusted key until one works
        let (issuer, claims) = self.extract_and_verify(token)?;

        // Validate issuer is trusted (already verified by finding the key)
        if !self.trusted_roots.contains_key(&issuer) {
            return Err(AttestationError::UntrustedIssuer { issuer });
        }

        // Bind the authenticated issuer to the attested URI's namespace.
        // The issuer must equal the trust root (authority) of the `agent_uri`
        // claim. Fail closed when the authority cannot be parsed.
        if claims.trust_root() != Some(claims.iss.as_str()) {
            return Err(AttestationError::IssuerNamespaceMismatch {
                issuer: claims.iss.clone(),
                uri_trust_root: claims.trust_root().unwrap_or_default().to_string(),
            });
        }

        verification::validate_capability_scope(&claims.agent_uri, &claims.capabilities)?;
        verification::validate_audience(claims.aud.as_deref(), verifier_audience)?;

        Ok(claims)
    }

    /// Verifies a token and checks it matches the expected agent URI.
    ///
    /// # Arguments
    ///
    /// * `token` - The PASETO token to verify
    /// * `expected_uri` - The agent URI that should be attested
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if:
    /// - Token verification fails (including `IssuerNamespaceMismatch` when the
    ///   issuer does not own the attested URI's namespace)
    /// - The token's `agent_uri` doesn't match `expected_uri`
    pub fn verify_for_uri(
        &self,
        token: &str,
        expected_uri: &AgentUri,
    ) -> Result<AttestationClaims, AttestationError> {
        // `verify` already binds `iss` to the `agent_uri` claim's trust root, so
        // an authenticated token's authority is guaranteed to equal its own
        // issuer here. Comparing the full `agent_uri` to `expected_uri` is the
        // only remaining, load-bearing check.
        let claims = self.verify(token)?;

        let expected_str = expected_uri.canonical();
        let token_uri = AgentUri::parse(&claims.agent_uri).map_err(|error| {
            AttestationError::InvalidClaims {
                reason: format!("invalid agent_uri claim: {error}"),
            }
        })?;
        if token_uri.canonical() != expected_str {
            return Err(AttestationError::UriMismatch {
                token_uri: claims.agent_uri.clone(),
                expected_uri: expected_str,
            });
        }

        Ok(claims)
    }

    /// Verifies a token, canonical subject URI, and verifier audience.
    ///
    /// # Errors
    ///
    /// Returns an error when signature, claims, audience, or subject validation
    /// fails.
    pub fn verify_for_uri_and_audience(
        &self,
        token: &str,
        expected_uri: &AgentUri,
        verifier_audience: &str,
    ) -> Result<AttestationClaims, AttestationError> {
        let claims = self.verify_for_audience(token, verifier_audience)?;
        let token_uri = AgentUri::parse(&claims.agent_uri).map_err(|error| {
            AttestationError::InvalidClaims {
                reason: format!("invalid agent_uri claim: {error}"),
            }
        })?;
        if token_uri.canonical() != expected_uri.canonical() {
            return Err(AttestationError::UriMismatch {
                token_uri: claims.agent_uri.clone(),
                expected_uri: expected_uri.canonical(),
            });
        }
        Ok(claims)
    }

    /// Verifies a token, checks URI match, AND validates capability coverage.
    ///
    /// This is the most comprehensive verification method, performing:
    /// 1. Signature verification using trusted keys
    /// 2. Expiration check
    /// 3. Issuer validation against trusted roots
    /// 4. Issuer/namespace binding (`iss` owns the attested URI's authority)
    /// 5. URI match verification
    /// 6. Capability coverage verification
    ///
    /// # Arguments
    ///
    /// * `token` - The PASETO token to verify
    /// * `uri` - The agent URI that should be attested
    /// * `required_capability` - The capability path required for the operation
    ///
    /// # Returns
    ///
    /// The verified `AttestationClaims` if all checks pass
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if any verification step fails:
    /// - `InvalidSignature` - Signature doesn't match any trusted key
    /// - `TokenExpired` - Token has passed its expiration time
    /// - `UntrustedIssuer` - Issuer is not in the trusted roots set
    /// - `IssuerNamespaceMismatch` - Issuer does not own the attested URI's namespace
    /// - `UriMismatch` - Token's `agent_uri` doesn't match expected URI
    /// - `InsufficientCapabilities` - Token capabilities don't cover required path
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUri;
    /// use agent_uri::CapabilityPath;
    /// use agent_uri_attestation::{Issuer, Verifier, SigningKey};
    /// use std::time::Duration;
    ///
    /// let signing_key = SigningKey::generate();
    /// let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
    ///
    /// let uri = AgentUri::parse(
    ///     "agent://acme.com/workflow/approval/agent_01h455vb4pex5vsknk084sn02q"
    /// ).unwrap();
    /// let token = issuer.issue(&uri, vec!["workflow/approval".into()]).unwrap();
    ///
    /// let mut verifier = Verifier::new();
    /// verifier.add_trusted_root("acme.com", signing_key.verifying_key());
    ///
    /// // "workflow" capability covers "workflow/approval"
    /// let required = CapabilityPath::parse("workflow/approval").unwrap();
    /// let claims = verifier.verify_for_capability(&token, &uri, &required).unwrap();
    ///
    /// assert_eq!(claims.iss, "acme.com");
    /// ```
    pub fn verify_for_capability(
        &self,
        token: &str,
        uri: &AgentUri,
        required_capability: &CapabilityPath,
    ) -> Result<AttestationClaims, AttestationError> {
        if !required_capability.starts_with(uri.capability_path()) {
            return Err(AttestationError::CapabilityOutsideIdentity {
                identity_path: uri.capability_path().as_str().to_string(),
                capability: required_capability.as_str().to_string(),
            });
        }

        // First verify the token and URI match
        let claims = self.verify_for_uri(token, uri)?;

        // Then check capability coverage using pure function
        verification::check_capability_coverage(&claims.capabilities, required_capability)?;

        Ok(claims)
    }

    /// Verifies a token for a URI, required capability, and audience.
    ///
    /// # Errors
    ///
    /// Returns an error when any signature, claim, subject, capability, or
    /// audience check fails.
    pub fn verify_for_capability_and_audience(
        &self,
        token: &str,
        uri: &AgentUri,
        required_capability: &CapabilityPath,
        verifier_audience: &str,
    ) -> Result<AttestationClaims, AttestationError> {
        if !required_capability.starts_with(uri.capability_path()) {
            return Err(AttestationError::CapabilityOutsideIdentity {
                identity_path: uri.capability_path().as_str().to_string(),
                capability: required_capability.as_str().to_string(),
            });
        }
        let claims = self.verify_for_uri_and_audience(token, uri, verifier_audience)?;
        verification::check_capability_coverage(&claims.capabilities, required_capability)?;
        Ok(claims)
    }

    /// Internal method to extract issuer and verify signature.
    fn extract_and_verify(
        &self,
        token: &str,
    ) -> Result<(String, AttestationClaims), AttestationError> {
        // Try each trusted key until one works
        let mut last_error = None;

        for (trust_root, verifying_key) in &self.trusted_roots {
            match try_verify_with_key(token, verifying_key) {
                Ok(claims) => {
                    // Verify the issuer matches the key we used
                    if claims.iss == *trust_root {
                        return Ok((trust_root.clone(), claims));
                    }
                    // Issuer mismatch - this key signed it but claims different issuer
                    last_error = Some(AttestationError::TrustRootMismatch {
                        token_root: claims.iss.clone(),
                        expected_root: trust_root.clone(),
                    });
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(AttestationError::UntrustedIssuer {
            issuer: "unknown".to_string(),
        }))
    }
}

/// Classifies a PASETO failure by its cause rather than by its message text.
///
/// The failure modes fall into two groups, and conflating them misleads callers:
///
/// - **Structural**: the string is not a well-formed v4.public token at all
///   (wrong header, bad base64, truncated). Nothing was verified because there
///   was nothing to verify.
/// - **Cryptographic**: the token is well-formed, but its signature does not
///   check out under this key. The token was tampered with, or this is simply
///   the wrong key for it.
///
/// Everything not explicitly structural is treated as a signature failure, so a
/// new cipher-side variant fails closed rather than being reported as a
/// malformed token.
fn classify_paseto_error(error: &PasetoError) -> AttestationError {
    match error {
        PasetoError::IncorrectSize
        | PasetoError::WrongHeader
        | PasetoError::FooterInvalid
        | PasetoError::PayloadBase64Decode { .. }
        | PasetoError::Utf8Error { .. }
        | PasetoError::FromUtf8Error { .. }
        | PasetoError::TryFromSlice { .. } => AttestationError::InvalidTokenFormat {
            reason: error.to_string(),
        },
        PasetoError::InvalidKey => AttestationError::InvalidKeyFormat {
            reason: error.to_string(),
        },
        _ => AttestationError::InvalidSignature,
    }
}

/// Try to verify a token with a specific key.
///
/// Verification happens in two stages, in this order, and the order is what
/// makes the resulting error trustworthy:
///
/// 1. **Signature.** [`Paseto::try_verify`] authenticates the payload and hands
///    it back. Until this succeeds the payload is attacker-controlled, so no
///    claim in it may be believed, let alone reported.
/// 2. **Claims.** Only then are the (now authenticated) claims parsed and their
///    validity window checked, via the pure [`verification::check_expiration`].
///
/// That second stage is why `TokenExpired` can name the instant a token lapsed:
/// by then, `exp` has been authenticated, so reporting it is safe.
fn try_verify_with_key(
    token: &str,
    verifying_key: &VerifyingKey,
) -> Result<AttestationClaims, AttestationError> {
    let key_bytes = verifying_key.to_bytes();
    let key_wrapper = Key::<32>::from(&key_bytes);
    let paseto_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&key_wrapper);

    // Stage 1: authenticate. Returns the verified payload, and validates no claims.
    let payload = Paseto::<V4, Public>::try_verify(token, &paseto_key, None, None)
        .map_err(|e| classify_paseto_error(&e))?;

    let json_value: serde_json::Value =
        serde_json::from_str(&payload).map_err(|e| AttestationError::InvalidClaims {
            reason: format!("token payload is not valid JSON: {e}"),
        })?;

    // Stage 2: the payload is authenticated, so its claims can now be believed,
    // and its validity window enforced with the real instants it carries.
    let claims = extract_claims(&json_value)?;
    verification::check_expiration(claims.exp, Utc::now())?;

    Ok(claims)
}

/// Extract `AttestationClaims` from parsed JSON value.
fn extract_claims(json: &serde_json::Value) -> Result<AttestationClaims, AttestationError> {
    let agent_uri = json["agent_uri"]
        .as_str()
        .ok_or_else(|| AttestationError::InvalidClaims {
            reason: "missing agent_uri claim".to_string(),
        })?
        .to_string();

    let capabilities: Vec<String> = json
        .get("capabilities")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let iss = json["iss"]
        .as_str()
        .ok_or_else(|| AttestationError::InvalidClaims {
            reason: "missing iss claim".to_string(),
        })?
        .to_string();

    let iat = json["iat"]
        .as_str()
        .ok_or_else(|| AttestationError::InvalidClaims {
            reason: "missing iat claim".to_string(),
        })?;
    let iat = chrono::DateTime::parse_from_rfc3339(iat)
        .map_err(|e| AttestationError::InvalidClaims {
            reason: format!("invalid iat format: {e}"),
        })?
        .with_timezone(&Utc);

    let exp = json["exp"]
        .as_str()
        .ok_or_else(|| AttestationError::InvalidClaims {
            reason: "missing exp claim".to_string(),
        })?;
    let exp = chrono::DateTime::parse_from_rfc3339(exp)
        .map_err(|e| AttestationError::InvalidClaims {
            reason: format!("invalid exp format: {e}"),
        })?
        .with_timezone(&Utc);

    let aud = json.get("aud").and_then(|v| v.as_str()).map(String::from);

    Ok(AttestationClaims {
        agent_uri,
        capabilities,
        iss,
        iat,
        exp,
        aud,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::issuer::Issuer;
    use crate::keys::SigningKey;

    fn test_uri() -> AgentUri {
        AgentUri::parse("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap()
    }

    #[test]
    fn verifier_starts_empty() {
        let verifier = Verifier::new();
        assert_eq!(verifier.trusted_root_count(), 0);
        assert!(!verifier.has_trusted_root("acme.com"));
    }

    #[test]
    fn add_trusted_root() {
        let mut verifier = Verifier::new();
        let signing_key = SigningKey::generate();

        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert_eq!(verifier.trusted_root_count(), 1);
        assert!(verifier.has_trusted_root("acme.com"));
        assert!(!verifier.has_trusted_root("other.com"));
    }

    /// Corrupts a token's payload so that its decoded bytes definitely change.
    ///
    /// Flipping the *last* base64 character is not enough: the final character of
    /// a base64url payload can carry "don't care" bits that decode to the same
    /// bytes, leaving the signature intact and the test passing by accident. A
    /// character in the middle of the payload always lands on a full 6-bit group.
    fn tamper(token: &str) -> String {
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        let payload = &mut parts[2];

        let midpoint = payload.len() / 2;
        let original = payload.as_bytes()[midpoint] as char;
        let replacement = if original == 'a' { 'b' } else { 'a' };
        payload.replace_range(midpoint..=midpoint, &replacement.to_string());

        parts.join(".")
    }

    /// Signs claims verbatim, so tests can mint tokens outside the validity window.
    fn issue_raw(signing_key: &SigningKey, claims: &AttestationClaims) -> String {
        Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1))
            .issue_claims(claims)
            .unwrap()
    }

    /// Claims for `acme.com`, with a caller-chosen validity window.
    fn claims_valid_for(
        iat: chrono::DateTime<Utc>,
        exp: chrono::DateTime<Utc>,
    ) -> AttestationClaims {
        AttestationClaims {
            agent_uri: test_uri().to_string(),
            capabilities: vec!["test".into()],
            iss: "acme.com".into(),
            iat,
            exp,
            aud: None,
        }
    }

    #[test]
    fn a_tampered_token_is_reported_as_an_invalid_signature() {
        // Regression: the failure was classified by substring-matching the PASETO
        // error text for "signature". The cipher error says "A paseto cipher error
        // occurred", so this arm never fired and every tampered token surfaced as
        // InvalidTokenFormat, sending callers hunting for a copy-paste error.
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let token = issuer.issue(&test_uri(), vec!["test".into()]).unwrap();

        let tampered = tamper(&token);

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert_eq!(
            verifier.verify(&tampered),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn a_token_signed_by_another_key_is_reported_as_an_invalid_signature() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key, Duration::from_hours(1));
        let token = issuer.issue(&test_uri(), vec!["test".into()]).unwrap();

        // The right authority, but the wrong key registered for it.
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", SigningKey::generate().verifying_key());

        assert_eq!(
            verifier.verify(&token),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn a_malformed_token_is_reported_as_an_invalid_format() {
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", SigningKey::generate().verifying_key());

        // Structurally not a token: nothing was verified because there was nothing
        // to verify, and that is a different problem from a bad signature.
        assert!(matches!(
            verifier.verify("not-a-token"),
            Err(AttestationError::InvalidTokenFormat { .. })
        ));
    }

    #[test]
    fn an_expired_token_reports_the_instant_it_expired() {
        // Regression: `expired_at` was always the literal string "unknown", so a
        // caller could say only "expired", never "expired at T".
        let signing_key = SigningKey::generate();
        let now = Utc::now();
        let expired_at = now - chrono::Duration::days(3);
        let claims = claims_valid_for(now - chrono::Duration::days(4), expired_at);

        let token = issue_raw(&signing_key, &claims);

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        match verifier.verify(&token) {
            Err(AttestationError::TokenExpired {
                expired_at: reported,
            }) => {
                assert_ne!(reported, "unknown", "the real instant must be carried");

                // It is the token's own exp, to the second, and it round-trips.
                let parsed = chrono::DateTime::parse_from_rfc3339(&reported)
                    .expect("expired_at must be RFC 3339")
                    .with_timezone(&Utc);
                assert_eq!(parsed.timestamp(), expired_at.timestamp());
            }
            other => panic!("expected TokenExpired, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_expired_token_is_a_signature_failure_first() {
        // Precedence matters: claims are only believed after they are
        // authenticated. An attacker must not be able to steer the error message
        // by forging an expiry, so the signature check comes first.
        let signing_key = SigningKey::generate();
        let now = Utc::now();
        let claims = claims_valid_for(
            now - chrono::Duration::days(4),
            now - chrono::Duration::days(3),
        );

        let tampered = tamper(&issue_raw(&signing_key, &claims));

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert_eq!(
            verifier.verify(&tampered),
            Err(AttestationError::InvalidSignature),
            "an unauthenticated payload's exp must never be reported"
        );
    }

    #[test]
    fn a_token_inside_its_window_still_verifies() {
        let signing_key = SigningKey::generate();
        let now = Utc::now();
        let claims = claims_valid_for(
            now - chrono::Duration::hours(1),
            now + chrono::Duration::hours(1),
        );

        let token = issue_raw(&signing_key, &claims);

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert!(verifier.verify(&token).is_ok());
    }

    #[test]
    fn verify_valid_token() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec!["test".into()]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let claims = verifier.verify(&token).unwrap();

        assert_eq!(claims.agent_uri, uri.to_string());
        assert_eq!(claims.iss, "acme.com");
        assert_eq!(claims.capabilities, vec!["test"]);
    }

    #[test]
    fn verify_rejects_untrusted_issuer() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("evil.com", signing_key.clone(), Duration::from_hours(1));
        let uri =
            AgentUri::parse("agent://evil.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();

        let token = issuer.issue(&uri, vec![]).unwrap();

        let mut verifier = Verifier::new();
        // Register key under different trust root
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let result = verifier.verify(&token);

        // Token signed by key we know, but issuer claim doesn't match
        assert!(matches!(
            result,
            Err(AttestationError::TrustRootMismatch { .. })
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signing_key1 = SigningKey::generate();
        let signing_key2 = SigningKey::generate();

        let issuer = Issuer::new("acme.com", signing_key1, Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec![]).unwrap();

        let mut verifier = Verifier::new();
        // Register different key
        verifier.add_trusted_root("acme.com", signing_key2.verifying_key());

        let result = verifier.verify(&token);

        // Wrong key should result in either InvalidSignature or InvalidTokenFormat
        // (depending on how PASETO reports the error)
        assert!(
            matches!(
                result,
                Err(AttestationError::InvalidSignature
                    | AttestationError::InvalidTokenFormat { .. })
            ),
            "Expected InvalidSignature or InvalidTokenFormat, got {result:?}",
        );
    }

    #[test]
    fn verify_for_uri_matches() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec![]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let claims = verifier.verify_for_uri(&token, &uri).unwrap();

        assert_eq!(claims.agent_uri, uri.to_string());
    }

    #[test]
    fn verify_for_uri_rejects_mismatch() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri1 = test_uri();
        let uri2 =
            AgentUri::parse("agent://acme.com/other/agent_01h455vb4pex5vsknk084sn02q").unwrap();

        let token = issuer.issue(&uri1, vec![]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let result = verifier.verify_for_uri(&token, &uri2);

        assert!(matches!(result, Err(AttestationError::UriMismatch { .. })));
    }

    #[test]
    fn verify_empty_verifier_returns_untrusted() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key, Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec![]).unwrap();

        let verifier = Verifier::new();

        let result = verifier.verify(&token);

        assert!(matches!(
            result,
            Err(AttestationError::UntrustedIssuer { .. })
        ));
    }

    #[test]
    fn verify_rejects_cross_root_issuance() {
        // A key trusted as authority "acme.com" mints an attestation for a URI
        // rooted at a *different* authority "evil.com". The issuer claim is
        // authentic (matches the registered trust root), but it does not own the
        // attested URI's namespace, so every verification path must reject it.
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));

        let foreign_uri =
            AgentUri::parse("agent://evil.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();
        let token = issuer.issue(&foreign_uri, vec!["test".into()]).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        // verify
        assert!(
            matches!(
                verifier.verify(&token),
                Err(AttestationError::IssuerNamespaceMismatch { .. })
            ),
            "verify should reject cross-root issuance"
        );

        // verify_for_uri (even when the caller's expected URI matches the token)
        assert!(
            matches!(
                verifier.verify_for_uri(&token, &foreign_uri),
                Err(AttestationError::IssuerNamespaceMismatch { .. })
            ),
            "verify_for_uri should reject cross-root issuance"
        );

        // verify_for_capability
        let required = CapabilityPath::parse("test").unwrap();
        assert!(
            matches!(
                verifier.verify_for_capability(&token, &foreign_uri, &required),
                Err(AttestationError::IssuerNamespaceMismatch { .. })
            ),
            "verify_for_capability should reject cross-root issuance"
        );
    }

    #[test]
    fn verify_for_capability_same_root_still_accepts() {
        // Regression: legitimate same-root attestations still verify end to end.
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri =
            AgentUri::parse("agent://acme.com/workflow/approval/agent_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let token = issuer
            .issue(&uri, vec!["workflow/approval".into()])
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let required = CapabilityPath::parse("workflow/approval").unwrap();

        assert!(verifier.verify(&token).is_ok());
        assert!(verifier.verify_for_uri(&token, &uri).is_ok());
        let claims = verifier
            .verify_for_capability(&token, &uri, &required)
            .unwrap();
        assert_eq!(claims.iss, "acme.com");
    }

    #[test]
    fn verify_rejects_unparseable_agent_uri() {
        // Fail closed: when the `agent_uri` claim has no parseable authority,
        // `trust_root()` is `None` and verification must reject rather than skip
        // the issuer/namespace binding.
        let result = AttestationClaims::builder()
            .agent_uri("not-an-agent-uri")
            .issuer("acme.com")
            .ttl(Duration::from_hours(1))
            .build();
        assert!(matches!(
            result,
            Err(AttestationError::InvalidClaims { .. })
        ));
    }

    #[test]
    fn audience_restricted_token_requires_matching_verifier() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();
        let claims = AttestationClaims::builder()
            .agent_uri(uri.canonical())
            .issuer("acme.com")
            .add_capability("test")
            .audience("api.globex.com")
            .build()
            .unwrap();
        let token = issuer.issue_claims(&claims).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert!(matches!(
            verifier.verify(&token),
            Err(AttestationError::AudienceMismatch { .. })
        ));
        assert!(matches!(
            verifier.verify_for_audience(&token, "api.evil.com"),
            Err(AttestationError::AudienceMismatch { .. })
        ));
        assert!(
            verifier
                .verify_for_uri_and_audience(&token, &uri, "api.globex.com")
                .is_ok()
        );
    }

    #[test]
    fn broader_or_unrelated_capabilities_are_rejected() {
        let uri =
            AgentUri::parse("agent://acme.com/workflow/approval/agent_01h455vb4pex5vsknk084sn02q")
                .unwrap();

        for capability in ["workflow", "financial/payment", "workflow/review"] {
            let result = AttestationClaims::builder()
                .agent_uri(uri.canonical())
                .issuer("acme.com")
                .add_capability(capability)
                .build();
            assert!(matches!(
                result,
                Err(AttestationError::CapabilityOutsideIdentity { .. })
            ));
        }

        assert!(
            AttestationClaims::builder()
                .agent_uri(uri.canonical())
                .issuer("acme.com")
                .add_capability("workflow/approval/invoice")
                .build()
                .is_ok()
        );
    }

    #[test]
    fn verify_multiple_capabilities() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();

        let capabilities = vec![
            "test/read".to_string(),
            "test/write".to_string(),
            "test/admin".to_string(),
        ];
        let token = issuer.issue(&uri, capabilities.clone()).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let claims = verifier.verify(&token).unwrap();

        assert_eq!(claims.capabilities, capabilities);
    }
}
