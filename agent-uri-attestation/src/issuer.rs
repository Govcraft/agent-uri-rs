//! Token issuer for creating attestations.

use std::time::Duration;

use agent_uri::AgentUri;
use rusty_paseto::core::Payload;
use rusty_paseto::prelude::*;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::claims::{AttestationClaims, AttestationClaimsBuilder};
use crate::error::AttestationError;
use crate::keys::{SigningKey, VerifyingKey};

/// Creates attestation tokens for agent URIs.
///
/// The issuer holds a signing key and creates PASETO v4.public tokens
/// that cryptographically bind agent URIs to capabilities.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{Issuer, SigningKey};
/// use agent_uri::AgentUri;
/// use std::time::Duration;
///
/// let signing_key = SigningKey::generate();
/// let issuer = Issuer::new("acme.com", signing_key, Duration::from_secs(86400));
///
/// let uri = AgentUri::parse(
///     "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q"
/// ).unwrap();
/// let token = issuer.issue(&uri, &SigningKey::generate().verifying_key(), vec!["workflow/approval".into()]).unwrap();
///
/// assert!(token.starts_with("v4.public."));
/// ```
#[derive(Debug, Clone)]
pub struct Issuer {
    trust_root: String,
    signing_key: SigningKey,
    default_ttl: Duration,
}

impl Issuer {
    /// Creates a new issuer.
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The trust root identifier (e.g., "acme.com")
    /// * `signing_key` - The Ed25519 signing key
    /// * `default_ttl` - Default time-to-live for issued tokens
    #[must_use]
    pub fn new(
        trust_root: impl Into<String>,
        signing_key: SigningKey,
        default_ttl: Duration,
    ) -> Self {
        Self {
            trust_root: trust_root.into(),
            signing_key,
            default_ttl,
        }
    }

    /// Generates a new issuer with a random signing key.
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The trust root identifier
    /// * `default_ttl` - Default time-to-live for issued tokens
    #[must_use]
    pub fn generate(trust_root: impl Into<String>, default_ttl: Duration) -> Self {
        Self::new(trust_root, SigningKey::generate(), default_ttl)
    }

    /// Returns the trust root this issuer represents.
    #[must_use]
    pub fn trust_root(&self) -> &str {
        &self.trust_root
    }

    /// Returns the verifying (public) key for this issuer.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the default TTL for issued tokens.
    #[must_use]
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Issues an attestation token for an agent URI.
    ///
    /// # Arguments
    ///
    /// * `uri` - The agent URI to attest
    /// * `agent_key` - The agent's own public key, which the token binds to
    /// * `capabilities` - Capabilities to grant
    ///
    /// The agent key is what stops the token from being a bearer credential.
    /// A trust root that attests a key it has not seen the agent prove
    /// possession of is vouching for whoever supplied that key.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if token creation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_uri_attestation::{Issuer, SigningKey};
    /// use agent_uri::AgentUri;
    /// use std::time::Duration;
    ///
    /// let signing_key = SigningKey::generate();
    /// let issuer = Issuer::new("acme.com", signing_key, Duration::from_secs(3600));
    ///
    /// let uri = AgentUri::parse(
    ///     "agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q"
    /// ).unwrap();
    /// let agent_key = SigningKey::generate().verifying_key();
    ///
    /// let token = issuer
    ///     .issue(&uri, &agent_key, vec!["test/read".into(), "test/write".into()])
    ///     .unwrap();
    /// ```
    pub fn issue(
        &self,
        uri: &AgentUri,
        agent_key: &VerifyingKey,
        capabilities: Vec<String>,
    ) -> Result<String, AttestationError> {
        self.issue_with_ttl(uri, agent_key, capabilities, self.default_ttl)
    }

    /// Issues an attestation token with a custom TTL.
    ///
    /// # Arguments
    ///
    /// * `uri` - The agent URI to attest
    /// * `agent_key` - The agent's own public key, which the token binds to
    /// * `capabilities` - Capabilities to grant
    /// * `ttl` - Time-to-live for this specific token
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if token creation fails.
    pub fn issue_with_ttl(
        &self,
        uri: &AgentUri,
        agent_key: &VerifyingKey,
        capabilities: Vec<String>,
        ttl: Duration,
    ) -> Result<String, AttestationError> {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri(uri.canonical())
            .agent_key(agent_key)
            .capabilities(capabilities)
            .issuer(&self.trust_root)
            .ttl(ttl)
            .build()?;

        self.issue_claims(&claims)
    }

    /// Issues a token for pre-built claims.
    ///
    /// This is useful when you need full control over the claims structure.
    ///
    /// The token carries `claims` and nothing else: minting reads no clock,
    /// and Ed25519 signing draws no randomness, so the same claims signed
    /// with the same key give the same token, byte for byte.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if token creation fails, including
    /// [`AttestationError::TokenTooLong`] when the claims produce a token over
    /// [`crate::MAX_TOKEN_LENGTH`] bytes, which the verifier would reject.
    pub fn issue_claims(&self, claims: &AttestationClaims) -> Result<String, AttestationError> {
        crate::verification::validate_capability_scope(&claims.agent_uri, &claims.capabilities)?;
        // A token whose agent key does not decode is one the verifier will
        // reject, so refuse to mint it here where the caller can still fix it.
        VerifyingKey::from_base64(&claims.agent_key)?;
        let payload = claims_payload(claims)?;

        // Signing needs the private half in a shape `rusty_paseto` accepts,
        // which means copying it out of the key that owns it. Both copies are
        // wiped when this function returns:
        //
        // - `key_bytes` is a bare `[u8; 64]`, which zeroizes nothing on its
        //   own. `Zeroizing` is what wipes it, and it has to: a private key
        //   left on the stack outlives the frame and can be read out of a core
        //   dump, a swapped page, or whatever runs on that stack next.
        // - `key_wrapper` needs no help. `rusty_paseto`'s `Key` is
        //   `#[zeroize(drop)]`, so it wipes itself.
        //
        // `paseto_key` borrows `key_wrapper` rather than copying, so it is not
        // a third copy and holds nothing to wipe.
        let dalek_key = self.signing_key.as_dalek();
        let key_bytes = Zeroizing::new(dalek_key.to_keypair_bytes());
        let key_wrapper = Key::<64>::from(&*key_bytes);
        let paseto_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_wrapper);

        let token = Paseto::<V4, Public>::builder()
            .set_payload(Payload::from(payload.as_str()))
            .try_sign(&paseto_key)
            .map_err(|e| AttestationError::InvalidTokenFormat {
                reason: e.to_string(),
            })?;

        // The verifier rejects oversized tokens outright, so minting one would
        // hand the caller a token that this crate refuses to verify. Fail here
        // instead, where the caller can still shrink the claims.
        crate::verification::check_token_length(&token)?;

        Ok(token)
    }
}

/// How a token writes `iat` and `exp`: RFC 3339 in UTC, to the millisecond.
const TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

/// The payload a token carries for `claims`, field for field.
///
/// The fields are written in this order whatever features `serde_json` is
/// built with. It is the lexicographic order earlier releases wrote them in,
/// so a payload differs from theirs only by the `nbf` those releases stamped
/// from the minting host's clock. The verifier never read `nbf`: `iat` is the
/// not-before instant.
#[derive(Serialize)]
struct ClaimsPayload<'a> {
    agent_key: &'a str,
    agent_uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<&'a str>,
    capabilities: &'a [String],
    exp: String,
    iat: String,
    iss: &'a str,
    jti: &'a str,
}

/// Writes the payload a token carries for `claims`, from the claims alone.
///
/// # Errors
///
/// [`AttestationError::InvalidClaims`] when `exp` or `iat` does not render as
/// an RFC 3339 date-time, as a year past 9999 does not, since the verifier
/// would refuse the token; [`AttestationError::InvalidTokenFormat`] if the
/// payload cannot be written.
fn claims_payload(claims: &AttestationClaims) -> Result<String, AttestationError> {
    let exp = claims.exp.format(TIMESTAMP_FORMAT).to_string();
    let iat = claims.iat.format(TIMESTAMP_FORMAT).to_string();
    ExpirationClaim::try_from(exp.as_str()).map_err(|e| AttestationError::InvalidClaims {
        reason: format!("invalid expiration: {e}"),
    })?;
    IssuedAtClaim::try_from(iat.as_str()).map_err(|e| AttestationError::InvalidClaims {
        reason: format!("invalid issued at: {e}"),
    })?;

    serde_json::to_string(&ClaimsPayload {
        agent_key: &claims.agent_key,
        agent_uri: &claims.agent_uri,
        aud: claims.aud.as_deref(),
        capabilities: &claims.capabilities,
        exp,
        iat,
        iss: &claims.iss,
        jti: &claims.jti,
    })
    .map_err(|e| AttestationError::InvalidTokenFormat {
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use chrono::{DateTime, TimeZone, Utc};

    use super::*;

    fn test_uri() -> AgentUri {
        AgentUri::parse("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap()
    }

    fn agent_key() -> VerifyingKey {
        SigningKey::from_bytes(&[7; 32]).unwrap().verifying_key()
    }

    /// Claims with every field fixed: issued at `iat`, expiring at `exp`.
    fn fixed_claims(
        iat: DateTime<Utc>,
        exp: DateTime<Utc>,
        audience: Option<&str>,
    ) -> AttestationClaims {
        AttestationClaims {
            jti: "01h455vb4pex5vsknk084sn02q".into(),
            agent_uri: test_uri().canonical(),
            agent_key: agent_key().to_base64(),
            capabilities: vec!["test/read".into(), "test/write".into()],
            iss: "acme.com".into(),
            iat,
            exp,
            aud: audience.map(Into::into),
        }
    }

    fn new_year(year: i32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn the_payload_is_the_claims_alone_in_a_fixed_order() {
        let iat = new_year(2030);
        let exp = iat + chrono::Duration::hours(1);

        assert_eq!(
            claims_payload(&fixed_claims(iat, exp, Some("api.acme.com"))).unwrap(),
            format!(
                concat!(
                    r#"{{"agent_key":"{}","#,
                    r#""agent_uri":"agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q","#,
                    r#""aud":"api.acme.com","capabilities":["test/read","test/write"],"#,
                    r#""exp":"2030-01-01T01:00:00.000Z","iat":"2030-01-01T00:00:00.000Z","#,
                    r#""iss":"acme.com","jti":"01h455vb4pex5vsknk084sn02q"}}"#,
                ),
                agent_key().to_base64()
            )
        );
    }

    #[test]
    fn a_payload_without_an_audience_writes_no_aud() {
        let iat = new_year(2030);
        let payload =
            claims_payload(&fixed_claims(iat, iat + chrono::Duration::hours(1), None)).unwrap();

        assert!(!payload.contains(r#""aud""#), "{payload}");
        assert!(
            payload.contains(r#""capabilities":["test/read","test/write"],"exp""#),
            "{payload}"
        );
    }

    #[test]
    fn a_window_that_is_not_rfc_3339_is_refused_before_signing() {
        // A year past 9999 renders as `+10000-...`, which is not RFC 3339, so
        // the verifier could never read the token back.
        let issuer = Issuer::generate("acme.com", Duration::from_hours(1));
        for (claims, says) in [
            (
                fixed_claims(new_year(2030), new_year(10_000), None),
                "invalid expiration",
            ),
            (
                fixed_claims(new_year(10_000), new_year(2030), None),
                "invalid issued at",
            ),
        ] {
            match issuer.issue_claims(&claims) {
                Err(AttestationError::InvalidClaims { reason }) => {
                    assert!(reason.starts_with(says), "{reason}");
                }
                other => panic!("Expected InvalidClaims, got {other:?}"),
            }
        }
    }

    #[test]
    fn issue_creates_valid_token() {
        let issuer = Issuer::generate("acme.com", Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer
            .issue(
                &uri,
                &SigningKey::generate().verifying_key(),
                vec!["test".into()],
            )
            .unwrap();

        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn generated_issuer_has_unique_key() {
        let issuer1 = Issuer::generate("acme.com", Duration::from_hours(1));
        let issuer2 = Issuer::generate("acme.com", Duration::from_hours(1));

        assert_ne!(
            issuer1.verifying_key().to_bytes(),
            issuer2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn issuer_trust_root_accessible() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key, Duration::from_hours(1));

        assert_eq!(issuer.trust_root(), "acme.com");
    }

    #[test]
    fn issuer_default_ttl_accessible() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key, Duration::from_hours(2));

        assert_eq!(issuer.default_ttl(), Duration::from_hours(2));
    }

    #[test]
    fn issue_with_custom_ttl() {
        let issuer = Issuer::generate("acme.com", Duration::from_hours(1));
        let uri = test_uri();

        // Should not error with different TTL
        let token = issuer
            .issue_with_ttl(
                &uri,
                &SigningKey::generate().verifying_key(),
                vec![],
                Duration::from_mins(1),
            )
            .unwrap();

        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn issue_with_multiple_capabilities() {
        let issuer = Issuer::generate("acme.com", Duration::from_hours(1));
        let uri = test_uri();

        let capabilities = vec!["test/read".into(), "test/write".into(), "test/admin".into()];

        let token = issuer
            .issue(&uri, &SigningKey::generate().verifying_key(), capabilities)
            .unwrap();

        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn issue_claims_directly() {
        let issuer = Issuer::generate("acme.com", Duration::from_hours(1));

        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&SigningKey::generate().verifying_key())
            .issuer("acme.com")
            .add_capability("test/read")
            .audience("api.acme.com")
            .build()
            .unwrap();

        let token = issuer.issue_claims(&claims).unwrap();

        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn issue_refuses_to_mint_an_oversized_token() {
        let issuer = Issuer::generate("acme.com", Duration::from_hours(1));
        let uri = test_uri();

        // Each capability stays inside the subject URI's identity scope and
        // within the per-capability limit; together they blow past the token
        // cap. Minting this would hand back a token the verifier rejects.
        let capabilities: Vec<String> = (0..64)
            .map(|index| format!("test/{}/{}/seg{index}", "a".repeat(60), "b".repeat(60)))
            .collect();

        match issuer.issue(&uri, &SigningKey::generate().verifying_key(), capabilities) {
            Err(AttestationError::TokenTooLong { max, actual }) => {
                assert_eq!(max, crate::MAX_TOKEN_LENGTH);
                assert!(actual > max);
            }
            other => panic!("Expected TokenTooLong, got {other:?}"),
        }
    }

    #[test]
    fn issuer_debug_does_not_print_its_signing_key() {
        // `Issuer` derives `Debug` and holds the trust root's private key, so
        // what it prints is decided entirely by `SigningKey`'s impl. That is
        // fine today and nothing was checking it: a derive on `SigningKey`
        // would leak the key through every `Issuer` in every log line, and the
        // change would look harmless at the site that made it.
        let seed = [0xCDu8; 32];
        let key = SigningKey::from_bytes(&seed).expect("a valid seed");
        let issuer = Issuer::new("acme.com", key, Duration::from_hours(1));

        let shown = format!("{issuer:?}");
        let as_hex = seed.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        });

        assert!(shown.contains("acme.com"), "the trust root is not a secret");
        for rendering in [as_hex, format!("{seed:?}")] {
            assert!(
                !shown.contains(&rendering),
                "the signing key leaked into Debug output: {shown}"
            );
        }
    }

    #[test]
    fn issued_tokens_are_verifiable_by_the_length_check() {
        let issuer = Issuer::generate("acme.com", Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer
            .issue(
                &uri,
                &SigningKey::generate().verifying_key(),
                vec!["test/read".into()],
            )
            .unwrap();

        assert!(crate::check_token_length(&token).is_ok());
    }
}
