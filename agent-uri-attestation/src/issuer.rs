//! Token issuer for creating attestations.

use std::time::Duration;

use agent_uri::AgentUri;
use rusty_paseto::prelude::*;

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
/// let token = issuer.issue(&uri, vec!["workflow.approval.read".into()]).unwrap();
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
    /// * `capabilities` - Capabilities to grant
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
    ///
    /// let token = issuer.issue(&uri, vec!["read".into(), "write".into()]).unwrap();
    /// ```
    pub fn issue(
        &self,
        uri: &AgentUri,
        capabilities: Vec<String>,
    ) -> Result<String, AttestationError> {
        self.issue_with_ttl(uri, capabilities, self.default_ttl)
    }

    /// Issues an attestation token with a custom TTL.
    ///
    /// # Arguments
    ///
    /// * `uri` - The agent URI to attest
    /// * `capabilities` - Capabilities to grant
    /// * `ttl` - Time-to-live for this specific token
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if token creation fails.
    pub fn issue_with_ttl(
        &self,
        uri: &AgentUri,
        capabilities: Vec<String>,
        ttl: Duration,
    ) -> Result<String, AttestationError> {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri(uri.to_string())
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
    /// # Errors
    ///
    /// Returns `AttestationError` if token creation fails.
    pub fn issue_claims(&self, claims: &AttestationClaims) -> Result<String, AttestationError> {
        // Build the PASETO key from the signing key
        let dalek_key = self.signing_key.as_dalek();
        let key_bytes = dalek_key.to_keypair_bytes();
        let key_wrapper = Key::<64>::from(&key_bytes);
        let paseto_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_wrapper);

        // Format timestamps for PASETO
        let exp_str = claims.exp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let iat_str = claims.iat.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        // Prepare claims
        let exp_claim =
            ExpirationClaim::try_from(exp_str.as_str()).map_err(|e| AttestationError::InvalidClaims {
                reason: format!("invalid expiration: {e}"),
            })?;
        let iat_claim =
            IssuedAtClaim::try_from(iat_str.as_str()).map_err(|e| AttestationError::InvalidClaims {
                reason: format!("invalid issued at: {e}"),
            })?;
        let iss_claim = IssuerClaim::from(claims.iss.as_str());
        let agent_uri_claim = CustomClaim::try_from(("agent_uri", claims.agent_uri.as_str()))
            .map_err(|e| AttestationError::InvalidClaims {
                reason: format!("invalid agent_uri claim: {e}"),
            })?;

        // Serialize capabilities as JSON array
        let capabilities_json = serde_json::to_value(&claims.capabilities).map_err(|e| {
            AttestationError::InvalidClaims {
                reason: format!("invalid capabilities: {e}"),
            }
        })?;
        let capabilities_claim = CustomClaim::try_from(("capabilities", capabilities_json))
            .map_err(|e| AttestationError::InvalidClaims {
                reason: format!("invalid capabilities claim: {e}"),
            })?;

        // Build the token with standard and custom claims
        let mut builder = PasetoBuilder::<V4, Public>::default();
        builder
            .set_claim(exp_claim)
            .set_claim(iat_claim)
            .set_claim(iss_claim)
            .set_claim(agent_uri_claim)
            .set_claim(capabilities_claim);

        // Set optional audience
        if let Some(aud) = &claims.aud {
            builder.set_claim(AudienceClaim::from(aud.as_str()));
        }

        // Build and sign the token
        builder.build(&paseto_key).map_err(|e| AttestationError::InvalidTokenFormat {
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> AgentUri {
        AgentUri::parse("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap()
    }

    #[test]
    fn issue_creates_valid_token() {
        let issuer = Issuer::generate("acme.com", Duration::from_secs(3600));
        let uri = test_uri();

        let token = issuer.issue(&uri, vec!["read".into()]).unwrap();

        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn generated_issuer_has_unique_key() {
        let issuer1 = Issuer::generate("acme.com", Duration::from_secs(3600));
        let issuer2 = Issuer::generate("acme.com", Duration::from_secs(3600));

        assert_ne!(
            issuer1.verifying_key().to_bytes(),
            issuer2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn issuer_trust_root_accessible() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key, Duration::from_secs(3600));

        assert_eq!(issuer.trust_root(), "acme.com");
    }

    #[test]
    fn issuer_default_ttl_accessible() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key, Duration::from_secs(7200));

        assert_eq!(issuer.default_ttl(), Duration::from_secs(7200));
    }

    #[test]
    fn issue_with_custom_ttl() {
        let issuer = Issuer::generate("acme.com", Duration::from_secs(3600));
        let uri = test_uri();

        // Should not error with different TTL
        let token = issuer
            .issue_with_ttl(&uri, vec![], Duration::from_secs(60))
            .unwrap();

        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn issue_with_multiple_capabilities() {
        let issuer = Issuer::generate("acme.com", Duration::from_secs(3600));
        let uri = test_uri();

        let capabilities = vec![
            "workflow.read".into(),
            "workflow.write".into(),
            "workflow.admin".into(),
        ];

        let token = issuer.issue(&uri, capabilities).unwrap();

        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn issue_claims_directly() {
        let issuer = Issuer::generate("acme.com", Duration::from_secs(3600));

        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .add_capability("read")
            .audience("api.acme.com")
            .build()
            .unwrap();

        let token = issuer.issue_claims(&claims).unwrap();

        assert!(token.starts_with("v4.public."));
    }
}
