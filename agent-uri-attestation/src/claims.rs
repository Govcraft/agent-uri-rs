//! Attestation claims types.
//!
//! See `grammar.abnf` for the formal ABNF specification of claims structure.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AttestationError;
use crate::keys::VerifyingKey;

/// Claims embedded in an attestation token.
///
/// These claims cryptographically bind an agent URI to a set of capabilities
/// and to the agent's own key, with issuer information and validity period.
///
/// # Why the agent key is in here
///
/// A token that named only a URI and its capabilities would be a bearer
/// credential: registration records are world-readable, so anyone who read one
/// could present its token as their own. Naming the agent's public key makes
/// the token useless without the matching private key, which the trust root
/// vouched for and the holder never publishes.
///
/// # Grammar Reference
///
/// See `grammar.abnf` for the formal ABNF specification of the claims
/// JSON structure. Key constraints:
///
/// | Field | Format | Max Length |
/// |-------|--------|------------|
/// | `agent_uri` | agent-uri ABNF | 512 chars |
/// | `agent_key` | base64 Ed25519 | 44 chars |
/// | `capabilities` | JSON array | 64 items |
/// | `iss` | trust-root | 128 chars |
/// | `iat` | ISO 8601 | 30 chars |
/// | `exp` | ISO 8601 | 30 chars |
/// | `aud` | alphanumeric | 128 chars |
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{AttestationClaims, SigningKey};
/// use std::time::Duration;
///
/// let claims = AttestationClaims::builder()
///     .agent_uri("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q")
///     .agent_key(&SigningKey::generate().verifying_key())
///     .capabilities(vec!["workflow/approval/read".into()])
///     .issuer("acme.com")
///     .ttl(Duration::from_secs(3600))
///     .build()
///     .unwrap();
///
/// assert_eq!(claims.iss, "acme.com");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationClaims {
    /// The full agent URI being attested
    pub agent_uri: String,
    /// The agent's own Ed25519 public key, base64-encoded.
    ///
    /// Whoever holds the matching private key is the agent this token attests.
    /// Read it as a [`VerifyingKey`] with
    /// [`AttestationClaims::agent_verifying_key`].
    pub agent_key: String,
    /// Capabilities granted to this agent
    pub capabilities: Vec<String>,
    /// Issuer (trust root) that created this attestation
    pub iss: String,
    /// When the token was issued
    pub iat: DateTime<Utc>,
    /// When the token expires
    pub exp: DateTime<Utc>,
    /// Optional audience restriction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

impl AttestationClaims {
    /// Creates a new builder for attestation claims.
    #[must_use]
    pub fn builder() -> AttestationClaimsBuilder {
        AttestationClaimsBuilder::new()
    }

    /// Returns the attested agent key.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidKeyFormat`] if the `agent_key` claim
    /// is not base64 of a valid Ed25519 public key. Claims that came from
    /// [`crate::Verifier`] have already passed this check.
    pub fn agent_verifying_key(&self) -> Result<VerifyingKey, AttestationError> {
        VerifyingKey::from_base64(&self.agent_key)
    }

    /// Returns the trust root from the agent URI.
    ///
    /// This extracts the authority portion of the agent URI for trust root
    /// verification.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_uri_attestation::{AttestationClaims, SigningKey};
    /// use std::time::Duration;
    ///
    /// let claims = AttestationClaims::builder()
    ///     .agent_uri("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q")
    ///     .agent_key(&SigningKey::generate().verifying_key())
    ///     .issuer("acme.com")
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(claims.trust_root(), Some("acme.com"));
    /// ```
    #[must_use]
    pub fn trust_root(&self) -> Option<&str> {
        // Extract trust root from agent:// URI
        self.agent_uri
            .strip_prefix("agent://")
            .and_then(|rest| rest.split('/').next())
    }

    /// Returns true if the claims have expired.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_uri_attestation::{AttestationClaims, SigningKey};
    /// use std::time::Duration;
    ///
    /// let claims = AttestationClaims::builder()
    ///     .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
    ///     .agent_key(&SigningKey::generate().verifying_key())
    ///     .issuer("acme.com")
    ///     .ttl(Duration::from_secs(3600))
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(!claims.is_expired());
    /// ```
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.exp
    }

    /// Returns true if the token is not yet valid (before `iat`).
    #[must_use]
    pub fn is_not_yet_valid(&self) -> bool {
        Utc::now() < self.iat
    }

    /// Checks if the claims have expired at a specific time.
    ///
    /// This method allows testing expiration logic without depending on
    /// the system clock, making edge cases testable.
    ///
    /// # Arguments
    ///
    /// * `now` - The time to check expiration against
    ///
    /// # Returns
    ///
    /// `true` if the claims have expired (now >= exp), `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri_attestation::{AttestationClaims, SigningKey};
    /// use chrono::{Utc, Duration};
    /// use std::time::Duration as StdDuration;
    ///
    /// let claims = AttestationClaims::builder()
    ///     .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
    ///     .agent_key(&SigningKey::generate().verifying_key())
    ///     .issuer("acme.com")
    ///     .ttl(StdDuration::from_secs(3600))
    ///     .build()
    ///     .unwrap();
    ///
    /// let now = Utc::now();
    /// let future = now + Duration::hours(2);
    ///
    /// assert!(!claims.is_expired_at(now));
    /// assert!(claims.is_expired_at(future));
    /// ```
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.exp
    }
}

/// Builder for constructing `AttestationClaims`.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{AttestationClaimsBuilder, SigningKey};
/// use std::time::Duration;
///
/// let claims = AttestationClaimsBuilder::new()
///     .agent_uri("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q")
///     .agent_key(&SigningKey::generate().verifying_key())
///     .add_capability("workflow/approval/read")
///     .add_capability("workflow/approval/execute")
///     .issuer("acme.com")
///     .ttl(Duration::from_secs(7200))
///     .audience("api.acme.com")
///     .build()
///     .unwrap();
///
/// assert_eq!(claims.capabilities.len(), 2);
/// assert_eq!(claims.aud, Some("api.acme.com".to_string()));
/// ```
#[derive(Debug, Clone)]
pub struct AttestationClaimsBuilder {
    agent_uri: Option<String>,
    agent_key: Option<String>,
    capabilities: Vec<String>,
    issuer: Option<String>,
    ttl: Duration,
    audience: Option<String>,
}

impl AttestationClaimsBuilder {
    /// Creates a new builder with default TTL of 24 hours.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agent_uri: None,
            agent_key: None,
            capabilities: Vec::new(),
            issuer: None,
            ttl: Duration::from_hours(24),
            audience: None,
        }
    }

    /// Sets the agent URI to attest.
    #[must_use]
    pub fn agent_uri(mut self, uri: impl Into<String>) -> Self {
        self.agent_uri = Some(uri.into());
        self
    }

    /// Sets the agent's own public key.
    ///
    /// Required. Without it the token would authenticate nobody: a token that
    /// names only a URI can be lifted from a public registration record and
    /// presented by whoever read it.
    #[must_use]
    pub fn agent_key(mut self, key: &VerifyingKey) -> Self {
        self.agent_key = Some(key.to_base64());
        self
    }

    /// Sets the capabilities granted.
    #[must_use]
    pub fn capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }

    /// Adds a single capability.
    #[must_use]
    pub fn add_capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    /// Sets the issuer (trust root).
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets the time-to-live duration.
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the optional audience.
    #[must_use]
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.audience = Some(aud.into());
        self
    }

    /// Builds the claims.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError::MissingField` if required fields are not set.
    pub fn build(self) -> Result<AttestationClaims, AttestationError> {
        let agent_uri = self
            .agent_uri
            .ok_or(AttestationError::MissingField { field: "agent_uri" })?;
        let agent_key = self
            .agent_key
            .ok_or(AttestationError::MissingField { field: "agent_key" })?;
        let issuer = self
            .issuer
            .ok_or(AttestationError::MissingField { field: "issuer" })?;

        let parsed_uri = agent_uri::AgentUri::parse(&agent_uri).map_err(|error| {
            AttestationError::InvalidClaims {
                reason: format!("invalid agent_uri claim: {error}"),
            }
        })?;
        let capabilities = if self.capabilities.is_empty() {
            vec![parsed_uri.capability_path().as_str().to_string()]
        } else {
            self.capabilities
        };
        crate::verification::validate_capability_scope(&agent_uri, &capabilities)?;

        let now = Utc::now();
        let exp =
            now + chrono::Duration::from_std(self.ttl).map_err(|_| AttestationError::InvalidTtl)?;

        Ok(AttestationClaims {
            agent_uri,
            agent_key,
            capabilities,
            iss: issuer,
            iat: now,
            exp,
            aud: self.audience,
        })
    }
}

impl Default for AttestationClaimsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    fn agent_key() -> VerifyingKey {
        SigningKey::generate().verifying_key()
    }

    #[test]
    fn builder_creates_valid_claims() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .build()
            .unwrap();

        assert_eq!(
            claims.agent_uri,
            "agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q"
        );
        assert_eq!(claims.iss, "acme.com");
        assert_eq!(claims.capabilities, vec!["test"]);
        assert!(claims.aud.is_none());
    }

    #[test]
    fn builder_requires_agent_uri() {
        let result = AttestationClaimsBuilder::new()
            .agent_key(&agent_key())
            .issuer("acme.com")
            .build();

        assert!(matches!(
            result,
            Err(AttestationError::MissingField { field: "agent_uri" })
        ));
    }

    #[test]
    fn builder_requires_an_agent_key() {
        // Without it the token names a URI and nothing else, which is a bearer
        // credential: anyone who reads a registration record can present it.
        let result = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .build();

        assert!(matches!(
            result,
            Err(AttestationError::MissingField { field: "agent_key" })
        ));
    }

    #[test]
    fn builder_records_the_agent_key_in_its_wire_form() {
        let key = agent_key();
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&key)
            .issuer("acme.com")
            .build()
            .unwrap();

        assert_eq!(claims.agent_key, key.to_base64());
        assert_eq!(claims.agent_verifying_key().unwrap(), key);
    }

    #[test]
    fn an_agent_key_that_is_not_a_key_is_reported_when_read() {
        let mut claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .build()
            .unwrap();
        claims.agent_key = "not a key".to_string();

        assert!(matches!(
            claims.agent_verifying_key(),
            Err(AttestationError::InvalidKeyFormat { .. })
        ));
    }

    #[test]
    fn builder_requires_issuer() {
        let result = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .build();

        assert!(matches!(
            result,
            Err(AttestationError::MissingField { field: "issuer" })
        ));
    }

    #[test]
    fn builder_with_capabilities() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .add_capability("test/read")
            .add_capability("test/write")
            .build()
            .unwrap();

        assert_eq!(claims.capabilities, vec!["test/read", "test/write"]);
    }

    #[test]
    fn builder_with_audience() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .audience("api.acme.com")
            .build()
            .unwrap();

        assert_eq!(claims.aud, Some("api.acme.com".to_string()));
    }

    #[test]
    fn builder_with_custom_ttl() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .ttl(Duration::from_hours(1))
            .build()
            .unwrap();

        // Expiration should be roughly 1 hour from now
        let expected_exp = claims.iat + chrono::Duration::seconds(3600);
        assert!((claims.exp - expected_exp).num_seconds().abs() < 2);
    }

    #[test]
    fn trust_root_extraction() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .build()
            .unwrap();

        assert_eq!(claims.trust_root(), Some("acme.com"));
    }

    #[test]
    fn trust_root_with_port() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://localhost:8472/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("localhost:8472")
            .build()
            .unwrap();

        assert_eq!(claims.trust_root(), Some("localhost:8472"));
    }

    #[test]
    fn is_expired_returns_false_for_future_expiration() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .ttl(Duration::from_hours(1))
            .build()
            .unwrap();

        assert!(!claims.is_expired());
    }

    #[test]
    fn is_not_yet_valid_tracks_iat() {
        let mut claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .ttl(Duration::from_hours(1))
            .build()
            .unwrap();

        assert!(!claims.is_not_yet_valid());

        claims.iat = Utc::now() + chrono::Duration::hours(1);
        assert!(claims.is_not_yet_valid());
    }

    #[test]
    fn claims_serialization_roundtrip() {
        let original = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .agent_key(&agent_key())
            .issuer("acme.com")
            .add_capability("test/read")
            .audience("api.acme.com")
            .build()
            .unwrap();

        let json = serde_json::to_string(&original).unwrap();
        let recovered: AttestationClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(original.agent_uri, recovered.agent_uri);
        assert_eq!(original.agent_key, recovered.agent_key);
        assert_eq!(original.iss, recovered.iss);
        assert_eq!(original.capabilities, recovered.capabilities);
        assert_eq!(original.aud, recovered.aud);
    }
}
