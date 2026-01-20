//! Attestation claims types.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AttestationError;

/// Claims embedded in an attestation token.
///
/// These claims cryptographically bind an agent URI to a set of capabilities,
/// with issuer information and validity period.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::AttestationClaims;
/// use std::time::Duration;
///
/// let claims = AttestationClaims::builder()
///     .agent_uri("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q")
///     .capabilities(vec!["workflow.approval.read".into()])
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

    /// Returns the trust root from the agent URI.
    ///
    /// This extracts the authority portion of the agent URI for trust root
    /// verification.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_uri_attestation::AttestationClaims;
    /// use std::time::Duration;
    ///
    /// let claims = AttestationClaims::builder()
    ///     .agent_uri("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q")
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
    /// use agent_uri_attestation::AttestationClaims;
    /// use std::time::Duration;
    ///
    /// let claims = AttestationClaims::builder()
    ///     .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
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
}

/// Builder for constructing `AttestationClaims`.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::AttestationClaimsBuilder;
/// use std::time::Duration;
///
/// let claims = AttestationClaimsBuilder::new()
///     .agent_uri("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q")
///     .add_capability("workflow.approval.read")
///     .add_capability("workflow.approval.execute")
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
            capabilities: Vec::new(),
            issuer: None,
            ttl: Duration::from_secs(86400), // 24 hours
            audience: None,
        }
    }

    /// Sets the agent URI to attest.
    #[must_use]
    pub fn agent_uri(mut self, uri: impl Into<String>) -> Self {
        self.agent_uri = Some(uri.into());
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
        let agent_uri = self.agent_uri.ok_or(AttestationError::MissingField {
            field: "agent_uri",
        })?;
        let issuer = self.issuer.ok_or(AttestationError::MissingField {
            field: "issuer",
        })?;

        let now = Utc::now();
        let exp = now
            + chrono::Duration::from_std(self.ttl).map_err(|_| AttestationError::InvalidTtl)?;

        Ok(AttestationClaims {
            agent_uri,
            capabilities: self.capabilities,
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

    #[test]
    fn builder_creates_valid_claims() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .build()
            .unwrap();

        assert_eq!(
            claims.agent_uri,
            "agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q"
        );
        assert_eq!(claims.iss, "acme.com");
        assert!(claims.capabilities.is_empty());
        assert!(claims.aud.is_none());
    }

    #[test]
    fn builder_requires_agent_uri() {
        let result = AttestationClaimsBuilder::new().issuer("acme.com").build();

        assert!(matches!(
            result,
            Err(AttestationError::MissingField { field: "agent_uri" })
        ));
    }

    #[test]
    fn builder_requires_issuer() {
        let result = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
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
            .issuer("acme.com")
            .add_capability("read")
            .add_capability("write")
            .build()
            .unwrap();

        assert_eq!(claims.capabilities, vec!["read", "write"]);
    }

    #[test]
    fn builder_with_audience() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
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
            .issuer("acme.com")
            .ttl(Duration::from_secs(3600))
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
            .issuer("acme.com")
            .build()
            .unwrap();

        assert_eq!(claims.trust_root(), Some("acme.com"));
    }

    #[test]
    fn trust_root_with_port() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://localhost:8472/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("localhost:8472")
            .build()
            .unwrap();

        assert_eq!(claims.trust_root(), Some("localhost:8472"));
    }

    #[test]
    fn is_expired_returns_false_for_future_expiration() {
        let claims = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .ttl(Duration::from_secs(3600))
            .build()
            .unwrap();

        assert!(!claims.is_expired());
    }

    #[test]
    fn claims_serialization_roundtrip() {
        let original = AttestationClaimsBuilder::new()
            .agent_uri("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("acme.com")
            .add_capability("read")
            .audience("api.acme.com")
            .build()
            .unwrap();

        let json = serde_json::to_string(&original).unwrap();
        let recovered: AttestationClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(original.agent_uri, recovered.agent_uri);
        assert_eq!(original.iss, recovered.iss);
        assert_eq!(original.capabilities, recovered.capabilities);
        assert_eq!(original.aud, recovered.aud);
    }
}
