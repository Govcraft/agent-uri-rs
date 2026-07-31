//! Error types for attestation operations.

use std::fmt;

/// Errors that can occur during attestation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// A required field was not provided.
    MissingField {
        /// Name of the missing field
        field: &'static str,
    },
    /// The TTL duration is invalid.
    InvalidTtl,
    /// Token has expired.
    TokenExpired {
        /// When the token expired
        expired_at: String,
    },
    /// Token is not yet valid.
    TokenNotYetValid {
        /// When the token becomes valid
        valid_from: String,
    },
    /// Token signature verification failed.
    InvalidSignature,
    /// Token format is invalid.
    InvalidTokenFormat {
        /// Description of the format error
        reason: String,
    },
    /// Token exceeds the maximum permitted length.
    ///
    /// The cap is enforced before the token is decoded or signature-checked, so
    /// an oversized token costs no Ed25519 verifications. Nothing in the token
    /// has been authenticated when this is returned.
    TokenTooLong {
        /// Maximum permitted token length in bytes
        max: usize,
        /// Actual token length in bytes
        actual: usize,
    },
    /// Claims could not be parsed.
    InvalidClaims {
        /// Description of the parsing error
        reason: String,
    },
    /// Trust root mismatch between token and expected URI.
    TrustRootMismatch {
        /// The trust root in the token
        token_root: String,
        /// The expected trust root
        expected_root: String,
    },
    /// The authenticated issuer does not own the attested URI's namespace.
    ///
    /// The `iss` claim is authenticated (it matched the trust root the
    /// verifying key is registered under), but it differs from the trust root
    /// (authority) parsed from the `agent_uri` claim. A key is only authorized
    /// to attest URIs rooted at its own authority; anything else is a
    /// cross-namespace forgery and is rejected. This is also returned when the
    /// `agent_uri` claim has no parseable authority (fail closed).
    IssuerNamespaceMismatch {
        /// The authenticated issuer (`iss` claim)
        issuer: String,
        /// The trust root (authority) parsed from the `agent_uri` claim
        uri_trust_root: String,
    },
    /// The issuer is not in the trusted roots set.
    UntrustedIssuer {
        /// The untrusted issuer
        issuer: String,
    },
    /// The verifier has no revocation source, so it cannot honour any token.
    ///
    /// Specification section 8.2 requires that verifiers check revocation
    /// before accepting. A verifier with nothing to check against cannot do
    /// that, and accepting anyway would mean reporting a token as verified
    /// when one of the required checks was silently skipped. Supply a source
    /// with [`Verifier::with_revocation`](crate::Verifier::with_revocation) —
    /// [`Denylist`](crate::Denylist) for a real one, or
    /// [`AcceptAll`](crate::AcceptAll) to state that this deployment does not
    /// revoke.
    ///
    /// Nothing in the token has been authenticated when this is returned; it
    /// describes the verifier, not the token.
    RevocationUnavailable,
    /// The token's `jti` is on the revocation list.
    ///
    /// The signature is good and the claims are authentic. The issuer has
    /// withdrawn this particular attestation.
    TokenRevoked {
        /// The revoked token's identifier
        jti: String,
    },
    /// The key that signed this token has been revoked.
    ///
    /// Wider than [`Self::TokenRevoked`]: every token this key ever signed is
    /// refused, including ones that were never individually listed. This is
    /// what a key compromise looks like from the verifying side.
    KeyRevoked {
        /// The trust root whose key was revoked
        issuer: String,
    },
    /// URI in token does not match expected URI.
    UriMismatch {
        /// URI in the token
        token_uri: String,
        /// Expected URI
        expected_uri: String,
    },
    /// No public key registered for the issuer.
    MissingPublicKey {
        /// The issuer lacking a public key
        issuer: String,
    },
    /// Key format is invalid.
    InvalidKeyFormat {
        /// Description of the key error
        reason: String,
    },
    /// Token capabilities do not cover the required capability path.
    InsufficientCapabilities {
        /// The capability path that was required
        required: String,
        /// The capabilities that were attested in the token
        attested: Vec<String>,
    },
    /// An attested capability falls outside the subject URI's identity scope.
    CapabilityOutsideIdentity {
        /// Capability path embedded in the subject URI
        identity_path: String,
        /// Capability claim that is broader than or unrelated to the identity
        capability: String,
    },
    /// An audience-restricted token was verified without the required audience.
    AudienceMismatch {
        /// Audience required by the token
        token_audience: String,
        /// Audience supplied by the verifier, if any
        verifier_audience: Option<String>,
    },
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => {
                write!(f, "missing required field '{field}' in attestation claims")
            }
            Self::InvalidTtl => write!(f, "TTL duration is invalid or out of range"),
            Self::TokenExpired { expired_at } => write!(
                f,
                "token expired at {expired_at}; request a new attestation"
            ),
            Self::TokenNotYetValid { valid_from } => {
                write!(f, "token not yet valid; valid from {valid_from}")
            }
            Self::InvalidSignature => write!(
                f,
                "token signature verification failed; token may have been tampered with"
            ),
            Self::InvalidTokenFormat { reason } => write!(f, "invalid token format: {reason}"),
            Self::TokenTooLong { max, actual } => write!(
                f,
                "token is {actual} bytes, exceeding the {max}-byte maximum; \
                 reduce the claims (capabilities are usually the largest)"
            ),
            Self::InvalidClaims { reason } => write!(f, "failed to parse claims: {reason}"),
            Self::TrustRootMismatch {
                token_root,
                expected_root,
            } => write!(
                f,
                "trust root mismatch: token issued by '{token_root}' but expected '{expected_root}'"
            ),
            Self::IssuerNamespaceMismatch {
                issuer,
                uri_trust_root,
            } => write!(
                f,
                "issuer '{issuer}' is not authorized for the attested URI's namespace \
                 '{uri_trust_root}'; a key may only attest agent URIs rooted at its own authority"
            ),
            Self::UntrustedIssuer { issuer } => write!(
                f,
                "issuer '{issuer}' is not in trusted roots; add it with verifier.add_trusted_root()"
            ),
            Self::RevocationUnavailable => write!(
                f,
                "this verifier has no revocation source, so it cannot accept any token; \
                 supply one with verifier.with_revocation(), using Denylist for a real list \
                 or AcceptAll to declare that this deployment does not revoke"
            ),
            Self::TokenRevoked { jti } => write!(
                f,
                "token '{jti}' has been revoked by its issuer; request a new attestation"
            ),
            Self::KeyRevoked { issuer } => write!(
                f,
                "the signing key for trust root '{issuer}' has been revoked, so every token \
                 it signed is refused; obtain the trust root's current key"
            ),
            Self::UriMismatch {
                token_uri,
                expected_uri,
            } => write!(
                f,
                "URI mismatch: token attests '{token_uri}' but expected '{expected_uri}'"
            ),
            Self::MissingPublicKey { issuer } => write!(
                f,
                "no public key registered for issuer '{issuer}'; register with verifier.add_trusted_root()"
            ),
            Self::InvalidKeyFormat { reason } => write!(f, "invalid key format: {reason}"),
            Self::InsufficientCapabilities { required, attested } => write!(
                f,
                "token capabilities {attested:?} do not cover required capability '{required}'; \
                 add a capability that is a prefix of or equals the required path"
            ),
            Self::CapabilityOutsideIdentity {
                identity_path,
                capability,
            } => write!(
                f,
                "attested capability '{capability}' is outside agent identity scope \
                 '{identity_path}'; capabilities must equal the URI path or be descendants"
            ),
            Self::AudienceMismatch {
                token_audience,
                verifier_audience,
            } => write!(
                f,
                "token is restricted to audience '{token_audience}', but verifier audience was {}",
                verifier_audience.as_deref().unwrap_or("not supplied")
            ),
        }
    }
}

impl std::error::Error for AttestationError {}
