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
    /// The issuer is not in the trusted roots set.
    UntrustedIssuer {
        /// The untrusted issuer
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
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => {
                write!(f, "missing required field '{field}' in attestation claims")
            }
            Self::InvalidTtl => {
                write!(f, "TTL duration is invalid or out of range")
            }
            Self::TokenExpired { expired_at } => {
                write!(
                    f,
                    "token expired at {expired_at}; request a new attestation"
                )
            }
            Self::TokenNotYetValid { valid_from } => {
                write!(f, "token not yet valid; valid from {valid_from}")
            }
            Self::InvalidSignature => {
                write!(
                    f,
                    "token signature verification failed; token may have been tampered with"
                )
            }
            Self::InvalidTokenFormat { reason } => {
                write!(f, "invalid token format: {reason}")
            }
            Self::InvalidClaims { reason } => {
                write!(f, "failed to parse claims: {reason}")
            }
            Self::TrustRootMismatch {
                token_root,
                expected_root,
            } => {
                write!(
                    f,
                    "trust root mismatch: token issued by '{token_root}' but expected '{expected_root}'"
                )
            }
            Self::UntrustedIssuer { issuer } => {
                write!(
                    f,
                    "issuer '{issuer}' is not in trusted roots; add it with verifier.add_trusted_root()"
                )
            }
            Self::UriMismatch {
                token_uri,
                expected_uri,
            } => {
                write!(
                    f,
                    "URI mismatch: token attests '{token_uri}' but expected '{expected_uri}'"
                )
            }
            Self::MissingPublicKey { issuer } => {
                write!(
                    f,
                    "no public key registered for issuer '{issuer}'; register with verifier.add_trusted_root()"
                )
            }
            Self::InvalidKeyFormat { reason } => {
                write!(f, "invalid key format: {reason}")
            }
        }
    }
}

impl std::error::Error for AttestationError {}
