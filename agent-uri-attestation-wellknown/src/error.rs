//! What can go wrong between asking a trust root for its keys and holding them.

use std::fmt;

use agent_uri_attestation::AttestationError;

/// A key discovery that did not produce keys.
///
/// Every variant is a refusal to trust, never a degraded success. A caller that
/// wanted keys and got one of these has no keys, and a verifier built without
/// them verifies nothing rather than something.
///
/// `#[non_exhaustive]`, so a `match` on this enum needs a `_` arm — and that
/// arm should assume the same thing every named variant means, because every
/// variant added later will be another way of refusing to trust.
#[derive(Debug)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The trust root is not one this crate will build a URL from.
    ///
    /// The endpoint is derived from the trust root by string construction, so
    /// a "trust root" carrying a slash, an `@`, or a scheme would aim the
    /// request at a host of the caller's choosing while looking like a lookup
    /// of the root they named.
    InvalidTrustRoot {
        /// The rejected trust root
        trust_root: String,
        /// Why the agent-uri grammar refused it
        reason: String,
    },
    /// The request did not complete.
    Transport {
        /// The trust root being asked
        trust_root: String,
        /// What the HTTP client reported
        reason: String,
    },
    /// The endpoint answered, but not with a document.
    Status {
        /// The trust root being asked
        trust_root: String,
        /// The HTTP status returned
        status: u16,
    },
    /// The response body was longer than this crate will read.
    ///
    /// Read as a cap on what a server can make a client hold, not as a
    /// judgement about the document: nothing was parsed.
    TooLarge {
        /// The trust root being asked
        trust_root: String,
        /// The cap, in bytes
        max: usize,
    },
    /// The document arrived but does not say what a key document must.
    ///
    /// Includes a document that names a different trust root than the one
    /// whose endpoint served it.
    Document {
        /// The trust root being asked
        trust_root: String,
        /// What reading it found wrong
        source: AttestationError,
    },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTrustRoot { trust_root, reason } => write!(
                f,
                "'{trust_root}' is not a usable trust root, so no key endpoint was requested: \
                 {reason}"
            ),
            Self::Transport { trust_root, reason } => {
                write!(
                    f,
                    "could not reach the key endpoint of '{trust_root}': {reason}"
                )
            }
            Self::Status { trust_root, status } => write!(
                f,
                "the key endpoint of '{trust_root}' answered with HTTP {status}"
            ),
            Self::TooLarge { trust_root, max } => write!(
                f,
                "the key endpoint of '{trust_root}' returned more than {max} bytes"
            ),
            Self::Document { trust_root, source } => {
                write!(
                    f,
                    "the key document of '{trust_root}' is unusable: {source}"
                )
            }
        }
    }
}

impl std::error::Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Document { source, .. } => Some(source),
            _ => None,
        }
    }
}
