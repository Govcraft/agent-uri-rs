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
    /// whose endpoint served it, and a signed document whose signature does not
    /// check out against the keys pinned for that root.
    Document {
        /// The trust root being asked
        trust_root: String,
        /// What reading it found wrong
        source: AttestationError,
    },
    /// A root this verifier pins a key for served the bare, unsigned document.
    ///
    /// Pinning a root key is a statement that this deployment will not take
    /// that root's word from the publication channel alone. Accepting the bare
    /// form here would undo it, and would do so on the say-so of whoever served
    /// the document — which is exactly the party the pin exists to distrust.
    Unsigned {
        /// The trust root being asked
        trust_root: String,
    },
    /// A signed document is older than one already accepted from that root.
    ///
    /// Its signature is genuine: the root really did publish it, once. What
    /// makes it a refusal is that it is behind, which is how an attacker
    /// holding the publication host undoes a revocation without forging
    /// anything.
    VersionRegression {
        /// The trust root being asked
        trust_root: String,
        /// The newest version this verifier has accepted
        held: u64,
        /// The version the endpoint served
        offered: u64,
    },
    /// The record of what has already been accepted could not be consulted.
    ///
    /// A lock this process poisoned by panicking while holding it. Reported
    /// rather than worked around, because a rollback check that did not happen
    /// is not one that passed.
    VersionUnavailable {
        /// The trust root being asked
        trust_root: String,
    },
    /// A pinned root key is not a key.
    ///
    /// Describes the deployment's configuration, not anything a trust root
    /// served; no request was made.
    InvalidRootKey {
        /// Why the key could not be read
        reason: String,
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
            Self::Unsigned { trust_root } => write!(
                f,
                "a root key is pinned for '{trust_root}', so its key document must be the signed \
                 form of specification 7.2, but the endpoint served the bare form"
            ),
            Self::VersionRegression {
                trust_root,
                held,
                offered,
            } => write!(
                f,
                "the key document of '{trust_root}' is version {offered}, behind the version \
                 {held} already accepted; a document that goes backwards is a replay, whoever \
                 signed it"
            ),
            Self::VersionUnavailable { trust_root } => write!(
                f,
                "the record of which key documents have already been accepted from '{trust_root}' \
                 could not be read, so this one cannot be checked against it"
            ),
            Self::InvalidRootKey { reason } => {
                write!(f, "the pinned root key cannot be read: {reason}")
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
