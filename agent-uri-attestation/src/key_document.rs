//! The key document a trust root publishes, and what a verifier makes of it.
//!
//! [Specification](https://github.com/Govcraft/agent-uri-rs/blob/main/SPECIFICATION.md)
//! section 7.2 has every trust root serve its verification keys at
//! `https://{trust-root}/.well-known/agent-keys.json`. Without it, trusting a
//! root means someone exchanged a key with it out of band, which does not
//! scale past the roots you already know.
//!
//! ```json
//! {
//!   "trust_root": "acme.com",
//!   "keys": [{
//!     "kid": "key-2026-01",
//!     "algorithm": "Ed25519",
//!     "public_key": "<base64 of 32 bytes>",
//!     "not_before": "2026-01-01T00:00:00Z",
//!     "not_after": "2027-01-01T00:00:00Z"
//!   }],
//!   "revoked_keys": []
//! }
//! ```
//!
//! This module reads that document and turns it into a [`TrustStore`] and a
//! [`Denylist`]. It does no I/O: what fetched the bytes is not its business,
//! and a caller with the document in a config file, a secrets manager, or a
//! deployment artefact should not have to pull in a network stack to use it.
//! `agent-uri-attestation-wellknown` is what fetches it over HTTPS.
//!
//! # What it refuses
//!
//! A key document is attacker-controlled until it has been checked. The one
//! thing that makes it trustworthy is the TLS connection it arrived over, and
//! that is upstream of this module, so what is left here is arithmetic:
//!
//! - the document must name the trust root it was fetched for, so a root
//!   cannot publish keys for somebody else's namespace;
//! - a key whose `algorithm` is not `Ed25519` is skipped rather than trusted;
//! - `public_key` must decode to a real Ed25519 key;
//! - `not_before` and `not_after` are required, as section 7.2 requires them,
//!   and a window that ends before it starts is refused;
//! - the number of keys is capped, because each one costs a signature
//!   verification on every token that fails to verify;
//! - `kid` must be unique within the document, since it is what names a key
//!   in a rotation and in an error.
//!
//! A document that survives all of that is still only as good as the root that
//! served it. It says which keys the root stands behind, not that the root
//! deserves to be trusted.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AttestationError;
use crate::keys::VerifyingKey;
use crate::revocation::Denylist;
use crate::trust::{TrustStore, TrustedKey};

/// The only signature algorithm PASETO v4.public has.
///
/// Compared case-sensitively. A root that writes `ed25519` is not writing what
/// section 7.2 specifies, and guessing at near-misses in a security-critical
/// document is how a typo becomes a trusted key.
pub const ED25519: &str = "Ed25519";

/// The largest key document this crate will read, in bytes.
///
/// A published document holds a handful of keys and a revocation list. This
/// bound is what stops a trust root, or something impersonating one, from
/// handing a verifier a document large enough to matter.
pub const MAX_DOCUMENT_LENGTH: usize = 65_536;

/// The most keys one trust root may publish.
///
/// A rotation needs two. This leaves room for an unusual schedule while
/// keeping the per-token cost bounded: a token that verifies under none of
/// them costs one Ed25519 verification per key held.
pub const MAX_KEYS: usize = 16;

/// A key document as a trust root serves it.
///
/// Parse one with [`Self::parse`], then take a [`TrustStore`] and a
/// [`Denylist`] from it. Both conversions validate; neither performs I/O.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::KeyDocument;
///
/// # let key = agent_uri_attestation::SigningKey::generate().verifying_key().to_base64();
/// let json = format!(r#"{{
///     "trust_root": "acme.com",
///     "keys": [{{
///         "kid": "key-2026-01",
///         "algorithm": "Ed25519",
///         "public_key": "{key}",
///         "not_before": "2026-01-01T00:00:00Z",
///         "not_after": "2027-01-01T00:00:00Z"
///     }}],
///     "revoked_keys": []
/// }}"#);
///
/// let document = KeyDocument::parse(&json).unwrap();
/// assert_eq!(document.trust_root(), "acme.com");
///
/// let store = document.trust_store().unwrap();
/// assert_eq!(store.key_count(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDocument {
    trust_root: String,
    keys: Vec<PublishedKey>,
    #[serde(default)]
    revoked_keys: Vec<RevokedKey>,
}

/// One key from a document's `keys` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedKey {
    /// Names the key, in a rotation and in an error.
    pub kid: String,
    /// The signature algorithm. Anything but [`ED25519`] is skipped.
    pub algorithm: String,
    /// The verification key, base64 of 32 bytes.
    pub public_key: String,
    /// When the key becomes usable. Required by section 7.2.
    pub not_before: DateTime<Utc>,
    /// When the key stops being usable. Required by section 7.2.
    pub not_after: DateTime<Utc>,
}

/// One entry from a document's `revoked_keys` list.
///
/// Carries the key material rather than only a `kid`, because that is what a
/// verifier can act on: a [`Denylist`] recognises a revoked key by the bytes
/// that signed the token, and a verifier that has already dropped the key it
/// is being told about has no way to turn a name back into one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedKey {
    /// The revoked key, base64 of 32 bytes.
    pub public_key: String,
    /// What the key was called while it was published, if the root says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl KeyDocument {
    /// Reads a key document.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidClaims`] when the document is longer
    /// than [`MAX_DOCUMENT_LENGTH`], is not the JSON section 7.2 specifies, or
    /// publishes more than [`MAX_KEYS`] keys.
    pub fn parse(json: &str) -> Result<Self, AttestationError> {
        if json.len() > MAX_DOCUMENT_LENGTH {
            return Err(AttestationError::InvalidClaims {
                reason: format!(
                    "key document is {} bytes, over the {MAX_DOCUMENT_LENGTH}-byte maximum",
                    json.len()
                ),
            });
        }

        let document: Self =
            serde_json::from_str(json).map_err(|e| AttestationError::InvalidClaims {
                reason: format!("key document is not the JSON of specification 7.2: {e}"),
            })?;

        document.check_limits()?;

        Ok(document)
    }

    /// Refuses a document that publishes more keys than a verifier will hold.
    ///
    /// Separate from [`Self::parse`] because the signed form of section 7.2
    /// reaches these same fields by a different route — deserialized as part of
    /// a larger payload rather than parsed from a whole body — and a cap that
    /// only one of the two routes applied would not be a cap.
    pub(crate) fn check_limits(&self) -> Result<(), AttestationError> {
        if self.keys.len() > MAX_KEYS {
            return Err(AttestationError::InvalidClaims {
                reason: format!(
                    "key document publishes {} keys, over the maximum of {MAX_KEYS}",
                    self.keys.len()
                ),
            });
        }
        Ok(())
    }

    /// The trust root this document says it belongs to.
    #[must_use]
    pub fn trust_root(&self) -> &str {
        &self.trust_root
    }

    /// The keys as published, before any of them are checked.
    #[must_use]
    pub fn keys(&self) -> &[PublishedKey] {
        &self.keys
    }

    /// The revocations as published, before any of them are checked.
    #[must_use]
    pub fn revoked_keys(&self) -> &[RevokedKey] {
        &self.revoked_keys
    }

    /// Refuses a document that does not belong to the root it was fetched for.
    ///
    /// The check that keeps `evil.example` from serving keys for `acme.com`:
    /// a document is only evidence about the authority whose endpoint served
    /// it, so whoever did the fetching has to say which authority that was.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::TrustRootMismatch`] when the document names
    /// a different root.
    pub fn check_belongs_to(&self, trust_root: &str) -> Result<(), AttestationError> {
        if self.trust_root == trust_root {
            return Ok(());
        }
        Err(AttestationError::TrustRootMismatch {
            token_root: self.trust_root.clone(),
            expected_root: trust_root.to_string(),
        })
    }

    /// Builds the trust store this document describes.
    ///
    /// Keys whose `algorithm` is not [`ED25519`] are skipped, so a root that
    /// publishes a future algorithm alongside its current one stays usable
    /// here. Everything else is a defect in the document and is refused.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidKeyFormat`] when a key does not
    /// decode or its window ends before it starts, and
    /// [`AttestationError::InvalidClaims`] when two keys share a `kid` or when
    /// no key is left that this crate can use.
    pub fn trust_store(&self) -> Result<TrustStore, AttestationError> {
        let mut store = TrustStore::new();
        let mut seen: HashSet<&str> = HashSet::new();

        for key in &self.keys {
            if !seen.insert(key.kid.as_str()) {
                return Err(AttestationError::InvalidClaims {
                    reason: format!(
                        "key document uses the identifier '{}' for more than one key",
                        key.kid
                    ),
                });
            }
            if key.algorithm != ED25519 {
                continue;
            }
            store.add(self.trust_root.clone(), key.to_trusted()?);
        }

        if store.is_empty() {
            return Err(AttestationError::InvalidClaims {
                reason: format!(
                    "key document for '{}' publishes no {ED25519} key this verifier can use",
                    self.trust_root
                ),
            });
        }

        Ok(store)
    }

    /// Builds the denylist this document's `revoked_keys` describes.
    ///
    /// An empty list is not an error: it is a root saying it has revoked
    /// nothing, which is the ordinary case.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidKeyFormat`] when a revoked key does
    /// not decode. A revocation that cannot be read is not one that can be
    /// enforced, and dropping it silently would leave a verifier honouring a
    /// key its root has withdrawn.
    pub fn denylist(&self) -> Result<Denylist, AttestationError> {
        let mut denylist = Denylist::new();
        for revoked in &self.revoked_keys {
            denylist.insert_key(&VerifyingKey::from_base64(&revoked.public_key)?);
        }
        Ok(denylist)
    }
}

impl PublishedKey {
    /// Reads this entry as a key the trust store can hold.
    fn to_trusted(&self) -> Result<TrustedKey, AttestationError> {
        if self.not_after < self.not_before {
            return Err(AttestationError::InvalidKeyFormat {
                reason: format!(
                    "key '{}' is published with a window that ends ({}) before it starts ({})",
                    self.kid,
                    self.not_after.to_rfc3339(),
                    self.not_before.to_rfc3339()
                ),
            });
        }

        Ok(
            TrustedKey::new(VerifyingKey::from_base64(&self.public_key)?)
                .with_id(self.kid.clone())
                .not_before(self.not_before)
                .not_after(self.not_after),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use crate::revocation::RevocationCheck;

    fn key() -> VerifyingKey {
        SigningKey::generate().verifying_key()
    }

    fn document_with(keys: &str, revoked: &str) -> String {
        format!(r#"{{"trust_root": "acme.com", "keys": [{keys}], "revoked_keys": [{revoked}]}}"#)
    }

    fn ed25519_entry(kid: &str, key: &VerifyingKey) -> String {
        format!(
            r#"{{"kid": "{kid}", "algorithm": "Ed25519", "public_key": "{}",
                 "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}"#,
            key.to_base64()
        )
    }

    #[test]
    fn a_published_key_becomes_a_trusted_key_with_its_window() {
        let published = key();
        let json = document_with(&ed25519_entry("key-2026-01", &published), "");

        let document = KeyDocument::parse(&json).expect("the document parses");
        let store = document.trust_store().expect("the key is usable");

        let held = &store.keys_for("acme.com")[0];
        assert_eq!(held.key(), &published);
        assert_eq!(held.id(), Some("key-2026-01"));
        assert!(held.valid_from().is_some());
        assert!(held.valid_until().is_some());
    }

    #[test]
    fn a_rotation_publishes_both_keys_under_one_root() {
        let json = document_with(
            &format!(
                "{}, {}",
                ed25519_entry("outgoing", &key()),
                ed25519_entry("incoming", &key())
            ),
            "",
        );

        let store = KeyDocument::parse(&json).unwrap().trust_store().unwrap();

        assert_eq!(store.root_count(), 1);
        assert_eq!(store.key_count(), 2);
    }

    #[test]
    fn a_key_in_an_algorithm_this_crate_cannot_use_is_skipped_not_trusted() {
        // Forward compatibility, not leniency: PASETO v4.public is Ed25519, so
        // a key in anything else is one this verifier could not check a
        // signature with even if it wanted to.
        let usable = key();
        let json = document_with(
            &format!(
                r#"{{"kid": "future", "algorithm": "Ed448", "public_key": "{}",
                     "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}, {}"#,
                key().to_base64(),
                ed25519_entry("current", &usable)
            ),
            "",
        );

        let store = KeyDocument::parse(&json).unwrap().trust_store().unwrap();

        assert_eq!(store.key_count(), 1);
        assert_eq!(store.keys_for("acme.com")[0].key(), &usable);
    }

    #[test]
    fn a_document_with_nothing_usable_is_refused_rather_than_left_empty() {
        // An empty store would be indistinguishable from a root nobody has
        // fetched yet, and the caller would install it and wonder why every
        // token from that root stopped verifying.
        let json = document_with(
            &format!(
                r#"{{"kid": "future", "algorithm": "Ed448", "public_key": "{}",
                     "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}"#,
                key().to_base64()
            ),
            "",
        );

        let error = KeyDocument::parse(&json)
            .unwrap()
            .trust_store()
            .expect_err("a document with no usable key must be refused");

        assert!(
            matches!(&error, AttestationError::InvalidClaims { reason } if reason.contains("Ed25519")),
            "{error}"
        );
    }

    #[test]
    fn the_algorithm_is_matched_exactly() {
        let json = document_with(
            &ed25519_entry("current", &key()).replace("Ed25519", "ed25519"),
            "",
        );

        assert!(KeyDocument::parse(&json).unwrap().trust_store().is_err());
    }

    #[test]
    fn a_key_that_does_not_decode_is_refused() {
        let json = document_with(
            r#"{"kid": "broken", "algorithm": "Ed25519", "public_key": "not base64",
                "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}"#,
            "",
        );

        let error = KeyDocument::parse(&json)
            .unwrap()
            .trust_store()
            .unwrap_err();

        assert!(
            matches!(error, AttestationError::InvalidKeyFormat { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_window_that_ends_before_it_starts_is_refused() {
        let json = document_with(
            &format!(
                r#"{{"kid": "inverted", "algorithm": "Ed25519", "public_key": "{}",
                     "not_before": "2027-01-01T00:00:00Z", "not_after": "2026-01-01T00:00:00Z"}}"#,
                key().to_base64()
            ),
            "",
        );

        let error = KeyDocument::parse(&json)
            .unwrap()
            .trust_store()
            .unwrap_err();

        assert!(
            matches!(&error, AttestationError::InvalidKeyFormat { reason } if reason.contains("before it starts")),
            "{error}"
        );
    }

    #[test]
    fn a_key_with_no_window_is_refused_because_7_2_requires_one() {
        let json = document_with(
            &format!(
                r#"{{"kid": "unbounded", "algorithm": "Ed25519", "public_key": "{}"}}"#,
                key().to_base64()
            ),
            "",
        );

        assert!(KeyDocument::parse(&json).is_err());
    }

    #[test]
    fn two_keys_cannot_share_an_identifier() {
        // A kid is what names a key in a rotation and in an error. Two keys
        // answering to one name means removing "the" key removes whichever the
        // store happened to keep.
        let json = document_with(
            &format!(
                "{}, {}",
                ed25519_entry("same", &key()),
                ed25519_entry("same", &key())
            ),
            "",
        );

        let error = KeyDocument::parse(&json)
            .unwrap()
            .trust_store()
            .unwrap_err();

        assert!(
            matches!(&error, AttestationError::InvalidClaims { reason } if reason.contains("more than one key")),
            "{error}"
        );
    }

    #[test]
    fn revoked_keys_become_a_denylist() {
        let revoked = key();
        let json = document_with(
            &ed25519_entry("current", &key()),
            &format!(
                r#"{{"public_key": "{}", "kid": "leaked"}}"#,
                revoked.to_base64()
            ),
        );

        let denylist = KeyDocument::parse(&json).unwrap().denylist().unwrap();

        assert!(denylist.is_key_revoked(&revoked));
        assert!(!denylist.is_key_revoked(&key()));
    }

    #[test]
    fn a_revocation_that_does_not_decode_is_refused_rather_than_dropped() {
        // Dropping it would leave the verifier honouring a key its root has
        // withdrawn, which is the one outcome the list exists to prevent.
        let json = document_with(
            &ed25519_entry("current", &key()),
            r#"{"public_key": "not base64"}"#,
        );

        assert!(KeyDocument::parse(&json).unwrap().denylist().is_err());
    }

    #[test]
    fn an_absent_revocation_list_means_nothing_is_revoked() {
        let json = format!(
            r#"{{"trust_root": "acme.com", "keys": [{}]}}"#,
            ed25519_entry("current", &key())
        );

        let denylist = KeyDocument::parse(&json).unwrap().denylist().unwrap();

        assert_eq!(denylist.revoked_key_count(), 0);
    }

    #[test]
    fn a_document_must_name_the_root_it_was_fetched_for() {
        let json = document_with(&ed25519_entry("current", &key()), "");
        let document = KeyDocument::parse(&json).unwrap();

        assert!(document.check_belongs_to("acme.com").is_ok());

        let error = document
            .check_belongs_to("evil.example")
            .expect_err("a document for another root must be refused");
        assert!(
            matches!(error, AttestationError::TrustRootMismatch { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_document_over_the_length_cap_is_refused_before_it_is_parsed() {
        let json = format!(
            r#"{{"trust_root": "{}", "keys": []}}"#,
            "a".repeat(MAX_DOCUMENT_LENGTH)
        );

        let error = KeyDocument::parse(&json).unwrap_err();

        assert!(
            matches!(&error, AttestationError::InvalidClaims { reason } if reason.contains("maximum")),
            "{error}"
        );
    }

    #[test]
    fn more_keys_than_the_cap_allows_is_refused() {
        let entries: Vec<String> = (0..=MAX_KEYS)
            .map(|n| ed25519_entry(&format!("key-{n}"), &key()))
            .collect();
        let json = document_with(&entries.join(", "), "");

        let error = KeyDocument::parse(&json).unwrap_err();

        assert!(
            matches!(&error, AttestationError::InvalidClaims { reason } if reason.contains("over the maximum")),
            "{error}"
        );
    }

    #[test]
    fn a_document_round_trips_through_its_own_serialization() {
        let json = document_with(
            &ed25519_entry("current", &key()),
            &format!(r#"{{"public_key": "{}"}}"#, key().to_base64()),
        );
        let document = KeyDocument::parse(&json).unwrap();

        let rendered = serde_json::to_string(&document).unwrap();

        assert_eq!(KeyDocument::parse(&rendered).unwrap(), document);
    }
}
