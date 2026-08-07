//! The signed form of a key document, and what a verifier makes of it.
//!
//! [Specification](https://github.com/Govcraft/agent-uri-rs/blob/main/SPECIFICATION.md)
//! section 7.2 authenticates a key document by the channel it arrives over:
//! HTTPS, no redirects, and the document naming the root whose endpoint served
//! it. Every one of those says where the bytes came from, and every one of them
//! is satisfied by an attacker who can write to the web host — which is why
//! section 8.12 treats publication-host compromise as its own threat.
//!
//! The signed form closes that. A trust root MAY serve, at the same endpoint,
//! its document wrapped in a signature by a **root key** it holds offline:
//!
//! ```json
//! {
//!   "signed": {
//!     "trust_root": "acme.com",
//!     "version": 4,
//!     "expires": "2026-08-14T00:00:00Z",
//!     "keys": [ ... ],
//!     "revoked_keys": [ ... ]
//!   },
//!   "signatures": [{
//!     "root_kid": "root-2026",
//!     "signature": "<base64 of 64 bytes>"
//!   }]
//! }
//! ```
//!
//! Publication then becomes a file copy: the host never holds material whose
//! theft mints trust.
//!
//! # What the signature covers
//!
//! ```text
//! "agent-uri-key-document-v1\n" || <the exact octets of the `signed` value>
//! ```
//!
//! There is no canonicalization. The document is signed as serialized and
//! verified as received, so a publisher and a verifier never have to agree on
//! how to re-encode JSON — only on the bytes that were sent. That is why
//! [`SignedKeyDocument`] keeps the payload's raw octets rather than re-rendering
//! the parsed value: re-rendering would make the signature depend on this
//! crate's serializer, and any other serializer's document would fail against a
//! signature that was perfectly good.
//!
//! The prefix is a domain separator, so a signature minted over a key document
//! cannot be presented as a signature over anything else these keys sign.
//!
//! # Where the authority comes from
//!
//! From the pinned key the caller supplies, and from nowhere else. The root key
//! MUST NOT appear in the document's own `keys`, and this module never looks
//! there for one: a signature checked against a key the same document publishes
//! proves nothing, because whoever wrote the file wrote the key.
//!
//! A verifier that pins no key for a root can still read what that root serves —
//! [`ServedDocument`] parses both forms — but what it holds is then evidence on
//! exactly the terms of the bare form. That is deliberate: it lets a root adopt
//! signing without breaking verifiers that have not pinned it.

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::AttestationError;
use crate::key_document::{KeyDocument, MAX_DOCUMENT_LENGTH};
use crate::keys::{Signature, SigningKey, VerifyingKey};

/// The domain separator prefixed to a key document before it is signed.
///
/// Ends in a newline, as section 7.2 specifies. Its job is to keep a signature
/// minted over a key document from being presentable as a signature over
/// anything else a root key signs.
pub const DOCUMENT_SIGNING_PREFIX: &str = "agent-uri-key-document-v1\n";

/// The most signatures one envelope may carry.
///
/// Each one is tried against each pinned key, so this bounds what a served
/// document can make a verifier compute. Room for a root-key rotation with
/// overlap, and then some; a root needing more than eight has a key-management
/// problem this cap is not the right place to solve.
pub const MAX_SIGNATURES: usize = 8;

/// The clock-skew tolerance applied to a document's `expires` by default.
///
/// The same minute [`Verifier::DEFAULT_LEEWAY`](crate::Verifier::DEFAULT_LEEWAY)
/// gives a token's `exp`, and for the same reason: publisher and verifier run
/// different clocks, and a verifier whose clock runs fast should not lose the
/// keys of a root that is publishing on schedule.
pub const DEFAULT_DOCUMENT_LEEWAY: Duration = Duration::from_mins(1);

/// How many times a trust root has published its key document.
///
/// A root increments this on every publication, and a verifier refuses a
/// document older than the newest it has accepted. That is what stops an
/// attacker who controls the web host from replaying a validly signed document
/// that predates a revocation: the signature is genuine, and the version says
/// it is behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DocumentVersion(u64);

impl DocumentVersion {
    /// The version of a root's first publication.
    pub const FIRST: Self = Self(1);

    /// Names a specific publication.
    #[must_use]
    pub const fn new(version: u64) -> Self {
        Self(version)
    }

    /// The counter as published.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The version of the publication after this one.
    ///
    /// `None` only at `u64::MAX`, which no publication schedule reaches.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl fmt::Display for DocumentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One entry of an envelope's `signatures`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentSignature {
    /// What the root calls the key that produced this signature, if it says.
    ///
    /// Advisory, and deliberately not used to choose which key to check
    /// against: it is written by whoever wrote the document, so letting it
    /// select a key would let the document decide how it is verified. Every
    /// pinned key is tried against every signature instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_kid: Option<String>,
    /// The Ed25519 signature, base64 of 64 bytes.
    pub signature: String,
}

impl DocumentSignature {
    /// Reads the signature bytes.
    fn to_signature(&self) -> Result<Signature, AttestationError> {
        let decoded =
            BASE64
                .decode(&self.signature)
                .map_err(|error| AttestationError::InvalidKeyFormat {
                    reason: format!("a document signature is not valid base64: {error}"),
                })?;
        let bytes: [u8; 64] =
            decoded
                .try_into()
                .map_err(|decoded: Vec<u8>| AttestationError::InvalidKeyFormat {
                    reason: format!(
                        "an Ed25519 signature is 64 bytes, but this decoded to {}",
                        decoded.len()
                    ),
                })?;
        Ok(Signature::from_bytes(bytes))
    }
}

/// What a signature covers: a key document, plus when it was published and how
/// long it stands.
///
/// The two extra fields are what make a signature worth more than the bytes it
/// authenticates. Without `version`, an attacker holding the web host can serve
/// an older document the root really signed, and so undo a revocation; without
/// `expires`, it can do so forever.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{
///     DocumentSigner, DocumentVersion, KeyDocument, KeyDocumentPayload, SigningKey,
/// };
/// use chrono::{Duration, Utc};
///
/// # let key = SigningKey::generate().verifying_key().to_base64();
/// # let json = format!(r#"{{"trust_root": "acme.com", "keys": [{{
/// #     "kid": "key-2026-01", "algorithm": "Ed25519", "public_key": "{key}",
/// #     "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"
/// # }}]}}"#);
/// let document = KeyDocument::parse(&json)?;
///
/// // The root key. It is not in `keys`, and it never leaves the offline host.
/// let root_key = SigningKey::generate();
///
/// let payload = KeyDocumentPayload::new(
///     document,
///     DocumentVersion::FIRST,
///     Utc::now() + Duration::days(7),
/// );
/// let published = payload.to_signed_json(&[DocumentSigner::new(&root_key).named("root-2026")])?;
///
/// // What a verifier holding the pinned root key makes of it.
/// let served = agent_uri_attestation::SignedKeyDocument::parse(&published)?;
/// let verified = served.verify(&[root_key.verifying_key()])?;
/// assert_eq!(verified.version(), DocumentVersion::FIRST);
/// # Ok::<(), agent_uri_attestation::AttestationError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDocumentPayload {
    #[serde(flatten)]
    document: KeyDocument,
    version: DocumentVersion,
    expires: DateTime<Utc>,
}

impl KeyDocumentPayload {
    /// The payload a trust root signs.
    #[must_use]
    pub const fn new(
        document: KeyDocument,
        version: DocumentVersion,
        expires: DateTime<Utc>,
    ) -> Self {
        Self {
            document,
            version,
            expires,
        }
    }

    /// The key document itself.
    #[must_use]
    pub const fn document(&self) -> &KeyDocument {
        &self.document
    }

    /// Which publication this is.
    #[must_use]
    pub const fn version(&self) -> DocumentVersion {
        self.version
    }

    /// When this document stops being evidence of anything.
    #[must_use]
    pub const fn expires(&self) -> DateTime<Utc> {
        self.expires
    }

    /// Takes the key document out, leaving the publication metadata behind.
    ///
    /// For the caller that has already read `version` and `expires` and wants
    /// the document itself without copying it again.
    #[must_use]
    pub fn into_document(self) -> KeyDocument {
        self.document
    }

    /// Renders the envelope a trust root serves.
    ///
    /// The payload is serialized once and every signature covers exactly those
    /// octets, which are the octets that go on the wire. A publisher that
    /// re-encoded the payload between signing and serving would produce a
    /// document its own signature did not cover.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidClaims`] when no signer is supplied,
    /// when more than [`MAX_SIGNATURES`] are, or when the rendered document
    /// would be longer than [`MAX_DOCUMENT_LENGTH`] — a document this crate
    /// would decline to read is not one it should mint.
    pub fn to_signed_json(
        &self,
        signers: &[DocumentSigner<'_>],
    ) -> Result<String, AttestationError> {
        if signers.is_empty() {
            return Err(AttestationError::InvalidClaims {
                reason: "a signed key document needs at least one signer".to_string(),
            });
        }
        check_signature_count(signers.len())?;

        let payload = serde_json::to_string(self).map_err(|e| serialization_failed(&e))?;
        let signatures = signers
            .iter()
            .map(|signer| signer.sign(payload.as_bytes()))
            .collect();
        let signed = RawValue::from_string(payload).map_err(|e| serialization_failed(&e))?;

        let envelope = serde_json::to_string(&Envelope { signed, signatures })
            .map_err(|e| serialization_failed(&e))?;

        if envelope.len() > MAX_DOCUMENT_LENGTH {
            return Err(AttestationError::InvalidClaims {
                reason: format!(
                    "the signed document is {} bytes, over the {MAX_DOCUMENT_LENGTH}-byte maximum \
                     a verifier will read",
                    envelope.len()
                ),
            });
        }

        Ok(envelope)
    }
}

/// A root key, and the name the published document gives it.
///
/// Borrowed rather than owned because signing is a moment, not a lifetime: the
/// key comes out of wherever it is kept, signs, and goes back.
#[derive(Debug, Clone, Copy)]
pub struct DocumentSigner<'a> {
    key: &'a SigningKey,
    root_kid: Option<&'a str>,
}

impl<'a> DocumentSigner<'a> {
    /// Signs with this key, publishing no name for it.
    #[must_use]
    pub const fn new(key: &'a SigningKey) -> Self {
        Self {
            key,
            root_kid: None,
        }
    }

    /// Publishes a name alongside the signature.
    ///
    /// Operational only: it tells whoever is reading the document which of a
    /// root's keys signed it. No verifier decides anything by it.
    #[must_use]
    pub const fn named(mut self, root_kid: &'a str) -> Self {
        self.root_kid = Some(root_kid);
        self
    }

    /// Signs the payload octets, prefix and all.
    fn sign(&self, payload: &[u8]) -> DocumentSignature {
        let signature = self.key.sign(&signing_input(payload));
        DocumentSignature {
            root_kid: self.root_kid.map(ToString::to_string),
            signature: BASE64.encode(signature.to_bytes()),
        }
    }
}

/// The envelope, as it is serialized and deserialized.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    signed: Box<RawValue>,
    signatures: Vec<DocumentSignature>,
}

/// Answers whether a body is in the signed form, without committing to reading it.
#[derive(Deserialize)]
struct FormProbe {
    #[serde(default)]
    signed: Option<IgnoredAny>,
}

/// A key document served inside a signature envelope, before the signature has
/// been checked.
///
/// Parsing gets you the shape. [`Self::verify`] is what gets you the payload,
/// and the only thing that should: the whole point of the signed form is that
/// what the document says is worth nothing until a pinned key vouches for it.
/// [`Self::unverified_payload`] exists for the verifier that pins no key for
/// this root and is knowingly trusting the channel instead; its name is the
/// warning.
#[derive(Debug)]
pub struct SignedKeyDocument {
    /// The exact octets the signature covers.
    signed: Box<RawValue>,
    signatures: Vec<DocumentSignature>,
    payload: KeyDocumentPayload,
}

impl SignedKeyDocument {
    /// Reads an envelope. Checks no signature.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidClaims`] when the document is longer
    /// than [`MAX_DOCUMENT_LENGTH`], is not the JSON section 7.2 specifies for
    /// the signed form, carries no signature or more than [`MAX_SIGNATURES`],
    /// or publishes more keys than a key document may.
    pub fn parse(json: &str) -> Result<Self, AttestationError> {
        check_document_length(json.len())?;

        let envelope: Envelope =
            serde_json::from_str(json).map_err(|e| AttestationError::InvalidClaims {
                reason: format!("key document is not the signed JSON of specification 7.2: {e}"),
            })?;

        if envelope.signatures.is_empty() {
            return Err(AttestationError::DocumentUnsigned);
        }
        check_signature_count(envelope.signatures.len())?;

        let payload: KeyDocumentPayload = serde_json::from_str(envelope.signed.get()).map_err(
            |e| AttestationError::InvalidClaims {
                reason: format!(
                    "the signed part of the key document is not what specification 7.2 requires \
                     (a key document plus 'version' and 'expires'): {e}"
                ),
            },
        )?;
        payload.document.check_limits()?;

        Ok(Self {
            signed: envelope.signed,
            signatures: envelope.signatures,
            payload,
        })
    }

    /// The octet string the signatures are over.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(self.signed.get().as_bytes())
    }

    /// The signatures as served, none of them checked.
    #[must_use]
    pub fn signatures(&self) -> &[DocumentSignature] {
        &self.signatures
    }

    /// The payload before any signature has been checked.
    ///
    /// For the verifier that pins no root key for this trust root, and is
    /// therefore trusting the TLS channel exactly as it does for the bare form.
    /// A verifier that holds a pinned key must use [`Self::verify`] instead;
    /// what this returns is whatever the endpoint said.
    #[must_use]
    pub const fn unverified_payload(&self) -> &KeyDocumentPayload {
        &self.payload
    }

    /// Checks the document against pinned root keys, with the default leeway.
    ///
    /// # Errors
    ///
    /// As [`Self::verify_at`].
    pub fn verify(&self, pinned: &[VerifyingKey]) -> Result<KeyDocumentPayload, AttestationError> {
        self.verify_at(pinned, Utc::now(), DEFAULT_DOCUMENT_LEEWAY)
    }

    /// Checks the document against pinned root keys at a stated time.
    ///
    /// One valid signature by one pinned key is enough, which is what lets a
    /// root key rotate: publish signed by the outgoing and incoming keys for
    /// the overlap, and a verifier holding either pin keeps working.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidSignature`] when no signature in the
    /// document was produced by any pinned key, and
    /// [`AttestationError::DocumentExpired`] when `expires` has passed by more
    /// than `leeway`.
    ///
    /// An entry that does not decode is not a valid signature and is passed
    /// over rather than made fatal, so a stray malformed entry cannot cost a
    /// verifier a document a pinned key really did sign. If nothing verified
    /// *and* something was unreadable, the unreadable entry is what is
    /// reported: it is the more actionable of the two for whoever publishes the
    /// document.
    ///
    /// The payload comes back owned rather than borrowed, so that what a caller
    /// carries onward is the checked document and not a borrow of the envelope
    /// it arrived in. A key document is bounded by
    /// [`MAX_DOCUMENT_LENGTH`] and is read about once per cache lifetime, so the
    /// copy costs nothing worth the lifetime it would otherwise impose.
    pub fn verify_at(
        &self,
        pinned: &[VerifyingKey],
        now: DateTime<Utc>,
        leeway: Duration,
    ) -> Result<KeyDocumentPayload, AttestationError> {
        let message = self.signing_input();

        let mut unreadable = None;
        let mut verified = false;
        for entry in &self.signatures {
            let signature = match entry.to_signature() {
                Ok(signature) => signature,
                Err(error) => {
                    unreadable.get_or_insert(error);
                    continue;
                }
            };
            if pinned
                .iter()
                .any(|key| key.verify(&message, &signature).is_ok())
            {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(unreadable.unwrap_or(AttestationError::InvalidSignature));
        }

        check_document_expiry(self.payload.expires, now, leeway)?;

        Ok(self.payload.clone())
    }
}

/// Which of the two forms section 7.2 defines a served body is in.
///
/// A verifier has to be able to tell them apart before it can apply a policy to
/// either: a pinned root that serves the bare form has to be refused, and an
/// unpinned root that serves the signed form has to keep working.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServedDocument {
    /// The bare form. Authenticated by nothing but the channel it arrived over.
    Bare(KeyDocument),
    /// The signed form, before any signature has been checked.
    Signed(SignedKeyDocument),
}

impl ServedDocument {
    /// Reads whichever form the body is in. Checks no signature.
    ///
    /// # Errors
    ///
    /// As [`KeyDocument::parse`] or [`SignedKeyDocument::parse`], whichever the
    /// body turned out to be. A body carrying a `signed` member is read as the
    /// signed form and is not retried as the bare form: half a signed document
    /// is not a bare one, and reporting it as malformed says so.
    pub fn parse(json: &str) -> Result<Self, AttestationError> {
        check_document_length(json.len())?;

        let probe: FormProbe =
            serde_json::from_str(json).map_err(|e| AttestationError::InvalidClaims {
                reason: format!("key document is not JSON: {e}"),
            })?;

        if probe.signed.is_some() {
            SignedKeyDocument::parse(json).map(Self::Signed)
        } else {
            KeyDocument::parse(json).map(Self::Bare)
        }
    }

    /// The document either form carries, before any signature has been checked.
    ///
    /// What a verifier holding no pinned key for this root acts on, in both
    /// cases on the terms of the bare form.
    #[must_use]
    pub const fn unverified_document(&self) -> &KeyDocument {
        match self {
            Self::Bare(document) => document,
            Self::Signed(signed) => signed.payload.document(),
        }
    }
}

/// The octet string a document signature is over.
fn signing_input(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOCUMENT_SIGNING_PREFIX.len() + payload.len());
    message.extend_from_slice(DOCUMENT_SIGNING_PREFIX.as_bytes());
    message.extend_from_slice(payload);
    message
}

/// Refuses a document past its `expires`, allowing for clock skew.
///
/// A document is expired once `now` has passed `expires + leeway`. The tolerance
/// exists because the trust root's clock and the verifier's clock are different
/// clocks; it cuts both ways, so it belongs at the smallest value covering the
/// fleet's spread rather than the largest that avoids complaints.
///
/// The addition saturates rather than panicking, so a leeway large enough to
/// run off the end of representable time forgives every expiry instead of
/// taking the process down. That is a caller's own instruction and never
/// something the served document can influence.
///
/// # Errors
///
/// Returns [`AttestationError::DocumentExpired`] when `now > expires + leeway`.
/// The reported instant is the document's real `expires`, not the extended one.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use agent_uri_attestation::check_document_expiry;
/// use chrono::Utc;
///
/// let expires = Utc::now();
/// let just_after = expires + chrono::Duration::seconds(10);
///
/// assert!(check_document_expiry(expires, just_after, Duration::ZERO).is_err());
/// assert!(check_document_expiry(expires, just_after, Duration::from_secs(30)).is_ok());
/// ```
pub fn check_document_expiry(
    expires: DateTime<Utc>,
    now: DateTime<Utc>,
    leeway: Duration,
) -> Result<(), AttestationError> {
    let tolerance = chrono::Duration::from_std(leeway).unwrap_or(chrono::Duration::MAX);
    let deadline = expires
        .checked_add_signed(tolerance)
        .unwrap_or(DateTime::<Utc>::MAX_UTC);

    if now > deadline {
        return Err(AttestationError::DocumentExpired {
            expires: expires.to_rfc3339(),
        });
    }
    Ok(())
}

fn check_document_length(length: usize) -> Result<(), AttestationError> {
    if length > MAX_DOCUMENT_LENGTH {
        return Err(AttestationError::InvalidClaims {
            reason: format!(
                "key document is {length} bytes, over the {MAX_DOCUMENT_LENGTH}-byte maximum"
            ),
        });
    }
    Ok(())
}

fn check_signature_count(count: usize) -> Result<(), AttestationError> {
    if count > MAX_SIGNATURES {
        return Err(AttestationError::InvalidClaims {
            reason: format!(
                "key document carries {count} signatures, over the maximum of {MAX_SIGNATURES}"
            ),
        });
    }
    Ok(())
}

fn serialization_failed(error: &serde_json::Error) -> AttestationError {
    AttestationError::InvalidClaims {
        reason: format!("the key document could not be serialized: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUST_ROOT: &str = "acme.com";

    fn key_document() -> KeyDocument {
        let published = SigningKey::generate().verifying_key().to_base64();
        let json = format!(
            r#"{{"trust_root": "{TRUST_ROOT}", "keys": [{{
                 "kid": "key-2026-01", "algorithm": "Ed25519", "public_key": "{published}",
                 "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}]}}"#
        );
        KeyDocument::parse(&json).expect("the fixture document parses")
    }

    fn payload() -> KeyDocumentPayload {
        KeyDocumentPayload::new(
            key_document(),
            DocumentVersion::FIRST,
            Utc::now() + chrono::Duration::days(7),
        )
    }

    fn published_by(root_key: &SigningKey) -> String {
        payload()
            .to_signed_json(&[DocumentSigner::new(root_key).named("root-2026")])
            .expect("the fixture payload renders")
    }

    #[test]
    fn a_document_signed_by_a_pinned_root_key_verifies() {
        let root_key = SigningKey::generate();
        let served = SignedKeyDocument::parse(&published_by(&root_key)).unwrap();

        let verified = served
            .verify(&[root_key.verifying_key()])
            .expect("a document signed by the pinned key must verify");

        assert_eq!(verified.version(), DocumentVersion::FIRST);
        assert_eq!(verified.document().trust_root(), TRUST_ROOT);
    }

    #[test]
    fn a_document_signed_by_a_key_nobody_pinned_is_refused() {
        // The entire mechanism: authority comes from the pin, not from the
        // document. A stranger's signature is as good as no signature.
        let stranger = SigningKey::generate();
        let served = SignedKeyDocument::parse(&published_by(&stranger)).unwrap();

        assert_eq!(
            served.verify(&[SigningKey::generate().verifying_key()]),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn a_signature_by_a_key_the_document_itself_publishes_is_not_enough() {
        // Whoever wrote the file wrote `keys`, so a document that vouches for
        // itself vouches for nothing. Pinning the *published* key must not make
        // an attacker-written document verify.
        let root_key = SigningKey::generate();
        let json = published_by(&root_key);
        let served = SignedKeyDocument::parse(&json).unwrap();
        let published_key = served.unverified_payload().document().keys()[0]
            .public_key
            .clone();
        let published_key = VerifyingKey::from_base64(&published_key).unwrap();

        assert_eq!(
            served.verify(&[published_key]),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn one_signature_by_a_pinned_key_among_others_is_enough() {
        // What makes a root-key rotation survivable: the root publishes signed
        // by outgoing and incoming, and a verifier holding either pin works.
        let outgoing = SigningKey::generate();
        let incoming = SigningKey::generate();
        let json = payload()
            .to_signed_json(&[
                DocumentSigner::new(&outgoing).named("root-2026"),
                DocumentSigner::new(&incoming).named("root-2027"),
            ])
            .unwrap();
        let served = SignedKeyDocument::parse(&json).unwrap();

        assert!(served.verify(&[outgoing.verifying_key()]).is_ok());
        assert!(served.verify(&[incoming.verifying_key()]).is_ok());
    }

    #[test]
    fn a_verifier_pinning_several_keys_accepts_a_document_signed_by_any_of_them() {
        let root_key = SigningKey::generate();
        let served = SignedKeyDocument::parse(&published_by(&root_key)).unwrap();

        let pinned = [
            SigningKey::generate().verifying_key(),
            root_key.verifying_key(),
        ];

        assert!(served.verify(&pinned).is_ok());
    }

    #[test]
    fn a_document_edited_after_it_was_signed_is_refused() {
        // The attack this exists to stop: an attacker with write access to the
        // host swaps in a key of their own and keeps the root's signature.
        let root_key = SigningKey::generate();
        let attacker_key = SigningKey::generate().verifying_key().to_base64();
        let json = published_by(&root_key);

        let honest = SignedKeyDocument::parse(&json).unwrap();
        let honest_key = honest.unverified_payload().document().keys()[0]
            .public_key
            .clone();
        let tampered = json.replace(&honest_key, &attacker_key);
        assert_ne!(tampered, json, "the fixture must actually have been edited");

        assert_eq!(
            SignedKeyDocument::parse(&tampered)
                .unwrap()
                .verify(&[root_key.verifying_key()]),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn a_reformatted_payload_no_longer_verifies() {
        // Not a defect: the signature covers the octets as served, which is
        // what lets a publisher and a verifier skip agreeing on how to
        // re-encode JSON. A republishing proxy that pretty-prints the document
        // has produced a different document, and this says so rather than
        // pretending otherwise.
        let root_key = SigningKey::generate();
        let json = published_by(&root_key);
        let spaced = json.replace(r#""version""#, r#" "version""#);
        assert_ne!(spaced, json, "the fixture must actually have been respaced");

        assert_eq!(
            SignedKeyDocument::parse(&spaced)
                .unwrap()
                .verify(&[root_key.verifying_key()]),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn the_domain_separator_is_part_of_what_is_signed() {
        // Without it, a root key that signs anything else in this format could
        // have one of those signatures presented as a key document's.
        let root_key = SigningKey::generate();
        let json = published_by(&root_key);
        let served = SignedKeyDocument::parse(&json).unwrap();

        let raw_payload = serde_json::to_string(served.unverified_payload()).unwrap();
        let undecorated = root_key.sign(raw_payload.as_bytes());

        assert_eq!(
            root_key
                .verifying_key()
                .verify(&served.signing_input(), &undecorated),
            Err(AttestationError::InvalidSignature)
        );
        assert!(
            served
                .signing_input()
                .starts_with(DOCUMENT_SIGNING_PREFIX.as_bytes())
        );
    }

    #[test]
    fn a_document_past_its_expiry_is_refused_even_though_its_signature_is_good() {
        // The bound on replaying a document the root really did sign.
        let root_key = SigningKey::generate();
        let expired = KeyDocumentPayload::new(
            key_document(),
            DocumentVersion::FIRST,
            Utc::now() - chrono::Duration::days(1),
        );
        let json = expired
            .to_signed_json(&[DocumentSigner::new(&root_key)])
            .unwrap();

        let error = SignedKeyDocument::parse(&json)
            .unwrap()
            .verify(&[root_key.verifying_key()])
            .expect_err("an expired document must be refused");

        assert!(
            matches!(error, AttestationError::DocumentExpired { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_document_that_expired_within_the_leeway_is_still_accepted() {
        // Publisher and verifier run different clocks, and a verifier running a
        // few seconds fast should not lose a root that is publishing on time.
        let root_key = SigningKey::generate();
        let expires = Utc::now() - chrono::Duration::seconds(5);
        let json = KeyDocumentPayload::new(key_document(), DocumentVersion::FIRST, expires)
            .to_signed_json(&[DocumentSigner::new(&root_key)])
            .unwrap();

        assert!(
            SignedKeyDocument::parse(&json)
                .unwrap()
                .verify(&[root_key.verifying_key()])
                .is_ok()
        );
    }

    #[test]
    fn the_expiry_check_is_made_against_the_time_it_is_given() {
        let expires = Utc::now();
        let leeway = Duration::ZERO;

        assert!(check_document_expiry(expires, expires, leeway).is_ok());
        assert!(
            check_document_expiry(expires, expires + chrono::Duration::seconds(1), leeway).is_err()
        );
    }

    #[test]
    fn a_leeway_that_runs_off_the_end_of_time_forgives_rather_than_panicking() {
        // `expires + leeway` is arithmetic on a real calendar, and a caller may
        // pass any Duration. Saturating is the honest reading of a tolerance
        // that large; panicking in a verifier is not an option.
        let expires = Utc::now();

        assert!(
            check_document_expiry(
                expires,
                expires + chrono::Duration::days(365),
                Duration::MAX
            )
            .is_ok()
        );
    }

    #[test]
    fn a_payload_without_a_version_or_an_expiry_is_not_a_signed_document() {
        // They are what a signature buys beyond authenticity, so a document
        // that omits them is not the signed form however well it is signed.
        let root_key = SigningKey::generate();
        let json = published_by(&root_key);
        let served = SignedKeyDocument::parse(&json).unwrap();
        let document = serde_json::to_string(served.unverified_payload().document()).unwrap();
        let signature = &served.signatures()[0].signature;
        let without =
            format!(r#"{{"signed": {document}, "signatures": [{{"signature": "{signature}"}}]}}"#);

        assert!(matches!(
            SignedKeyDocument::parse(&without),
            Err(AttestationError::InvalidClaims { .. })
        ));
    }

    #[test]
    fn an_envelope_carrying_no_signature_is_refused() {
        let document = serde_json::to_string(&payload()).unwrap();
        let json = format!(r#"{{"signed": {document}, "signatures": []}}"#);

        assert_eq!(
            SignedKeyDocument::parse(&json).unwrap_err(),
            AttestationError::DocumentUnsigned
        );
    }

    #[test]
    fn more_signatures_than_the_cap_allows_is_refused() {
        // Each one costs a verification against each pinned key, so the number
        // a served document can demand has to be bounded.
        let keys: Vec<SigningKey> = (0..=MAX_SIGNATURES)
            .map(|_| SigningKey::generate())
            .collect();
        let signers: Vec<DocumentSigner<'_>> = keys.iter().map(DocumentSigner::new).collect();

        let error = payload()
            .to_signed_json(&signers)
            .expect_err("minting more signatures than a verifier will read must be refused");
        assert!(
            matches!(&error, AttestationError::InvalidClaims { reason } if reason.contains("over the maximum")),
            "{error}"
        );

        let json = format!(
            r#"{{"signed": {}, "signatures": [{}]}}"#,
            serde_json::to_string(&payload()).unwrap(),
            (0..=MAX_SIGNATURES)
                .map(|_| r#"{"signature": "AA=="}"#.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(matches!(
            SignedKeyDocument::parse(&json),
            Err(AttestationError::InvalidClaims { .. })
        ));
    }

    #[test]
    fn a_signed_document_over_the_length_cap_is_refused_before_it_is_parsed() {
        let json = format!(
            r#"{{"signed": {{"trust_root": "{}"}}, "signatures": []}}"#,
            "a".repeat(MAX_DOCUMENT_LENGTH)
        );

        assert!(matches!(
            SignedKeyDocument::parse(&json),
            Err(AttestationError::InvalidClaims { .. })
        ));
        assert!(matches!(
            ServedDocument::parse(&json),
            Err(AttestationError::InvalidClaims { .. })
        ));
    }

    #[test]
    fn the_key_cap_is_not_bypassed_by_wrapping_the_document_in_an_envelope() {
        // The bare parser enforces it; the signed one reaches the same fields
        // by a different route and has to enforce it too.
        let entries: Vec<String> = (0..=crate::key_document::MAX_KEYS)
            .map(|n| {
                format!(
                    r#"{{"kid": "key-{n}", "algorithm": "Ed25519", "public_key": "{}",
                         "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}"#,
                    SigningKey::generate().verifying_key().to_base64()
                )
            })
            .collect();
        let json = format!(
            r#"{{"signed": {{"trust_root": "{TRUST_ROOT}", "version": 1,
                 "expires": "2027-01-01T00:00:00Z", "keys": [{}]}},
                 "signatures": [{{"signature": "AA=="}}]}}"#,
            entries.join(", ")
        );

        let error = SignedKeyDocument::parse(&json).unwrap_err();

        assert!(
            matches!(&error, AttestationError::InvalidClaims { reason } if reason.contains("over the maximum")),
            "{error}"
        );
    }

    #[test]
    fn a_signature_that_does_not_decode_is_reported_rather_than_ignored() {
        let root_key = SigningKey::generate();
        let document = serde_json::to_string(&payload()).unwrap();
        let json =
            format!(r#"{{"signed": {document}, "signatures": [{{"signature": "not base64"}}]}}"#);

        assert!(matches!(
            SignedKeyDocument::parse(&json)
                .unwrap()
                .verify(&[root_key.verifying_key()]),
            Err(AttestationError::InvalidKeyFormat { .. })
        ));
    }

    #[test]
    fn a_signature_that_does_not_decode_does_not_cost_a_document_its_good_one() {
        // "At least one valid signature" means an unreadable entry is simply
        // not one of them. Making it fatal would let a stray character in a
        // published document deny every verifier the keys it names.
        let root_key = SigningKey::generate();
        let json = published_by(&root_key);
        let served = SignedKeyDocument::parse(&json).unwrap();
        let good = &served.signatures()[0].signature;
        let with_junk_first = format!(
            r#"{{"signed": {}, "signatures": [{{"signature": "not base64"}}, {{"signature": "{good}"}}]}}"#,
            served.signed.get()
        );

        assert!(
            SignedKeyDocument::parse(&with_junk_first)
                .unwrap()
                .verify(&[root_key.verifying_key()])
                .is_ok()
        );
    }

    #[test]
    fn to_signed_json_refuses_to_mint_a_document_with_no_signer() {
        assert!(matches!(
            payload().to_signed_json(&[]),
            Err(AttestationError::InvalidClaims { .. })
        ));
    }

    #[test]
    fn served_documents_are_told_apart_by_the_member_that_distinguishes_them() {
        let root_key = SigningKey::generate();
        let bare = serde_json::to_string(&key_document()).unwrap();

        assert!(matches!(
            ServedDocument::parse(&bare).unwrap(),
            ServedDocument::Bare(_)
        ));
        assert!(matches!(
            ServedDocument::parse(&published_by(&root_key)).unwrap(),
            ServedDocument::Signed(_)
        ));
    }

    #[test]
    fn both_forms_yield_the_same_document_to_a_verifier_that_pins_nothing() {
        // What lets a trust root adopt signing without breaking every verifier
        // that has not pinned its root key.
        let root_key = SigningKey::generate();
        let document = key_document();
        let bare = serde_json::to_string(&document).unwrap();
        let signed = KeyDocumentPayload::new(
            document.clone(),
            DocumentVersion::FIRST,
            Utc::now() + chrono::Duration::days(7),
        )
        .to_signed_json(&[DocumentSigner::new(&root_key)])
        .unwrap();

        assert_eq!(
            ServedDocument::parse(&bare).unwrap().unverified_document(),
            ServedDocument::parse(&signed)
                .unwrap()
                .unverified_document()
        );
    }

    #[test]
    fn a_half_written_signed_document_is_not_read_as_a_bare_one() {
        // Retrying it as the bare form would report "not a key document" for
        // something that is plainly trying to be a signed one, and would hide
        // the failure that matters.
        let json =
            r#"{"signed": {"trust_root": "acme.com"}, "signatures": [{"signature": "AA=="}]}"#;

        let error = ServedDocument::parse(json).unwrap_err();

        assert!(
            matches!(&error, AttestationError::InvalidClaims { reason } if reason.contains("version")),
            "{error}"
        );
    }

    #[test]
    fn a_version_counts_and_orders() {
        assert_eq!(DocumentVersion::FIRST.get(), 1);
        assert_eq!(DocumentVersion::FIRST.next(), Some(DocumentVersion::new(2)));
        assert_eq!(DocumentVersion::new(u64::MAX).next(), None);
        assert!(DocumentVersion::new(4) > DocumentVersion::new(3));
        assert_eq!(DocumentVersion::new(4).to_string(), "4");
    }

    #[test]
    fn a_payload_round_trips_through_its_own_serialization() {
        let original = payload();

        let rendered = serde_json::to_string(&original).unwrap();

        assert_eq!(
            serde_json::from_str::<KeyDocumentPayload>(&rendered).unwrap(),
            original
        );
    }
}
