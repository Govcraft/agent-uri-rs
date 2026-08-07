//! The values this backend stores in Kademlia, and their encoding.
//!
//! Three record shapes travel over the overlay. Each is tagged so that a value
//! read from one key can never be interpreted as another shape, even though
//! [`crate::keys`] already domain-separates the keys themselves.
//!
//! # Why records are stored verbatim
//!
//! Kademlia replicates and caches records by copying their bytes between nodes.
//! Nothing in this crate rewrites a stored value: a node either accepts a
//! received record unchanged or rejects it. That is what makes verbatim
//! propagation safe. A design where each node adjusted the record it stored,
//! by clamping an expiry or normalizing a field, would have every replica
//! holding a value whose signature no longer checks out at the next hop.
//!
//! Convergence therefore comes from the *choice* between records rather than
//! from editing them: identity records are ordered, and pointer pages merge by
//! union.

use std::time::{Duration, SystemTime};

use agent_uri_attestation::Signature;
use agent_uri_dht::{MutationKind, Registration};
use serde::{Deserialize, Serialize};

/// Encoding version. A record whose first byte is anything else is from a
/// protocol this node does not speak, and is discarded rather than guessed at.
const ENCODING_VERSION: u8 = 1;

/// Which of the three record shapes a value holds.
///
/// Read from the value rather than inferred from the key. Record keys are
/// hashes and carry no structure, so a node handed a value has nothing else to
/// go on when deciding which validator to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One agent's signed registration.
    Identity = 1,
    /// A capability path's shard level.
    Descriptor = 2,
    /// One page of a capability path's pointers.
    Page = 3,
}

/// Reports which shape a value claims to be, without decoding its body.
///
/// # Errors
///
/// Returns [`CodecError`] if the value is empty, announces another encoding
/// version, or names no shape this node knows.
pub fn classify(bytes: &[u8]) -> Result<Shape, CodecError> {
    let (&version, rest) = bytes.split_first().ok_or(CodecError::Empty)?;
    if version != ENCODING_VERSION {
        return Err(CodecError::UnknownVersion(version));
    }
    match rest.first() {
        Some(1) => Ok(Shape::Identity),
        Some(2) => Ok(Shape::Descriptor),
        Some(3) => Ok(Shape::Page),
        _ => Err(CodecError::ShapeMismatch),
    }
}

/// A value read from the overlay that this node could not make sense of.
///
/// `#[non_exhaustive]`, so a `match` on this enum needs a `_` arm. A wire
/// format grows new ways to be wrong; each should be nameable without a major
/// release, and every one of them still means the value is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The value was empty, so it carries no version byte.
    Empty,
    /// The value announces an encoding version this node does not implement.
    UnknownVersion(u8),
    /// The value decoded, but as a different record shape than the key implies.
    ShapeMismatch,
    /// The value's bytes are not a well-formed record.
    Malformed,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("record value is empty"),
            Self::UnknownVersion(v) => {
                write!(
                    f,
                    "record announces encoding version {v}, which this node does not speak"
                )
            }
            Self::ShapeMismatch => {
                f.write_str("record decoded as a different shape than its key holds")
            }
            Self::Malformed => f.write_str("record value is not a well-formed record"),
        }
    }
}

impl std::error::Error for CodecError {}

/// One agent's registration as published to the overlay.
///
/// The record carries the full state after the write, plus the signature that
/// authorized it. Which mutation the signature covers is part of the record,
/// because the signed bytes differ per mutation kind: a validator has to know
/// which payload to reconstruct before it can check anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityRecord {
    /// The registration as it stands after this write.
    ///
    /// For a deregistration this is the tombstone: the same record with its
    /// endpoints cleared.
    pub state: Registration,
    /// Which mutation the signature authorizes.
    pub kind: WireKind,
    /// The TTL a refresh asked for, in milliseconds.
    ///
    /// Present only for [`WireKind::Refresh`], whose signed payload covers the
    /// requested duration rather than the resulting instant.
    pub refresh_ttl_millis: Option<u64>,
    /// The agent key's signature over this write.
    pub signature: WireSignature,
}

/// An Ed25519 signature as it travels between nodes.
///
/// A newtype because a signature is fixed width and serde has no impl for a
/// 64-byte array. Decoding checks the length, so a short or long value is a
/// malformed record rather than a signature that fails to verify for reasons
/// nobody can see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireSignature([u8; 64]);

impl WireSignature {
    /// Wraps the raw bytes of a signature.
    #[must_use]
    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of the signature.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl From<Signature> for WireSignature {
    fn from(signature: Signature) -> Self {
        Self(signature.to_bytes())
    }
}

impl From<WireSignature> for Signature {
    fn from(signature: WireSignature) -> Self {
        Self::from_bytes(signature.0)
    }
}

impl Serialize for WireSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for WireSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <&[u8]>::deserialize(deserializer)?;
        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))?;
        Ok(Self(bytes))
    }
}

/// [`MutationKind`] as it appears on the wire.
///
/// A separate type because the numbering is protocol, not an implementation
/// detail of the core crate: it has to stay put across versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WireKind {
    /// The record was created, or recreated after a deregistration.
    Register = 1,
    /// The record's endpoints were replaced.
    UpdateEndpoint = 2,
    /// The record's lifetime was extended.
    Refresh = 3,
    /// The record was removed, and this is its tombstone.
    Deregister = 4,
}

impl From<WireKind> for MutationKind {
    fn from(kind: WireKind) -> Self {
        match kind {
            WireKind::Register => Self::Register,
            WireKind::UpdateEndpoint => Self::UpdateEndpoint,
            WireKind::Refresh => Self::Refresh,
            WireKind::Deregister => Self::Deregister,
        }
    }
}

impl From<MutationKind> for WireKind {
    fn from(kind: MutationKind) -> Self {
        match kind {
            MutationKind::Register => Self::Register,
            MutationKind::UpdateEndpoint => Self::UpdateEndpoint,
            MutationKind::Refresh => Self::Refresh,
            MutationKind::Deregister => Self::Deregister,
        }
    }
}

impl IdentityRecord {
    /// Returns true if this record removes the agent rather than publishing it.
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        matches!(self.kind, WireKind::Deregister)
    }

    /// Returns the TTL a refresh record asked for.
    #[must_use]
    pub fn refresh_ttl(&self) -> Option<Duration> {
        self.refresh_ttl_millis.map(Duration::from_millis)
    }

    /// Returns the position of this write in the record's history.
    ///
    /// Ordering is lexicographic over `(registered_at, sequence)`. The sequence
    /// alone orders writes within one record's life but resets when an agent
    /// deregisters and returns, so the registration time is what distinguishes
    /// one incarnation of a URI from the next.
    #[must_use]
    pub fn version(&self) -> (u64, u64) {
        (millis(self.state.registered_at()), self.state.sequence())
    }

    /// Encodes this record for publication.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::Malformed`] if the record cannot be serialized,
    /// which in practice means a field held a value the encoding cannot
    /// represent.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(Shape::Identity, self)
    }

    /// Decodes a record published by another node.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the value is empty, announces another
    /// encoding version, decodes as another record shape, or is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(Shape::Identity, bytes)
    }
}

/// A pointer from a capability path to an agent registered beneath it.
///
/// Pointers are hints, not authority. Nothing signs them, and a node that
/// wanted to could put any URI in any page. What stops that being an attack is
/// that a reader dereferences every pointer to the agent's own identity record
/// and checks the capability path it finds there against the path it queried.
/// An injected pointer therefore costs a wasted read and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pointer {
    /// The canonical agent URI this pointer names.
    pub agent_uri: String,
    /// When the pointer stops being worth following, in milliseconds since the
    /// Unix epoch.
    pub expires_at_millis: u64,
}

impl Pointer {
    /// Creates a pointer to an agent, valid until the given instant.
    #[must_use]
    pub fn new(agent_uri: impl Into<String>, expires_at: SystemTime) -> Self {
        Self {
            agent_uri: agent_uri.into(),
            expires_at_millis: millis(expires_at),
        }
    }

    /// Returns true if this pointer is no longer worth following at `now`.
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        millis(now) >= self.expires_at_millis
    }
}

/// One page of a capability path's pointers.
///
/// A page is a grow-only set with per-entry expiry: merging two copies unions
/// their entries and keeps the later expiry for any URI in both. That makes
/// the value a conflict-free type, which is what allows Kademlia to copy pages
/// between nodes without a stale replica erasing entries a fresher one holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerPage {
    /// The pointers on this page, in no particular order.
    pub pointers: Vec<Pointer>,
}

impl PointerPage {
    /// Creates a page holding exactly these pointers.
    #[must_use]
    pub const fn new(pointers: Vec<Pointer>) -> Self {
        Self { pointers }
    }

    /// Encodes this page for publication.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::Malformed`] if the page cannot be serialized.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(Shape::Page, self)
    }

    /// Decodes a page published by another node.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the value is empty, announces another
    /// encoding version, decodes as another record shape, or is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(Shape::Page, bytes)
    }
}

/// How widely a capability path's pointers are spread.
///
/// The descriptor is read before a page key can be derived, so it sits on the
/// critical path of every lookup. It is deliberately one byte of payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardDescriptor {
    /// The shard level: the path's pointers occupy `2^level` pages.
    pub level: u8,
}

impl ShardDescriptor {
    /// Creates a descriptor at the given shard level.
    #[must_use]
    pub const fn at_level(level: u8) -> Self {
        Self { level }
    }

    /// Encodes this descriptor for publication.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::Malformed`] if the descriptor cannot be
    /// serialized.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(Shape::Descriptor, self)
    }

    /// Decodes a descriptor published by another node.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if the value is empty, announces another
    /// encoding version, decodes as another record shape, or is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        decode(Shape::Descriptor, bytes)
    }
}

/// Milliseconds since the Unix epoch, saturating at both ends.
///
/// Matches the resolution `Registration`'s own serialization uses, so a record
/// that has been over the wire and one that has not order identically.
pub(crate) fn millis(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn encode<T: Serialize>(shape: Shape, value: &T) -> Result<Vec<u8>, CodecError> {
    let mut bytes = vec![ENCODING_VERSION, shape as u8];
    let body = postcard::to_stdvec(value).map_err(|_| CodecError::Malformed)?;
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

fn decode<T: for<'de> Deserialize<'de>>(shape: Shape, bytes: &[u8]) -> Result<T, CodecError> {
    let (&version, rest) = bytes.split_first().ok_or(CodecError::Empty)?;
    if version != ENCODING_VERSION {
        return Err(CodecError::UnknownVersion(version));
    }
    let (&tag, body) = rest.split_first().ok_or(CodecError::Malformed)?;
    if tag != shape as u8 {
        return Err(CodecError::ShapeMismatch);
    }
    postcard::from_bytes(body).map_err(|_| CodecError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_uri::AgentUri;
    use agent_uri_attestation::SigningKey;
    use agent_uri_dht::Endpoint;

    fn registration() -> Registration {
        let uri =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        Registration::new(
            uri,
            SigningKey::generate().verifying_key(),
            vec![Endpoint::https("agent.anthropic.com:443")],
        )
    }

    fn identity() -> IdentityRecord {
        IdentityRecord {
            state: registration(),
            kind: WireKind::Register,
            refresh_ttl_millis: None,
            signature: WireSignature::new([7u8; 64]),
        }
    }

    #[test]
    fn identity_record_round_trips() {
        let record = identity();
        let decoded = IdentityRecord::decode(&record.encode().unwrap()).unwrap();
        assert_eq!(decoded.state.agent_uri(), record.state.agent_uri());
        assert_eq!(decoded.signature, record.signature);
        assert_eq!(decoded.kind, WireKind::Register);
        assert_eq!(decoded.state.endpoints(), record.state.endpoints());
        assert_eq!(decoded.state.agent_key(), record.state.agent_key());
    }

    #[test]
    fn pointer_page_round_trips() {
        let page = PointerPage::new(vec![Pointer::new("agent://a.com/b/c_1", SystemTime::now())]);
        assert_eq!(PointerPage::decode(&page.encode().unwrap()).unwrap(), page);
    }

    #[test]
    fn descriptor_round_trips() {
        let descriptor = ShardDescriptor::at_level(5);
        assert_eq!(
            ShardDescriptor::decode(&descriptor.encode().unwrap()).unwrap(),
            descriptor
        );
    }

    #[test]
    fn classify_reads_the_shape_without_the_body() {
        assert_eq!(
            classify(&identity().encode().unwrap()).unwrap(),
            Shape::Identity
        );
        assert_eq!(
            classify(&PointerPage::default().encode().unwrap()).unwrap(),
            Shape::Page
        );
        assert_eq!(
            classify(&ShardDescriptor::default().encode().unwrap()).unwrap(),
            Shape::Descriptor
        );
        assert_eq!(classify(&[]).unwrap_err(), CodecError::Empty);
        assert_eq!(classify(&[1, 99]).unwrap_err(), CodecError::ShapeMismatch);
        assert_eq!(
            classify(&[9, 1]).unwrap_err(),
            CodecError::UnknownVersion(9)
        );
    }

    #[test]
    fn a_page_does_not_decode_as_an_identity_record() {
        // Keys are domain-separated, so this should be unreachable. The tag is
        // there for the case where it is not: a decode that guessed would hand
        // the validator a record built from someone else's bytes.
        let page = PointerPage::new(vec![]).encode().unwrap();
        assert_eq!(
            IdentityRecord::decode(&page).unwrap_err(),
            CodecError::ShapeMismatch
        );
    }

    #[test]
    fn an_unknown_version_is_refused_not_guessed_at() {
        let mut bytes = identity().encode().unwrap();
        bytes[0] = 99;
        assert_eq!(
            IdentityRecord::decode(&bytes).unwrap_err(),
            CodecError::UnknownVersion(99)
        );
    }

    #[test]
    fn an_empty_value_is_refused() {
        assert_eq!(IdentityRecord::decode(&[]).unwrap_err(), CodecError::Empty);
    }

    #[test]
    fn truncated_bytes_are_refused() {
        let bytes = identity().encode().unwrap();
        assert!(IdentityRecord::decode(&bytes[..bytes.len() / 2]).is_err());
    }

    #[test]
    fn version_orders_by_instance_then_sequence() {
        let mut a = identity();
        a.state = a.state.clone().with_sequence(9);
        let mut b = identity();
        b.state = b
            .state
            .clone()
            .with_registered_at(a.state.registered_at() + Duration::from_secs(1))
            .with_sequence(0);

        // A later incarnation outranks a higher sequence in an earlier one.
        assert!(b.version() > a.version());
    }

    #[test]
    fn a_deregistration_is_a_tombstone() {
        let record = IdentityRecord {
            kind: WireKind::Deregister,
            ..identity()
        };
        assert!(record.is_tombstone());
        assert!(!identity().is_tombstone());
    }

    #[test]
    fn wire_kinds_map_onto_mutation_kinds_both_ways() {
        for kind in [
            WireKind::Register,
            WireKind::UpdateEndpoint,
            WireKind::Refresh,
            WireKind::Deregister,
        ] {
            assert_eq!(WireKind::from(MutationKind::from(kind)), kind);
        }
    }

    #[test]
    fn a_pointer_expires() {
        let now = SystemTime::now();
        let stale = Pointer::new("agent://a.com/b/c_1", now - Duration::from_secs(1));
        let fresh = Pointer::new("agent://a.com/b/c_1", now + Duration::from_mins(1));
        assert!(stale.is_expired(now));
        assert!(!fresh.is_expired(now));
    }

    #[test]
    fn a_registration_and_its_attestation_fit_the_wire_limit() {
        // The spike in issue #72 put the ceiling at 16 KiB per record, and the
        // whole pointer design exists because a subtree does not fit. One
        // registration has to, or the design fails at its own first step.
        let record = IdentityRecord {
            state: registration().with_attestation("v4.public.".to_string() + &"x".repeat(8000)),
            ..identity()
        };
        let encoded = record.encode().unwrap();
        assert!(
            encoded.len() < 16 * 1024,
            "one registration at the 8 KiB token cap encoded to {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn a_page_holds_the_pointer_count_the_spec_publishes() {
        // SPECIFICATION.md Appendix C.4 publishes ~220 pointers per 16 KiB page
        // at typical URI lengths, and that figure is what §6.2 requirement 6's
        // case for sharding rests on. An encoding change that halved it would
        // leave the spec quoting a number nothing produces.
        let uri = "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q";
        let now = SystemTime::now();
        let page = PointerPage::new((0..220).map(|_| Pointer::new(uri, now)).collect());
        let encoded = page.encode().unwrap().len();
        assert!(
            encoded <= 16 * 1024,
            "220 pointers encoded to {encoded} bytes, over the 16 KiB wire limit"
        );

        // And the other end of the range: a page of maximum-length URIs holds
        // far fewer, which is why pointers move the ceiling rather than remove
        // it. Only sharding removes it.
        let long = format!(
            "agent://{}/{}/{}_01h455vb4pex5vsknk084sn02q",
            "a".repeat(115) + ".example.com",
            vec!["s".repeat(51); 5].join("/"),
            "p".repeat(63)
        );
        let page = PointerPage::new((0..33).map(|_| Pointer::new(long.clone(), now)).collect());
        assert!(page.encode().unwrap().len() <= 16 * 1024);
    }
}
