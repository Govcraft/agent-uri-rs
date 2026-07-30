//! Proof that the holder of an agent's key authorized a write.
//!
//! A registration record is world-readable, so knowing an agent's URI is not
//! evidence of anything, and neither is holding a copy of the attestation
//! token stored alongside it. Every write must therefore carry a
//! [`MutationProof`]: an Ed25519 signature, made by the agent's own key, over
//! the exact operation requested. Registration signs the record it creates;
//! later writes sign against the record they found.
//!
//! # What the signature covers
//!
//! The signed bytes are derived entirely from the arguments of the call being
//! authorized, never from data the proof itself carries. A proof cannot
//! disagree with the operation it accompanies, because there is nothing in it
//! to disagree with: it is a sequence number and a signature.
//!
//! Every mutation names the **resulting** record's `expires_at`, not only the
//! arguments that produced it. A store that holds the record and applies the
//! change itself has no use for that: it computes the new expiry locally and
//! there is nothing for anyone to substitute. On a wire protocol the resulting
//! record travels whole, so any field outside the payload is a field an
//! observer can rewrite before passing the record on. Leaving `expires_at`
//! outside let an attacker who watched a legitimate migration hold a real,
//! agent-signed record open past the moment the agent chose to let it lapse
//! (issue #81).
//!
//! # Replay
//!
//! Proofs travel in the clear alongside the operations they authorize, so any
//! node on the path can keep one. Two bindings make a kept proof worthless.
//!
//! The **sequence number** orders writes within one record's life: a record
//! only accepts a write whose sequence is strictly greater than the one it
//! already holds, so a proof cannot be applied twice.
//!
//! The record's **registration time** identifies the record instance. Sequence
//! numbers alone would not survive deregistration, because a re-registered
//! record starts its history over at zero and a captured proof would sit above
//! it again. Binding the instance means a proof signed against the record an
//! agent had yesterday cannot touch the record it has today.
//!
//! Together these say a proof authorizes one operation, on one record, at one
//! point in that record's history, and nothing else.
//!
//! One residual is worth naming. Instance identity is the registration time at
//! millisecond resolution, matching what survives serialization, so two
//! registrations of the same URI inside one millisecond are indistinguishable
//! to a proof. On a network that needs an agent to re-register within a
//! millisecond of its own deregistration, but a coarse system clock widens the
//! window. An agent that continues its sequence numbering across
//! re-registration, via
//! [`Registration::with_sequence`](crate::Registration::with_sequence), does
//! not depend on the clock at all. Note that what a captured proof buys is
//! re-eviction, a denial of service: repointing an agent needs a proof over
//! the attacker's own endpoints, which no capture supplies.

use std::time::{Duration, SystemTime};

use agent_uri::AgentUri;
use agent_uri_attestation::{Signature, SigningKey, VerifyingKey};

use crate::registration::system_time_to_millis;
use crate::{DhtError, Endpoint, Registration};

/// Domain separator. A signature minted for a DHT mutation must never verify
/// as authorization for anything else the agent key is used to sign.
///
/// The version moved to `v2` when `expires_at` entered the update and refresh
/// payloads. Every proof signed under `v1` is now unverifiable, which is the
/// point: a `v1` update proof says nothing about the expiry of the record it
/// produces, and accepting one would leave that field open on the wire.
const DOMAIN: &[u8] = b"agent-uri/dht-mutation/v2\x00";

/// The operation a proof authorizes.
///
/// The kind is part of the signed payload, so a proof for one operation cannot
/// be presented as authorization for another. Without this, a captured refresh
/// would double as a deregistration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationKind {
    /// Creating the record.
    Register,
    /// Replacing the record's endpoints.
    UpdateEndpoint,
    /// Extending the record's lifetime.
    Refresh,
    /// Removing the record.
    Deregister,
}

impl MutationKind {
    /// The tag written into the signed payload.
    ///
    /// These values are wire format. Renumbering one would make every proof in
    /// flight authorize a different operation than its signer intended.
    const fn tag(self) -> u8 {
        match self {
            Self::UpdateEndpoint => 1,
            Self::Refresh => 2,
            Self::Deregister => 3,
            Self::Register => 4,
        }
    }

    /// Returns the operation name, for error messages and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpdateEndpoint => "update_endpoint",
            Self::Refresh => "refresh",
            Self::Deregister => "deregister",
            Self::Register => "register",
        }
    }
}

impl std::fmt::Display for MutationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A write to an existing registration, with the parameters that write carries.
///
/// This mirrors the mutating [`crate::Dht`] methods so that the parameters
/// which distinguish two calls of the same kind (which endpoints, how much
/// TTL) are inside what the signature covers, and it names the resulting
/// record's `expires_at` so that no field of the record a write produces sits
/// outside the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation<'a> {
    /// Create the record with exactly this content.
    ///
    /// Registration is a write like any other and needs the same
    /// authorization. Without it, an attestation token lifted from a public
    /// record would be enough to re-register that URI pointing anywhere: the
    /// token binds the agent key, but nothing would bind the endpoints.
    Register {
        /// The key the new record will name as its only writer.
        agent_key: &'a VerifyingKey,
        /// The endpoints the new record will hold.
        endpoints: &'a [Endpoint],
        /// When the new record will expire.
        expires_at: SystemTime,
    },
    /// Replace the record's endpoints with these.
    ///
    /// A migration does not change when the record lapses, so `expires_at` is
    /// the expiry the record already carries. A store derives it from the
    /// record it holds rather than accepting it from the caller, so the two
    /// cannot describe the same write differently.
    UpdateEndpoint {
        /// The endpoints the record will hold.
        endpoints: &'a [Endpoint],
        /// When the record will expire, unchanged by this write.
        expires_at: SystemTime,
    },
    /// Extend the record's lifetime to this instant.
    ///
    /// `expires_at` is what a store applies. `ttl` is what the agent asked
    /// for, and is signed alongside it because it is an argument of the call:
    /// a backend that reports the requested lifetime, or carries it on the
    /// wire, must not be able to report one the agent never asked for. The
    /// instant is what the record ends up holding, so the instant is what
    /// stores act on. Only the signer knows both, because only the signer
    /// knows when it signed.
    Refresh {
        /// The lifetime the agent asked for.
        ttl: Duration,
        /// When the record will expire once this write is applied.
        expires_at: SystemTime,
    },
    /// Remove the record.
    Deregister,
}

impl Mutation<'_> {
    /// Returns the kind of operation this mutation performs.
    #[must_use]
    pub const fn kind(&self) -> MutationKind {
        match self {
            Self::Register { .. } => MutationKind::Register,
            Self::UpdateEndpoint { .. } => MutationKind::UpdateEndpoint,
            Self::Refresh { .. } => MutationKind::Refresh,
            Self::Deregister => MutationKind::Deregister,
        }
    }
}

/// Which record, and where in that record's history, a write applies.
///
/// A sequence number alone identifies a position but not a record: a
/// deregistered and re-registered URI starts counting again from zero, and a
/// proof captured before the gap would sit above the new record's history. The
/// registration time pins the instance so it cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordVersion {
    registered_at: SystemTime,
    sequence: u64,
}

impl RecordVersion {
    /// Names a version explicitly, for a caller holding the parts rather than
    /// the record.
    #[must_use]
    pub const fn new(registered_at: SystemTime, sequence: u64) -> Self {
        Self {
            registered_at,
            sequence,
        }
    }

    /// The version `record` currently holds.
    #[must_use]
    pub fn of(record: &Registration) -> Self {
        Self::new(record.registered_at(), record.sequence())
    }

    /// The version the next write to `record` claims.
    #[must_use]
    pub fn next(record: &Registration) -> Self {
        Self::new(record.registered_at(), record.sequence().saturating_add(1))
    }

    /// Returns the registration time identifying the record instance.
    #[must_use]
    pub const fn registered_at(&self) -> SystemTime {
        self.registered_at
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Appends a length-prefixed byte string.
///
/// Every variable-length field is prefixed with its length so that the
/// encoding is injective. Concatenating `"a" + "bc"` and `"ab" + "c"` must not
/// produce the same bytes, or one signature would authorize two operations.
fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    let len = u64::try_from(field.len()).expect("a field length fits in u64");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}

fn push_endpoint(out: &mut Vec<u8>, endpoint: &Endpoint) {
    // The three components go in separately rather than via the rendered URI:
    // injectivity then holds regardless of how `Endpoint` chooses to format
    // itself, and a change to that formatting cannot silently alias two
    // endpoints onto one signed payload.
    push_field(out, endpoint.protocol().as_bytes());
    push_field(out, endpoint.address().as_bytes());
    match endpoint.path() {
        Some(path) => {
            out.push(1);
            push_field(out, path.as_bytes());
        }
        None => out.push(0),
    }
}

fn push_endpoints(out: &mut Vec<u8>, endpoints: &[Endpoint]) {
    let count = u64::try_from(endpoints.len()).expect("an endpoint count fits in u64");
    out.extend_from_slice(&count.to_be_bytes());
    for endpoint in endpoints {
        push_endpoint(out, endpoint);
    }
}

/// Returns the exact bytes a proof for this mutation signs.
///
/// Pure and deterministic: signer and verifier compute it independently from
/// the same arguments and must agree byte for byte.
///
/// # Panics
///
/// Panics if a field length or endpoint count does not fit in a `u64`, which
/// requires a `usize` wider than 64 bits. No supported target has one.
#[must_use]
pub fn signing_payload(
    agent_uri: &AgentUri,
    version: RecordVersion,
    mutation: &Mutation<'_>,
) -> Vec<u8> {
    let mut out = Vec::from(DOMAIN);
    out.push(mutation.kind().tag());
    out.extend_from_slice(&system_time_to_millis(version.registered_at()).to_be_bytes());
    out.extend_from_slice(&version.sequence().to_be_bytes());
    push_field(&mut out, agent_uri.canonical().as_bytes());

    match mutation {
        Mutation::Register {
            agent_key,
            endpoints,
            expires_at,
        } => {
            // The key goes in so the payload is self-certifying: the signature
            // commits to the key it must be checked against.
            push_field(&mut out, &agent_key.to_bytes());
            out.extend_from_slice(&system_time_to_millis(*expires_at).to_be_bytes());
            push_endpoints(&mut out, endpoints);
        }
        Mutation::UpdateEndpoint {
            endpoints,
            expires_at,
        } => {
            out.extend_from_slice(&system_time_to_millis(*expires_at).to_be_bytes());
            push_endpoints(&mut out, endpoints);
        }
        Mutation::Refresh { ttl, expires_at } => {
            out.extend_from_slice(&system_time_to_millis(*expires_at).to_be_bytes());
            out.extend_from_slice(&ttl.as_secs().to_be_bytes());
            out.extend_from_slice(&ttl.subsec_nanos().to_be_bytes());
        }
        Mutation::Deregister => {}
    }

    out
}

/// Authorization for one write to one registration.
///
/// Carries only what the record cannot derive from the call itself: the
/// sequence number claiming a position in the record's history, and the
/// signature over the whole request. Everything else the signature covers
/// (which agent, which record instance, which operation, which arguments) the
/// store already holds or was just handed, so a proof has nothing in it that
/// could contradict the write it accompanies.
///
/// # Examples
///
/// ```
/// use agent_uri::AgentUri;
/// use agent_uri_attestation::SigningKey;
/// use agent_uri_dht::{Endpoint, Mutation, MutationProof, Registration};
///
/// let key = SigningKey::generate();
/// let uri = AgentUri::parse(
///     "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
/// ).unwrap();
///
/// // In practice this record comes back from a lookup.
/// let record = Registration::new(
///     uri,
///     key.verifying_key(),
///     vec![Endpoint::https("us-east-1.agent.anthropic.com")],
/// );
///
/// let endpoints = vec![Endpoint::https("eu-west-1.agent.anthropic.com")];
/// // Migrating does not change when the record lapses, so the expiry signed
/// // is the one the record already carries.
/// let mutation = Mutation::UpdateEndpoint {
///     endpoints: &endpoints,
///     expires_at: record.expires_at(),
/// };
/// let proof = MutationProof::sign_next(&key, &record, &mutation);
///
/// assert!(proof.authorizes(&record, &mutation).is_ok());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutationProof {
    sequence: u64,
    signature: Signature,
}

impl MutationProof {
    /// Signs the registration of `record`.
    ///
    /// Covers the record as submitted: its key, endpoints, expiry, instance
    /// identity, and starting sequence. A relay can therefore forward a
    /// registration but not alter one.
    #[must_use]
    pub fn sign_registration(key: &SigningKey, record: &Registration) -> Self {
        Self::sign(
            key,
            record.agent_uri(),
            RecordVersion::of(record),
            &Self::registration_of(record),
        )
    }

    /// The mutation a registration proof covers.
    ///
    /// Derived from the record rather than supplied, so signer and store
    /// cannot describe the same registration two different ways.
    fn registration_of(record: &Registration) -> Mutation<'_> {
        Mutation::Register {
            agent_key: record.agent_key(),
            endpoints: record.endpoints(),
            expires_at: record.expires_at(),
        }
    }

    /// Checks that this proof authorizes the registration of `record`.
    ///
    /// Unlike a later write there is no history to advance past, so only the
    /// signature is at issue: the record's own key must have signed the record
    /// exactly as submitted.
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::Unauthorized`] if the signature does not answer for
    /// this record.
    pub fn authorizes_registration(&self, record: &Registration) -> Result<(), DhtError> {
        let version = RecordVersion::new(record.registered_at(), self.sequence);
        record
            .agent_key()
            .verify(
                &signing_payload(record.agent_uri(), version, &Self::registration_of(record)),
                &self.signature,
            )
            .map_err(|_| DhtError::Unauthorized {
                agent_uri: record.agent_uri().canonical(),
                operation: MutationKind::Register,
            })
    }

    /// Signs the next write to `record`.
    ///
    /// The usual way to build a proof: look the record up, then sign against
    /// what you read. Signing against a stale copy produces a proof the store
    /// will refuse rather than one it will misapply.
    #[must_use]
    pub fn sign_next(key: &SigningKey, record: &Registration, mutation: &Mutation<'_>) -> Self {
        Self::sign(
            key,
            record.agent_uri(),
            RecordVersion::next(record),
            mutation,
        )
    }

    /// Signs a write against an explicitly named version.
    ///
    /// For a caller that cached a record's version rather than the record.
    #[must_use]
    pub fn sign(
        key: &SigningKey,
        agent_uri: &AgentUri,
        version: RecordVersion,
        mutation: &Mutation<'_>,
    ) -> Self {
        Self {
            sequence: version.sequence(),
            signature: key.sign(&signing_payload(agent_uri, version, mutation)),
        }
    }

    /// Reassembles a proof received over the wire.
    #[must_use]
    pub const fn from_parts(sequence: u64, signature: Signature) -> Self {
        Self {
            sequence,
            signature,
        }
    }

    /// Returns the sequence number this proof claims.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }

    /// Checks that this proof authorizes `mutation` against `record`.
    ///
    /// The whole authorization rule, in one place: the signature must be the
    /// record's own key over exactly this record instance, position, operation
    /// and arguments, and the position must advance. A store calls this and
    /// has nothing further to decide.
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::Unauthorized`] if the signature does not answer for
    /// this write, or [`DhtError::StaleSequence`] if it does but the write
    /// does not advance the record's history.
    pub fn authorizes(
        &self,
        record: &Registration,
        mutation: &Mutation<'_>,
    ) -> Result<(), DhtError> {
        let version = RecordVersion::new(record.registered_at(), self.sequence);

        // Signature first. A stale-sequence answer to an unsigned write would
        // tell an attacker the record's position for free.
        record
            .agent_key()
            .verify(
                &signing_payload(record.agent_uri(), version, mutation),
                &self.signature,
            )
            .map_err(|_| DhtError::Unauthorized {
                agent_uri: record.agent_uri().canonical(),
                operation: mutation.kind(),
            })?;

        if self.sequence <= record.sequence() {
            return Err(DhtError::StaleSequence {
                agent_uri: record.agent_uri().canonical(),
                presented: self.sequence,
                current: record.sequence(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_uri_attestation::VerifyingKey;

    fn test_uri() -> AgentUri {
        AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
            .unwrap()
    }

    fn other_uri() -> AgentUri {
        AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02r")
            .unwrap()
    }

    fn record(uri: &AgentUri, key: &VerifyingKey) -> Registration {
        Registration::new(uri.clone(), key.clone(), vec![Endpoint::https("a.example")])
    }

    /// A migration of `record` to `endpoints`, naming the expiry a store would
    /// read off the record.
    fn migration<'a>(record: &Registration, endpoints: &'a [Endpoint]) -> Mutation<'a> {
        Mutation::UpdateEndpoint {
            endpoints,
            expires_at: record.expires_at(),
        }
    }

    /// A migration to `endpoints` at a fixed expiry, for tests about how the
    /// payload encodes the endpoints rather than about the expiry.
    fn moved_to(endpoints: &[Endpoint]) -> Mutation<'_> {
        Mutation::UpdateEndpoint {
            endpoints,
            expires_at: SystemTime::UNIX_EPOCH,
        }
    }

    /// A renewal to a fixed instant, so that a test asserting on the payload
    /// does not depend on when it ran.
    fn renewal(ttl: Duration) -> Mutation<'static> {
        Mutation::Refresh {
            ttl,
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        }
    }

    #[test]
    fn a_proof_authorizes_the_mutation_it_signed() {
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let endpoints = vec![Endpoint::https("b.example")];
        let mutation = migration(&record, &endpoints);

        let proof = MutationProof::sign_next(&key, &record, &mutation);

        assert!(proof.authorizes(&record, &mutation).is_ok());
    }

    #[test]
    fn a_proof_does_not_authorize_different_endpoints() {
        // This is the hijack the proof exists to stop: same agent, same
        // operation, endpoints swapped for the attacker's.
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let honest = vec![Endpoint::https("honest.example")];
        let attacker = vec![Endpoint::https("attacker.example")];
        let proof = MutationProof::sign_next(&key, &record, &migration(&record, &honest));

        let result = proof.authorizes(&record, &migration(&record, &attacker));

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_migration_proof_does_not_authorize_a_different_expiry() {
        // The gap #81 closed. On a wire protocol the record a migration
        // produces travels whole, so an expiry outside the signature is one
        // any relay can rewrite: an observer could hold a real, agent-signed
        // record open long past the moment the agent chose to let it lapse.
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let endpoints = vec![Endpoint::https("b.example")];
        let proof = MutationProof::sign_next(&key, &record, &migration(&record, &endpoints));

        let result = proof.authorizes(
            &record,
            &Mutation::UpdateEndpoint {
                endpoints: &endpoints,
                expires_at: record.expires_at() + Duration::from_hours(23),
            },
        );

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_refresh_proof_does_not_authorize_a_different_expiry() {
        // Same gap on the other write that moves an expiry. The TTL matching
        // is not enough: the instant is what the record ends up holding.
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let ttl = Duration::from_hours(1);
        let proof = MutationProof::sign_next(&key, &record, &renewal(ttl));

        let Mutation::Refresh { expires_at, .. } = renewal(ttl) else {
            unreachable!("renewal builds a refresh")
        };
        let result = proof.authorizes(
            &record,
            &Mutation::Refresh {
                ttl,
                expires_at: expires_at + Duration::from_hours(23),
            },
        );

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_proof_does_not_cross_operations() {
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let proof = MutationProof::sign_next(&key, &record, &renewal(Duration::from_hours(1)));

        let result = proof.authorizes(&record, &Mutation::Deregister);

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_agent() {
        let key = SigningKey::generate();
        let mine = record(&test_uri(), &key.verifying_key());
        // Same key, same instant, same sequence: only the URI differs.
        let theirs = Registration::new(
            other_uri(),
            key.verifying_key(),
            vec![Endpoint::https("a.example")],
        )
        .with_registered_at(mine.registered_at());
        let proof = MutationProof::sign_next(&key, &mine, &Mutation::Deregister);

        let result = proof.authorizes(&theirs, &Mutation::Deregister);

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_sequence() {
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let proof = MutationProof::sign_next(&key, &record, &Mutation::Deregister);
        let renumbered = MutationProof::from_parts(proof.sequence() + 1, proof.signature());

        let result = renumbered.authorizes(&record, &Mutation::Deregister);

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_record_instance() {
        // The reason the record's registration time is signed. Sequence numbers
        // start over when a URI is deregistered and registered again, so
        // without this a captured proof would sit above the new record's
        // history and evict the agent every time it came back.
        let key = SigningKey::generate();
        let before = record(&test_uri(), &key.verifying_key())
            .with_registered_at(SystemTime::now() - Duration::from_hours(1));
        let after = record(&test_uri(), &key.verifying_key());
        let captured = MutationProof::sign_next(&key, &before, &Mutation::Deregister);

        let result = captured.authorizes(&after, &Mutation::Deregister);

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn another_key_cannot_authorize_a_mutation() {
        let agent = SigningKey::generate();
        let attacker = SigningKey::generate();
        let record = record(&test_uri(), &agent.verifying_key());
        let proof = MutationProof::sign_next(&attacker, &record, &Mutation::Deregister);

        let result = proof.authorizes(&record, &Mutation::Deregister);

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_refresh_proof_is_bound_to_its_ttl() {
        // The TTL is bound as well as the resulting instant. A store applies
        // the instant, but the TTL is an argument of the call and a backend
        // that reports the requested lifetime, or carries it on the wire, must
        // not be able to report one the agent never asked for.
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let short = Duration::from_mins(1);
        let proof = MutationProof::sign_next(&key, &record, &renewal(short));

        let Mutation::Refresh { expires_at, .. } = renewal(short) else {
            unreachable!("renewal builds a refresh")
        };
        let result = proof.authorizes(
            &record,
            &Mutation::Refresh {
                ttl: Duration::from_hours(24),
                expires_at,
            },
        );

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_signed_proof_that_does_not_advance_is_stale_not_unauthorized() {
        // The two rejections mean different things to a caller: one says fix
        // your key, the other says re-read and try again.
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let proof = MutationProof::sign(
            &key,
            record.agent_uri(),
            RecordVersion::of(&record),
            &Mutation::Deregister,
        );

        let result = proof.authorizes(&record, &Mutation::Deregister);

        assert!(matches!(
            result,
            Err(DhtError::StaleSequence {
                presented: 0,
                current: 0,
                ..
            })
        ));
    }

    #[test]
    fn an_unsigned_write_is_refused_before_the_sequence_is_examined() {
        // Answering "stale sequence" to a write nobody signed would hand out
        // the record's position for free.
        let agent = SigningKey::generate();
        let attacker = SigningKey::generate();
        let record = record(&test_uri(), &agent.verifying_key());
        let proof = MutationProof::sign(
            &attacker,
            record.agent_uri(),
            RecordVersion::of(&record),
            &Mutation::Deregister,
        );

        let result = proof.authorizes(&record, &Mutation::Deregister);

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn the_next_version_advances_exactly_one_past_the_current() {
        let key = SigningKey::generate();
        let mut record = record(&test_uri(), &key.verifying_key());
        record.set_sequence(41);

        assert_eq!(RecordVersion::of(&record).sequence(), 41);
        assert_eq!(RecordVersion::next(&record).sequence(), 42);
        assert_eq!(
            RecordVersion::next(&record).registered_at(),
            record.registered_at()
        );
    }

    #[test]
    fn the_next_version_saturates_rather_than_wrapping() {
        // Wrapping would hand a record back to every proof ever captured for it.
        let key = SigningKey::generate();
        let mut record = record(&test_uri(), &key.verifying_key());
        record.set_sequence(u64::MAX);

        assert_eq!(RecordVersion::next(&record).sequence(), u64::MAX);
    }

    #[test]
    fn endpoint_lists_do_not_alias_through_concatenation() {
        // Length prefixes are the reason. Without them, ["ab", "c"] and
        // ["a", "bc"] would flatten to the same bytes and one signature would
        // authorize both.
        let uri = test_uri();
        let version = RecordVersion::new(SystemTime::UNIX_EPOCH, 1);
        let split_one = vec![Endpoint::https("ab"), Endpoint::https("c")];
        let split_two = vec![Endpoint::https("a"), Endpoint::https("bc")];

        assert_ne!(
            signing_payload(&uri, version, &moved_to(&split_one)),
            signing_payload(&uri, version, &moved_to(&split_two))
        );
    }

    #[test]
    fn an_endpoint_path_does_not_alias_into_the_address() {
        let uri = test_uri();
        let version = RecordVersion::new(SystemTime::UNIX_EPOCH, 1);
        let with_path = vec![Endpoint::https_with_path("a.example", "/v1")];
        let in_address = vec![Endpoint::https("a.example/v1")];

        assert_ne!(
            signing_payload(&uri, version, &moved_to(&with_path)),
            signing_payload(&uri, version, &moved_to(&in_address))
        );
    }

    #[test]
    fn the_payload_is_domain_separated() {
        let payload = signing_payload(
            &test_uri(),
            RecordVersion::new(SystemTime::UNIX_EPOCH, 1),
            &Mutation::Deregister,
        );
        assert!(payload.starts_with(DOMAIN));
    }

    #[test]
    fn the_payload_is_deterministic() {
        let uri = test_uri();
        let version = RecordVersion::new(SystemTime::UNIX_EPOCH, 7);
        assert_eq!(
            signing_payload(&uri, version, &Mutation::Deregister),
            signing_payload(&uri, version, &Mutation::Deregister)
        );
    }

    #[test]
    fn the_payload_survives_the_millisecond_rounding_serde_applies() {
        // Signer and verifier may sit on opposite sides of a serialization, so
        // sub-millisecond precision in the payload would make a proof stop
        // verifying purely because the record went over the wire.
        let uri = test_uri();
        let base = SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);

        assert_eq!(
            signing_payload(&uri, RecordVersion::new(base, 1), &Mutation::Deregister),
            signing_payload(
                &uri,
                RecordVersion::new(base + Duration::from_nanos(500), 1),
                &Mutation::Deregister
            )
        );
    }

    #[test]
    fn a_registration_proof_does_not_double_as_a_later_write() {
        // Both are signed at the same version by the same key, so only the
        // operation tag separates them.
        let key = SigningKey::generate();
        let record = record(&test_uri(), &key.verifying_key());
        let proof = MutationProof::sign_registration(&key, &record);

        assert!(proof.authorizes_registration(&record).is_ok());
        assert!(matches!(
            proof.authorizes(&record, &Mutation::Deregister),
            Err(DhtError::Unauthorized { .. })
        ));
    }

    #[test]
    fn a_registration_proof_is_bound_to_the_key_the_record_names() {
        // The key is inside the signed payload, so a record cannot be handed a
        // proof that was made for a record naming somebody else.
        let key = SigningKey::generate();
        let other = SigningKey::generate();
        let mine = record(&test_uri(), &key.verifying_key());
        let proof = MutationProof::sign_registration(&key, &mine);

        // Same everything except the key the record names.
        let swapped = Registration::new(
            test_uri(),
            other.verifying_key(),
            vec![Endpoint::https("a.example")],
        )
        .with_registered_at(mine.registered_at());

        assert!(matches!(
            proof.authorizes_registration(&swapped),
            Err(DhtError::Unauthorized { .. })
        ));
    }

    #[test]
    fn mutation_kinds_have_distinct_tags() {
        let tags = [
            MutationKind::Register.tag(),
            MutationKind::UpdateEndpoint.tag(),
            MutationKind::Refresh.tag(),
            MutationKind::Deregister.tag(),
        ];
        let mut sorted = tags.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len());
    }
}
