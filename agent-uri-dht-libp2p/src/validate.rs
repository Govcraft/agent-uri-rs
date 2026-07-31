//! What a node checks before it agrees to store a record.
//!
//! This is the whole of SPECIFICATION.md §6.2 requirement 4 and §6.6 as they
//! apply on a real overlay. Every path by which a value enters a node's store
//! runs through [`validate_identity`], so there is one place to read to know
//! what a stored record is guaranteed to satisfy.
//!
//! # The four checks
//!
//! 1. **The key matches the record.** A record must live at the key derived
//!    from its own URI, or one agent could publish over another's key.
//! 2. **The signature covers this write.** Rebuilt from the record's own
//!    contents, never from anything the record asserts about itself.
//! 3. **The attestation names this agent's key.** A token is world-readable, so
//!    presenting one proves nothing on its own; what it does is bind the key
//!    the signature was checked against to the trust root in the URI.
//! 4. **The write is later than what is held.** Records are immutable, so
//!    accepting one is choosing between two candidates.
//!
//! # Every field of a record is signed
//!
//! Check 2 rebuilds the mutation from the record's own fields, so any field it
//! reads is a field an attacker cannot change without breaking the signature.
//! `expires_at` is one of them, on all four kinds of write.
//!
//! It was not always. Until issue #81, `Mutation::UpdateEndpoint` and
//! `Mutation::Refresh` signed the parameters of the call and not the record
//! that results from it, which is exactly right for a store that holds the
//! record and applies the change itself, and left one field open here, where
//! the resulting record travels whole. An attacker who observed a legitimate
//! migration could republish it with an expiry of their choosing: shortening it
//! is the denial of service scoped in §8.1, and lengthening it held a genuine,
//! agent-signed record open past the moment the agent chose to let it lapse.
//!
//! Two rules bounded that, and both still earn their place. A record is refused
//! unless its expiry lies in `(now, now + max_record_ttl]`, which is why an
//! out-of-bounds expiry is **refused** rather than clamped: clamping rewrites
//! bytes the signature covers and would break the record at the next hop. And a
//! write is refused unless its version strictly advances, so a stale copy
//! cannot displace a current one.

use std::time::{Duration, SystemTime};

use agent_uri::AgentUri;
use agent_uri_attestation::Verifier;
use agent_uri_dht::{Mutation, RecordVersion, signing_payload};
use libp2p::kad::RecordKey;

use crate::config::AttestationPolicy;
use crate::keys::identity_key;
use crate::record::{IdentityRecord, WireKind, millis};

/// Why a node refused to store a record.
///
/// Every variant is a reason to drop the record and, for most of them, a reason
/// to think less of the peer that sent it.
///
/// `#[non_exhaustive]`, so a `match` on this enum needs a `_` arm, and dropping
/// the record is what that arm should do: a refusal this version cannot name is
/// still a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// The record does not belong at the key it arrived on.
    WrongKey,
    /// A live registration named no endpoints.
    NoEndpoints,
    /// The record's expiry is in the past, or further ahead than this node
    /// will hold a record.
    ExpiryOutOfBounds,
    /// A refresh record did not carry the TTL its signature covers.
    MissingRefreshTtl,
    /// The signature does not cover this record under its own agent key.
    BadSignature,
    /// The record carries no attestation and this node requires one.
    MissingAttestation,
    /// The attestation did not verify.
    ///
    /// Carries the reason, because an operator debugging a node that stores
    /// nothing needs to know whether it is clock skew or the wrong root key.
    InvalidAttestation(String),
    /// The attestation attests a different key than the record names.
    AgentKeyMismatch,
    /// This node does not know the record's trust root and its policy requires
    /// that it does.
    UnknownTrustRoot,
    /// The record does not advance past the one already held.
    NotNewer,
    /// The record would take the key over under a different agent key, without
    /// an attestation this node could verify.
    UnverifiedKeyChange,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongKey => f.write_str("record does not belong at the key it arrived on"),
            Self::NoEndpoints => f.write_str("live registration names no endpoints"),
            Self::ExpiryOutOfBounds => {
                f.write_str("record expiry is in the past or beyond this node's ceiling")
            }
            Self::MissingRefreshTtl => {
                f.write_str("refresh record omits the TTL its signature covers")
            }
            Self::BadSignature => {
                f.write_str("signature does not cover this write under the record's agent key")
            }
            Self::MissingAttestation => f.write_str("record carries no attestation"),
            Self::InvalidAttestation(reason) => write!(f, "attestation did not verify: {reason}"),
            Self::AgentKeyMismatch => {
                f.write_str("attestation attests a different key than the record names")
            }
            Self::UnknownTrustRoot => f.write_str("record's trust root is not known to this node"),
            Self::NotNewer => f.write_str("record does not advance past the one already held"),
            Self::UnverifiedKeyChange => f.write_str(
                "record would take the key over under a different agent key without a \
                 verifiable attestation",
            ),
        }
    }
}

impl std::error::Error for Rejection {}

/// Decides whether a node may store a record it has been handed.
///
/// `held` is the record already at this key, if any. `now` and `max_ttl` bound
/// the expiry a publisher may claim.
///
/// # Errors
///
/// Returns the first [`Rejection`] that applies. Checks run cheapest-first
/// except that the signature is checked before the version: answering "your
/// sequence is stale" to an unsigned write would tell an attacker where a
/// record stands for the cost of a malformed packet.
pub fn validate_identity(
    record: &IdentityRecord,
    key: &RecordKey,
    held: Option<&IdentityRecord>,
    verifier: &Verifier,
    policy: AttestationPolicy,
    now: SystemTime,
    max_ttl: Duration,
) -> Result<(), Rejection> {
    let uri = record.state.agent_uri();

    if identity_key(uri) != *key {
        return Err(Rejection::WrongKey);
    }

    check_shape(record, now, max_ttl)?;
    check_signature(record)?;
    let attested = check_attestation(record, verifier, policy)?;
    check_supersession(record, held, attested)?;

    Ok(())
}

/// Checks the parts of a record that need nothing but the record itself.
fn check_shape(
    record: &IdentityRecord,
    now: SystemTime,
    max_ttl: Duration,
) -> Result<(), Rejection> {
    if !record.is_tombstone() && record.state.endpoints().is_empty() {
        return Err(Rejection::NoEndpoints);
    }

    if matches!(record.kind, WireKind::Refresh) && record.refresh_ttl().is_none() {
        return Err(Rejection::MissingRefreshTtl);
    }

    let expires = millis(record.state.expires_at());
    if expires <= millis(now) || expires > millis(now + max_ttl) {
        return Err(Rejection::ExpiryOutOfBounds);
    }

    Ok(())
}

/// Checks the agent's signature over exactly this write.
///
/// The mutation is rebuilt from the record's own fields, so a record cannot
/// carry a description of itself that disagrees with its contents.
fn check_signature(record: &IdentityRecord) -> Result<(), Rejection> {
    let state = &record.state;
    let version = RecordVersion::new(state.registered_at(), state.sequence());

    let mutation = match record.kind {
        WireKind::Register => Mutation::Register {
            agent_key: state.agent_key(),
            endpoints: state.endpoints(),
            expires_at: state.expires_at(),
        },
        WireKind::UpdateEndpoint => Mutation::UpdateEndpoint {
            endpoints: state.endpoints(),
            expires_at: state.expires_at(),
        },
        WireKind::Refresh => Mutation::Refresh {
            ttl: record.refresh_ttl().ok_or(Rejection::MissingRefreshTtl)?,
            expires_at: state.expires_at(),
        },
        WireKind::Deregister => Mutation::Deregister,
    };

    let payload = signing_payload(state.agent_uri(), version, &mutation);
    state
        .agent_key()
        .verify(&payload, &record.signature.into())
        .map_err(|_| Rejection::BadSignature)
}

/// Checks the attestation, and reports whether verification actually happened.
///
/// Returns `true` when the trust root was known and the token checked out. That
/// distinction is what [`check_supersession`] uses to decide whether an
/// unverified record may change the key that owns a record.
fn check_attestation(
    record: &IdentityRecord,
    verifier: &Verifier,
    policy: AttestationPolicy,
) -> Result<bool, Rejection> {
    if matches!(policy, AttestationPolicy::Unverified) {
        return Ok(false);
    }

    let uri = record.state.agent_uri();
    let known = verifier.has_trusted_root(uri.trust_root().as_str());
    if !known {
        return if policy.accepts_unknown_roots() {
            Ok(false)
        } else {
            Err(Rejection::UnknownTrustRoot)
        };
    }

    let token = record
        .state
        .attestation()
        .ok_or(Rejection::MissingAttestation)?;
    let claims = verifier
        .verify_for_capability(token, uri, uri.capability_path())
        .map_err(|error| Rejection::InvalidAttestation(error.to_string()))?;

    let attested = claims
        .agent_verifying_key()
        .map_err(|error| Rejection::InvalidAttestation(error.to_string()))?;
    if attested != *record.state.agent_key() {
        return Err(Rejection::AgentKeyMismatch);
    }

    Ok(true)
}

/// Checks that a record is a later write than the one already held.
///
/// A key change is the case worth spelling out. Within one incarnation of a
/// record the agent key never moves, and an agent that deregisters and returns
/// under a new key is a legitimate thing to do. Telling the two apart needs the
/// attestation: without one this node can verify, a record that arrives under a
/// different key is refused, because accepting it would let anyone who can
/// reach a replica take a URI over by publishing a later registration time.
fn check_supersession(
    record: &IdentityRecord,
    held: Option<&IdentityRecord>,
    attested: bool,
) -> Result<(), Rejection> {
    let Some(held) = held else {
        return Ok(());
    };

    if record.version() <= held.version() {
        return Err(Rejection::NotNewer);
    }

    if record.state.agent_key() != held.state.agent_key() && !attested {
        return Err(Rejection::UnverifiedKeyChange);
    }

    Ok(())
}

/// Returns true if a registration found under a pointer really sits beneath the
/// queried path.
///
/// Pointer pages are unauthenticated, so a node can put any URI on any page.
/// This is the check that makes that harmless: a lookup only returns an agent
/// whose own URI places it under the path that was asked for. Without it,
/// injecting a pointer would let a hostile node advertise a real agent as
/// having a capability it never claimed.
#[must_use]
pub fn matches_query(
    agent_uri: &AgentUri,
    queried: &agent_uri::CapabilityPath,
    exact: bool,
) -> bool {
    let path = agent_uri.capability_path();
    if exact {
        path == queried
    } else {
        path.starts_with(queried)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_uri::CapabilityPath;
    use agent_uri_attestation::{AcceptAll, Issuer, SigningKey};
    use agent_uri_dht::{Endpoint, MutationProof, Registration};

    const TRUST_ROOT: &str = "anthropic.com";

    fn uri(suffix: &str) -> AgentUri {
        AgentUri::parse(&format!(
            "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn0{suffix}"
        ))
        .unwrap()
    }

    fn endpoints() -> Vec<Endpoint> {
        vec![Endpoint::https("agent.anthropic.com:443")]
    }

    struct Fixture {
        verifier: Verifier,
        issuer: Issuer,
    }

    impl Fixture {
        fn new() -> Self {
            let root_key = SigningKey::generate();
            let issuer = Issuer::new(TRUST_ROOT, root_key.clone(), Duration::from_hours(1));
            let mut verifier = Verifier::new().with_revocation(AcceptAll);
            verifier.add_trusted_root(TRUST_ROOT, root_key.verifying_key());
            Self { verifier, issuer }
        }

        fn attested(&self, uri: &AgentUri, agent: &SigningKey) -> Registration {
            let token = self
                .issuer
                .issue(uri, &agent.verifying_key(), vec![])
                .expect("issuing a token for a well-formed URI");
            Registration::new(uri.clone(), agent.verifying_key(), endpoints())
                .with_attestation(token)
        }
    }

    /// Publishes `state` as a `Register` write signed by `signer`.
    fn registered(state: Registration, signer: &SigningKey) -> IdentityRecord {
        let proof = MutationProof::sign_registration(signer, &state);
        IdentityRecord {
            signature: proof.signature().into(),
            state,
            kind: WireKind::Register,
            refresh_ttl_millis: None,
        }
    }

    /// Publishes `state` as a `Refresh` write signed by `signer`, extending the
    /// record to `now + ttl`.
    ///
    /// The instant goes into the payload, into the record, and onto the wire as
    /// the TTL, which is what an honest publisher does: all three describe one
    /// write, and a node rebuilds the payload from the record to check it.
    fn refreshed(state: Registration, signer: &SigningKey, ttl: Duration) -> IdentityRecord {
        let expires_at = SystemTime::now() + ttl;
        let proof =
            MutationProof::sign_next(signer, &state, &Mutation::Refresh { ttl, expires_at });
        let mut state = state.with_sequence(proof.sequence());
        state.set_expires_at(expires_at);
        IdentityRecord {
            signature: proof.signature().into(),
            state,
            kind: WireKind::Refresh,
            refresh_ttl_millis: Some(u64::try_from(ttl.as_millis()).unwrap()),
        }
    }

    /// Publishes a migration of `state` to `moved`, signed by `signer`.
    fn migrated(state: &Registration, signer: &SigningKey, moved: Vec<Endpoint>) -> IdentityRecord {
        let proof = MutationProof::sign_next(
            signer,
            state,
            &Mutation::UpdateEndpoint {
                endpoints: &moved,
                expires_at: state.expires_at(),
            },
        );
        let mut state = state.clone().with_sequence(proof.sequence());
        state.update_endpoints(moved);
        IdentityRecord {
            signature: proof.signature().into(),
            state,
            kind: WireKind::UpdateEndpoint,
            refresh_ttl_millis: None,
        }
    }

    fn validate(
        record: &IdentityRecord,
        held: Option<&IdentityRecord>,
        fixture: &Fixture,
        policy: AttestationPolicy,
    ) -> Result<(), Rejection> {
        validate_identity(
            record,
            &identity_key(record.state.agent_uri()),
            held,
            &fixture.verifier,
            policy,
            SystemTime::now(),
            Duration::from_hours(24),
        )
    }

    #[test]
    fn an_honest_registration_is_stored() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let record = registered(fixture.attested(&uri("2q"), &agent), &agent);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Ok(())
        );
    }

    #[test]
    fn a_record_at_the_wrong_key_is_refused() {
        // Otherwise one agent publishes over another's registration simply by
        // addressing the write elsewhere.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let record = registered(fixture.attested(&uri("2q"), &agent), &agent);

        let result = validate_identity(
            &record,
            &identity_key(&uri("2r")),
            None,
            &fixture.verifier,
            AttestationPolicy::VerifyKnownRoots,
            SystemTime::now(),
            Duration::from_hours(24),
        );
        assert_eq!(result, Err(Rejection::WrongKey));
    }

    #[test]
    fn a_registration_signed_by_another_key_is_refused() {
        // The attack #50 closed, arriving over the network instead of through
        // an API call.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let attacker = SigningKey::generate();
        let record = registered(fixture.attested(&uri("2q"), &agent), &attacker);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn a_lifted_token_presented_under_another_key_is_refused() {
        // The attack #51 closed: the attacker holds the victim's token and
        // their own key, and signs correctly for the key they hold.
        let fixture = Fixture::new();
        let victim = SigningKey::generate();
        let attacker = SigningKey::generate();
        let agent_uri = uri("2q");

        let token = fixture
            .issuer
            .issue(&agent_uri, &victim.verifying_key(), vec![])
            .unwrap();
        let state = Registration::new(agent_uri, attacker.verifying_key(), endpoints())
            .with_attestation(token);
        let record = registered(state, &attacker);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::AgentKeyMismatch)
        );
    }

    #[test]
    fn substituted_endpoints_break_the_signature() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let mut record = registered(fixture.attested(&uri("2q"), &agent), &agent);
        record
            .state
            .update_endpoints(vec![Endpoint::https("attacker.example:443")]);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn a_live_registration_needs_endpoints() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let state = Registration::new(uri("2q"), agent.verifying_key(), vec![]);
        let record = registered(state, &agent);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::Unverified),
            Err(Rejection::NoEndpoints)
        );
    }

    #[test]
    fn a_tombstone_may_have_no_endpoints() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let live = fixture.attested(&uri("2q"), &agent);
        let mut state = live.clone().with_sequence(1);
        state.update_endpoints(vec![]);
        let proof = MutationProof::sign_next(&agent, &live, &Mutation::Deregister);
        let record = IdentityRecord {
            signature: proof.signature().into(),
            state,
            kind: WireKind::Deregister,
            refresh_ttl_millis: None,
        };

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Ok(())
        );
    }

    #[test]
    fn an_expiry_beyond_this_nodes_ceiling_is_refused() {
        // Refused rather than clamped: clamping would rewrite bytes the
        // signature covers, and the record would stop verifying at the next
        // hop.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let state = fixture
            .attested(&uri("2q"), &agent)
            .with_ttl(Duration::from_hours(48));
        let record = registered(state, &agent);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::ExpiryOutOfBounds)
        );
    }

    #[test]
    fn an_already_expired_record_is_refused() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let state = fixture
            .attested(&uri("2q"), &agent)
            .with_expires_at(SystemTime::now() - Duration::from_secs(1));
        let record = registered(state, &agent);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::ExpiryOutOfBounds)
        );
    }

    #[test]
    fn a_replay_of_the_held_version_is_refused() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let record = registered(fixture.attested(&uri("2q"), &agent), &agent);

        assert_eq!(
            validate(
                &record,
                Some(&record),
                &fixture,
                AttestationPolicy::VerifyKnownRoots
            ),
            Err(Rejection::NotNewer)
        );
    }

    #[test]
    fn a_higher_sequence_supersedes() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let held = registered(fixture.attested(&uri("2q"), &agent), &agent);

        let moved = vec![Endpoint::https("eu-west-1.anthropic.com:443")];
        let update = migrated(&held.state, &agent, moved);

        assert_eq!(
            validate(
                &update,
                Some(&held),
                &fixture,
                AttestationPolicy::VerifyKnownRoots
            ),
            Ok(())
        );
    }

    #[test]
    fn a_migration_whose_expiry_was_rewritten_in_flight_is_refused() {
        // The gap #81 closed. A migration's resulting record travels whole, so
        // before `expires_at` entered the signed payload an attacker who
        // observed one could republish it holding the agent's own record open
        // long past the moment the agent chose to let it lapse. The expiry is
        // pushed out, not in: shortening a record is the denial of service
        // §8.1 already scopes, and lengthening it is what this closes.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let held = registered(fixture.attested(&uri("2q"), &agent), &agent);
        let moved = vec![Endpoint::https("eu-west-1.anthropic.com:443")];

        let mut tampered = migrated(&held.state, &agent, moved);
        let honest = tampered.state.expires_at();
        // Still inside the node's 24-hour ceiling, so the record clears the
        // shape check and is refused by the signature rather than the bound.
        tampered
            .state
            .set_expires_at(honest + Duration::from_hours(12));

        assert_eq!(
            validate(
                &tampered,
                Some(&held),
                &fixture,
                AttestationPolicy::VerifyKnownRoots
            ),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn a_refresh_whose_expiry_was_rewritten_in_flight_is_refused() {
        // Same gap on the other write that moves an expiry. Matching the TTL
        // is not enough to save it: the instant is what the record holds, and
        // the instant is signed.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let held = fixture.attested(&uri("2q"), &agent);

        let mut tampered = refreshed(held, &agent, Duration::from_mins(30));
        let honest = tampered.state.expires_at();
        tampered
            .state
            .set_expires_at(honest + Duration::from_hours(12));

        assert_eq!(
            validate(
                &tampered,
                None,
                &fixture,
                AttestationPolicy::VerifyKnownRoots
            ),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn an_honest_refresh_is_stored() {
        // The counterpart to the two tampering tests: an expiry that matches
        // what was signed is accepted, so those two are failing on the
        // rewrite and not on the fixture.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let held = fixture.attested(&uri("2q"), &agent);

        let record = refreshed(held, &agent, Duration::from_mins(30));

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Ok(())
        );
    }

    #[test]
    fn a_refresh_without_its_ttl_is_refused() {
        // The TTL is part of what the signature covers, so a refresh that omits
        // it cannot be checked at all.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let held = fixture.attested(&uri("2q"), &agent);

        let record = IdentityRecord {
            refresh_ttl_millis: None,
            ..refreshed(held, &agent, Duration::from_mins(30))
        };

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::MissingRefreshTtl)
        );
    }

    #[test]
    fn a_refresh_carrying_a_different_ttl_than_it_signed_is_refused() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let held = fixture.attested(&uri("2q"), &agent);

        let record = IdentityRecord {
            refresh_ttl_millis: Some(u64::try_from(Duration::from_hours(12).as_millis()).unwrap()),
            ..refreshed(held, &agent, Duration::from_mins(30))
        };

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn a_proof_for_one_operation_does_not_authorize_another() {
        // The record claims to be a deregistration and carries a signature the
        // agent made over a registration.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let honest = registered(fixture.attested(&uri("2q"), &agent), &agent);
        let forged = IdentityRecord {
            kind: WireKind::Deregister,
            ..honest
        };

        assert_eq!(
            validate(&forged, None, &fixture, AttestationPolicy::Unverified),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn an_unverified_key_change_cannot_take_a_record_over() {
        // The takeover this rule exists to stop: reach a replica that cannot
        // check the trust root, publish a later registration time under your
        // own key, own the URI.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let attacker = SigningKey::generate();
        let held = registered(fixture.attested(&uri("2q"), &agent), &agent);

        let takeover = registered(
            Registration::new(uri("2q"), attacker.verifying_key(), endpoints())
                .with_registered_at(held.state.registered_at() + Duration::from_mins(1)),
            &attacker,
        );

        assert_eq!(
            validate(
                &takeover,
                Some(&held),
                &fixture,
                AttestationPolicy::Unverified
            ),
            Err(Rejection::UnverifiedKeyChange)
        );
    }

    #[test]
    fn a_verified_key_change_is_allowed() {
        // An agent that deregisters and returns under a new key is legitimate,
        // and the attestation is what tells the two cases apart.
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let successor = SigningKey::generate();
        let held = registered(fixture.attested(&uri("2q"), &agent), &agent);

        let state = fixture
            .attested(&uri("2q"), &successor)
            .with_registered_at(held.state.registered_at() + Duration::from_mins(1));
        let reborn = registered(state, &successor);

        assert_eq!(
            validate(
                &reborn,
                Some(&held),
                &fixture,
                AttestationPolicy::VerifyKnownRoots
            ),
            Ok(())
        );
    }

    #[test]
    fn a_strict_node_refuses_trust_roots_it_does_not_know() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let foreign =
            AgentUri::parse("agent://openai.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let state = Registration::new(foreign, agent.verifying_key(), endpoints());
        let record = registered(state, &agent);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::RequireVerified),
            Err(Rejection::UnknownTrustRoot)
        );
        // The permissive policy holds it, because refusing every root a node
        // was not configured with would make it useless as a storing node.
        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Ok(())
        );
    }

    #[test]
    fn a_known_root_still_requires_a_token() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let state = Registration::new(uri("2q"), agent.verifying_key(), endpoints());
        let record = registered(state, &agent);

        assert_eq!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::MissingAttestation)
        );
    }

    #[test]
    fn a_garbage_token_for_a_known_root_is_refused() {
        let fixture = Fixture::new();
        let agent = SigningKey::generate();
        let state = Registration::new(uri("2q"), agent.verifying_key(), endpoints())
            .with_attestation("v4.public.not-a-token");
        let record = registered(state, &agent);

        assert!(matches!(
            validate(&record, None, &fixture, AttestationPolicy::VerifyKnownRoots),
            Err(Rejection::InvalidAttestation(_))
        ));
    }

    #[test]
    fn an_injected_pointer_to_an_unrelated_agent_is_filtered_out() {
        // Pointer pages are unauthenticated. This is the check that keeps that
        // from being a capability-confusion attack.
        let elsewhere =
            AgentUri::parse("agent://anthropic.com/payments/settle/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let queried = CapabilityPath::parse("assistant").unwrap();

        assert!(!matches_query(&elsewhere, &queried, false));
        assert!(matches_query(&uri("2q"), &queried, false));
    }

    #[test]
    fn exact_mode_does_not_return_descendants() {
        let deep = AgentUri::parse(
            "agent://anthropic.com/assistant/chat/streaming/llm_01h455vb4pex5vsknk084sn02q",
        )
        .unwrap();
        let queried = CapabilityPath::parse("assistant/chat").unwrap();

        assert!(matches_query(&deep, &queried, false));
        assert!(!matches_query(&deep, &queried, true));
    }

    #[test]
    fn rejections_say_what_went_wrong() {
        assert!(Rejection::WrongKey.to_string().contains("key"));
        assert!(
            Rejection::InvalidAttestation("clock skew".into())
                .to_string()
                .contains("clock skew")
        );
        assert!(
            Rejection::UnverifiedKeyChange
                .to_string()
                .contains("agent key")
        );
    }
}
