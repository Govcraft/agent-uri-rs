//! The task that owns the swarm.
//!
//! Everything in this module is transport. It moves opaque values between this
//! node's Kademlia store and its peers, and it decides whether a value another
//! node handed it may be stored. It knows nothing about registrations, lookups,
//! or capability paths: that lives in [`crate::dht`], written against the two
//! primitives this worker exposes, `Get` and `Put`.
//!
//! The split matters for one reason. A `libp2p` swarm is not `Send` across the
//! await points a protocol needs, so it has to sit in a task of its own and be
//! spoken to by message. Keeping that task free of protocol logic means the
//! protocol can be read straight through instead of as a state machine spread
//! across event arms.
//!
//! # Where values enter the store
//!
//! Two paths, and both run [`Worker::accept`]:
//!
//! - a peer sends a put request, which `StoreInserts::FilterBoth` routes to the
//!   application before storage;
//! - this node publishes, which `Behaviour::put_record` writes to the local
//!   store directly.
//!
//! The second is easy to miss, and missing it would leave the publisher as the
//! one node in the overlay that never merged.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use agent_uri_attestation::Verifier;
use agent_uri_dht::{DhtError, WriteReceipt};
use futures::StreamExt;
use libp2p::kad::store::{MemoryStore, RecordStore};
use libp2p::kad::{
    self, GetRecordOk, PeerRecord, QueryId, QueryResult, Quorum as KadQuorum, Record, RecordKey,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm, identify};
use tokio::sync::{mpsc, oneshot};

use crate::config::Libp2pConfig;
use crate::merge::{merge_pages, widest_descriptor};
use crate::record::{PointerPage, Shape, ShardDescriptor, classify};
use crate::validate::{Rejection, validate_identity};

/// The behaviours a node runs.
///
/// Identify is not decoration. Kademlia routes to peers by listen address, and
/// a peer that dialled out is known only by the ephemeral address it dialled
/// from; without identify, half the routing table would hold addresses nothing
/// can be reached at.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub(crate) struct Behaviour {
    pub(crate) kad: kad::Behaviour<MemoryStore>,
    pub(crate) identify: identify::Behaviour,
}

/// A request from a [`Libp2pDht`](crate::Libp2pDht) handle to the worker.
pub(crate) enum Command {
    /// Publish a value, merging it with what this node already holds.
    Put {
        key: RecordKey,
        value: Vec<u8>,
        quorum: KadQuorum,
        reply: oneshot::Sender<Result<WriteReceipt, DhtError>>,
    },
    /// Read every copy of a value the overlay will return.
    Get {
        key: RecordKey,
        reply: oneshot::Sender<Result<Vec<Vec<u8>>, DhtError>>,
    },
    /// Join the overlay through the given peers.
    Bootstrap {
        peers: Vec<Multiaddr>,
        reply: oneshot::Sender<Result<(), DhtError>>,
    },
    /// Report the addresses this node is listening on.
    Listeners {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    /// Forget a peer, for tests that partition an overlay.
    Disconnect {
        peer: PeerId,
        reply: oneshot::Sender<()>,
    },
}

/// A Kademlia query this worker is waiting on.
enum Pending {
    Get {
        values: Vec<Vec<u8>>,
        reply: oneshot::Sender<Result<Vec<Vec<u8>>, DhtError>>,
    },
    Put {
        required: usize,
        reply: oneshot::Sender<Result<WriteReceipt, DhtError>>,
    },
    Bootstrap {
        reply: oneshot::Sender<Result<(), DhtError>>,
    },
}

/// Owns the swarm and answers commands.
pub(crate) struct Worker {
    swarm: Swarm<Behaviour>,
    commands: mpsc::Receiver<Command>,
    pending: HashMap<QueryId, Pending>,
    verifier: Arc<Verifier>,
    config: Libp2pConfig,
}

impl Worker {
    pub(crate) fn new(
        swarm: Swarm<Behaviour>,
        commands: mpsc::Receiver<Command>,
        verifier: Arc<Verifier>,
        config: Libp2pConfig,
    ) -> Self {
        Self {
            swarm,
            commands,
            pending: HashMap::new(),
            verifier,
            config,
        }
    }

    /// Runs until every handle to this node has been dropped.
    pub(crate) async fn run(mut self) {
        loop {
            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(command) => self.on_command(command),
                    None => break,
                },
                event = self.swarm.select_next_some() => self.on_event(event),
            }
        }
        tracing::debug!("agent-uri dht worker stopped");
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Put {
                key,
                value,
                quorum,
                reply,
            } => match self.publish(key, value, quorum) {
                // A refused value fails here; an accepted one is not answered
                // until the peers say how many of them stored it.
                Ok(deferred) => self.park(deferred, reply),
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Command::Get { key, reply } => {
                let id = self.swarm.behaviour_mut().kad.get_record(key);
                self.pending.insert(
                    id,
                    Pending::Get {
                        values: Vec::new(),
                        reply,
                    },
                );
            }
            Command::Bootstrap { peers, reply } => self.bootstrap(peers, reply),
            Command::Listeners { reply } => {
                let _ = reply.send(self.swarm.listeners().cloned().collect());
            }
            Command::Disconnect { peer, reply } => {
                let _ = self.swarm.disconnect_peer_id(peer);
                self.swarm.behaviour_mut().kad.remove_peer(&peer);
                let _ = reply.send(());
            }
        }
    }

    /// Merges a value into the local store and pushes it to the `k` closest
    /// peers.
    ///
    /// The reply is deferred until the Kademlia query reports how many peers
    /// stored it, unless the merge refused the value outright.
    fn publish(
        &mut self,
        key: RecordKey,
        value: Vec<u8>,
        quorum: KadQuorum,
    ) -> Result<Deferred, DhtError> {
        let accepted = self.accept(&key, value).map_err(refusal_to_error)?;

        let record = Record {
            key,
            expires: accepted.deadline(),
            value: accepted.value,
            publisher: None,
        };
        let required = quorum_size(quorum, self.config.replication_factor.get());
        let id = self
            .swarm
            .behaviour_mut()
            .kad
            .put_record(record, quorum)
            // The local store refusing is this node's own limit, not a verdict
            // on the record: too large for the configured value size, or the
            // store already full.
            .map_err(|error| DhtError::unavailable(error.to_string()))?;
        Ok(Deferred { id, required })
    }

    fn bootstrap(&mut self, peers: Vec<Multiaddr>, reply: oneshot::Sender<Result<(), DhtError>>) {
        let mut added = 0usize;
        for address in peers {
            let Some(peer) = peer_id_of(&address) else {
                tracing::warn!(%address, "bootstrap address names no peer, skipping");
                continue;
            };
            self.swarm
                .behaviour_mut()
                .kad
                .add_address(&peer, address.clone());
            if self.swarm.dial(address.clone()).is_ok() {
                added += 1;
            }
        }

        if added == 0 {
            let _ = reply.send(Err(DhtError::NoPeers));
            return;
        }

        match self.swarm.behaviour_mut().kad.bootstrap() {
            Ok(id) => {
                self.pending.insert(id, Pending::Bootstrap { reply });
            }
            Err(_) => {
                let _ = reply.send(Err(DhtError::NoPeers));
            }
        }
    }

    fn on_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Kad(event)) => self.on_kad(event),
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                // Only the addresses a peer says it listens on are dialable.
                for address in info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, address);
                }
            }
            _ => {}
        }
    }

    fn on_kad(&mut self, event: kad::Event) {
        match event {
            kad::Event::InboundRequest {
                request:
                    kad::InboundRequest::PutRecord {
                        record: Some(record),
                        source,
                        ..
                    },
            } => self.on_inbound_put(record, source),
            kad::Event::OutboundQueryProgressed {
                id, result, step, ..
            } => self.on_query_progress(id, result, step.last),
            _ => {}
        }
    }

    /// Decides whether a record a peer sent may be stored here.
    ///
    /// This is the storing-node check SPECIFICATION.md §6.2 requirement 4 asks
    /// for. A refusal is logged and dropped: Kademlia has already told the
    /// sender the request was received, deliberately, so that a node cannot
    /// probe what its neighbours hold by watching which puts are acknowledged.
    fn on_inbound_put(&mut self, record: Record, source: PeerId) {
        let key = record.key.clone();
        match self.accept(&key, record.value) {
            Ok(accepted) => {
                // Keeping the held publisher matters: a node that published a
                // record and then merged a peer's copy of it would otherwise
                // stop republishing its own.
                let publisher = self
                    .store()
                    .get(&key)
                    .and_then(|held| held.publisher)
                    .or(record.publisher);
                let stored = Record {
                    key,
                    expires: accepted.deadline().or(record.expires),
                    value: accepted.value,
                    publisher,
                };
                if let Err(error) = self.store().put(stored) {
                    tracing::debug!(%source, ?error, "local store refused a record");
                }
            }
            Err(refusal) => {
                tracing::debug!(%source, %refusal, "refused a record from a peer");
            }
        }
    }

    /// Validates a value and returns what this node should store for it.
    ///
    /// Identity records come back verbatim, because they are immutable and
    /// signed and rewriting one would break it at the next hop. Pages and
    /// descriptors come back merged with whatever is already held.
    fn accept(&mut self, key: &RecordKey, value: Vec<u8>) -> Result<Accepted, Refusal> {
        let now = SystemTime::now();
        match classify(&value).map_err(|error| Refusal::Codec(error.to_string()))? {
            Shape::Identity => {
                let incoming = crate::record::IdentityRecord::decode(&value)
                    .map_err(|error| Refusal::Codec(error.to_string()))?;
                let held = self
                    .store()
                    .get(key)
                    .and_then(|held| crate::record::IdentityRecord::decode(&held.value).ok());
                validate_identity(
                    &incoming,
                    key,
                    held.as_ref(),
                    &self.verifier,
                    self.config.attestation_policy,
                    now,
                    self.config.max_record_ttl,
                )
                .map_err(|rejection| {
                    Refusal::Rejected(incoming.state.agent_uri().canonical(), rejection)
                })?;
                Ok(Accepted {
                    expires_at: Some(incoming.state.expires_at()),
                    value,
                })
            }
            Shape::Page => {
                let incoming = PointerPage::decode(&value)
                    .map_err(|error| Refusal::Codec(error.to_string()))?;
                let held = self
                    .store()
                    .get(key)
                    .and_then(|held| PointerPage::decode(&held.value).ok());
                merge_pages(held.into_iter().chain([incoming]), now)
                    .encode()
                    .map(Accepted::without_expiry)
                    .map_err(|error| Refusal::Codec(error.to_string()))
            }
            Shape::Descriptor => {
                let incoming = ShardDescriptor::decode(&value)
                    .map_err(|error| Refusal::Codec(error.to_string()))?;
                let held = self
                    .store()
                    .get(key)
                    .and_then(|held| ShardDescriptor::decode(&held.value).ok())
                    .unwrap_or_default();
                widest_descriptor(held, incoming)
                    .encode()
                    .map(Accepted::without_expiry)
                    .map_err(|error| Refusal::Codec(error.to_string()))
            }
        }
    }

    fn on_query_progress(&mut self, id: QueryId, result: QueryResult, last: bool) {
        match result {
            QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord { record, .. }))) => {
                if let Some(Pending::Get { values, .. }) = self.pending.get_mut(&id) {
                    values.push(record.value);
                }
            }
            QueryResult::GetRecord(Err(error)) => {
                // A read that found nothing is an answer, not a failure: the
                // keyspace is sparse by construction. A read that timed out or
                // missed its quorum is a failure, and the caller has to be able
                // to tell the two apart.
                if let kad::GetRecordError::Timeout { .. } = error
                    && let Some(Pending::Get { reply, .. }) = self.pending.remove(&id)
                {
                    let _ = reply.send(Err(DhtError::Timeout {
                        operation: "lookup",
                        after: self.config.query_timeout,
                    }));
                    return;
                }
            }
            QueryResult::PutRecord(result) | QueryResult::RepublishRecord(result) => {
                let Some(Pending::Put { required, reply }) = self.pending.remove(&id) else {
                    return;
                };
                let _ = reply.send(match result {
                    Ok(_) => Ok(WriteReceipt::new(required, required)),
                    Err(kad::PutRecordError::QuorumFailed { success, .. }) => {
                        Err(DhtError::QuorumFailed {
                            achieved: success.len(),
                            required,
                        })
                    }
                    Err(kad::PutRecordError::Timeout { .. }) => Err(DhtError::Timeout {
                        operation: "register",
                        after: self.config.query_timeout,
                    }),
                });
                return;
            }
            QueryResult::Bootstrap(result) => {
                if let Some(Pending::Bootstrap { reply }) = self.pending.remove(&id) {
                    let _ = reply.send(match result {
                        Ok(_) => Ok(()),
                        Err(kad::BootstrapError::Timeout { .. }) => Err(DhtError::Timeout {
                            operation: "bootstrap",
                            after: self.config.query_timeout,
                        }),
                    });
                }
                return;
            }
            // Everything else, including a get that finished with no further
            // record, falls through to the completion check below.
            _ => {}
        }

        if last && let Some(Pending::Get { values, reply }) = self.pending.remove(&id) {
            let _ = reply.send(Ok(values));
        }
    }

    fn store(&mut self) -> &mut MemoryStore {
        self.swarm.behaviour_mut().kad.store_mut()
    }

    /// Records a deferred reply against the query that will complete it.
    pub(crate) fn park(
        &mut self,
        deferred: Deferred,
        reply: oneshot::Sender<Result<WriteReceipt, DhtError>>,
    ) {
        let Deferred { id, required } = deferred;
        self.pending.insert(id, Pending::Put { required, reply });
    }
}

/// A value this node has agreed to store, and how long it should keep it.
struct Accepted {
    value: Vec<u8>,
    /// When the record stops being valid, for shapes that say so themselves.
    ///
    /// Only identity records carry their own lifetime. Pages and descriptors
    /// fall back to Kademlia's record TTL, which is the right default for
    /// values whose individual entries expire on their own schedule.
    expires_at: Option<SystemTime>,
}

impl Accepted {
    const fn without_expiry(value: Vec<u8>) -> Self {
        Self {
            value,
            expires_at: None,
        }
    }

    /// Converts the record's own expiry into the monotonic deadline the store
    /// wants.
    ///
    /// A record already past its expiry yields `None` rather than a deadline in
    /// the past, because the store treats a missing deadline as "use the
    /// default" rather than "expired". Such a record is refused before it gets
    /// here; this only decides what happens if one ever is not.
    fn deadline(&self) -> Option<Instant> {
        let expires_at = self.expires_at?;
        let remaining = expires_at.duration_since(SystemTime::now()).ok()?;
        Some(Instant::now() + remaining)
    }
}

/// A publish whose outcome is not known until the query completes.
#[derive(Clone, Copy)]
pub(crate) struct Deferred {
    id: QueryId,
    required: usize,
}

/// Why a value was not stored.
enum Refusal {
    /// The value is not a record this node can read.
    Codec(String),
    /// The record was read, and refused.
    Rejected(String, Rejection),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(reason) => write!(f, "undecodable record: {reason}"),
            Self::Rejected(uri, rejection) => write!(f, "{uri}: {rejection}"),
        }
    }
}

/// Maps a storing node's refusal onto the error a caller sees.
///
/// The mapping is deliberate rather than a catch-all: an operator reading
/// `Unauthorized` should be looking at keys, and one reading `Rejected` should
/// be looking at the record's own contents.
fn refusal_to_error(refusal: Refusal) -> DhtError {
    match refusal {
        Refusal::Codec(reason) => DhtError::unavailable(reason),
        Refusal::Rejected(uri, rejection) => match rejection {
            Rejection::WrongKey | Rejection::BadSignature | Rejection::UnverifiedKeyChange => {
                DhtError::Unauthorized {
                    agent_uri: uri,
                    operation: agent_uri_dht::MutationKind::Register,
                }
            }
            Rejection::NotNewer => DhtError::rejected(uri, rejection.to_string()),
            Rejection::NoEndpoints => DhtError::NoEndpoints,
            Rejection::AgentKeyMismatch => DhtError::AgentKeyMismatch { agent_uri: uri },
            Rejection::MissingAttestation
            | Rejection::InvalidAttestation(_)
            | Rejection::UnknownTrustRoot => {
                DhtError::invalid_attestation(uri, rejection.to_string())
            }
            Rejection::ExpiryOutOfBounds | Rejection::MissingRefreshTtl => {
                DhtError::rejected(uri, rejection.to_string())
            }
        },
    }
}

/// Resolves a Kademlia quorum against a replication factor.
///
/// Kademlia reports a successful put without saying how many peers stored it,
/// so this is what a [`WriteReceipt`] reports as acknowledged. It is a lower
/// bound: the write reached at least this many replicas.
fn quorum_size(quorum: KadQuorum, replication_factor: usize) -> usize {
    match quorum {
        KadQuorum::One => 1,
        KadQuorum::Majority => replication_factor / 2 + 1,
        KadQuorum::All => replication_factor,
        KadQuorum::N(n) => n.get().min(replication_factor),
    }
}

/// Extracts the peer identity from a multiaddr ending in `/p2p/<peer-id>`.
fn peer_id_of(address: &Multiaddr) -> Option<PeerId> {
    address.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    #[test]
    fn quorum_sizes_match_the_core_crates_arithmetic() {
        // The two crates resolve quorums independently, and a caller that asked
        // for a majority should not get different answers depending on which
        // one it asked.
        let k = NonZeroUsize::new(20).unwrap();
        for (kad, core) in [
            (KadQuorum::One, agent_uri_dht::Quorum::One),
            (KadQuorum::Majority, agent_uri_dht::Quorum::Majority),
            (KadQuorum::All, agent_uri_dht::Quorum::All),
        ] {
            assert_eq!(quorum_size(kad, k.get()), core.resolve(k));
        }
    }

    #[test]
    fn an_explicit_quorum_clamps_to_the_replication_factor() {
        let n = NonZeroUsize::new(100).unwrap();
        assert_eq!(quorum_size(KadQuorum::N(n), 20), 20);
    }

    #[test]
    fn a_bootstrap_address_without_a_peer_id_is_unusable() {
        // Kademlia routes to peer identities, so an address alone cannot be
        // added to a routing table.
        let bare: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        assert!(peer_id_of(&bare).is_none());
    }

    #[test]
    fn a_bootstrap_address_with_a_peer_id_yields_it() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer = PeerId::from(keypair.public());
        let address: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        assert_eq!(peer_id_of(&address), Some(peer));
    }

    #[test]
    fn a_bad_signature_reports_an_authorization_failure() {
        let error = refusal_to_error(Refusal::Rejected(
            "agent://a.com/b/c_1".into(),
            Rejection::BadSignature,
        ));
        assert!(matches!(error, DhtError::Unauthorized { .. }));
    }

    #[test]
    fn an_out_of_bounds_expiry_is_not_reported_as_an_attestation_problem() {
        // The mapping exists so that an operator debugging a clock is not sent
        // to look at trust roots.
        let error = refusal_to_error(Refusal::Rejected(
            "agent://a.com/b/c_1".into(),
            Rejection::ExpiryOutOfBounds,
        ));
        assert!(matches!(error, DhtError::Rejected { .. }));
        assert!(error.to_string().contains("expiry"));
    }

    #[test]
    fn a_lifted_token_reports_the_key_mismatch() {
        let error = refusal_to_error(Refusal::Rejected(
            "agent://a.com/b/c_1".into(),
            Rejection::AgentKeyMismatch,
        ));
        assert!(matches!(error, DhtError::AgentKeyMismatch { .. }));
    }

    #[test]
    fn every_refusal_maps_to_a_non_transient_error() {
        // Retrying an identical record against the same node is pure waste, so
        // no refusal may be reported as something a retry could fix.
        for rejection in [
            Rejection::WrongKey,
            Rejection::NoEndpoints,
            Rejection::ExpiryOutOfBounds,
            Rejection::MissingRefreshTtl,
            Rejection::BadSignature,
            Rejection::MissingAttestation,
            Rejection::InvalidAttestation("bad".into()),
            Rejection::AgentKeyMismatch,
            Rejection::UnknownTrustRoot,
            Rejection::NotNewer,
            Rejection::UnverifiedKeyChange,
        ] {
            let error =
                refusal_to_error(Refusal::Rejected("agent://a.com/b/c_1".into(), rejection));
            assert!(!error.is_transient(), "{error} was reported as retryable");
        }
    }
}
