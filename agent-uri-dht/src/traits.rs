//! DHT trait definition for capability-based agent discovery.

use std::time::Duration;

use agent_uri::AgentUri;
use async_trait::async_trait;

use crate::{
    DhtError, Endpoint, NodeId, Page, PeerAddr, Query, ReadOptions, Registration, WriteOptions,
    WriteReceipt,
};

/// Abstract DHT operations.
///
/// Implementations may be in-process ([`crate::SimulatedDht`]) or distributed
/// over a real overlay. Every method is asynchronous because every operation on
/// a real backend crosses the network.
///
/// # Scope
///
/// Every lookup is scoped to a single trust root, because every DHT key is
/// derived from one. There is deliberately no cross-trust-root query: the
/// specification's discovery protocol is trust-root scoped throughout, and
/// cross-trust-root isolation is a security property that bounds the blast
/// radius of a trust-root key compromise.
///
/// # Failure is normal
///
/// A distributed lookup does not simply succeed or find nothing. It can time
/// out, reach too few replicas, or find no peers at all, and each is a distinct
/// [`DhtError`]. Callers that collapse these into "not found" will treat a
/// partitioned network as an empty one.
///
/// # Pagination
///
/// A broad capability path can hold more registrations than one read can
/// return, so [`Dht::lookup`] returns a [`Page`]. Callers that need every
/// result must follow [`Page::next_cursor`] until it is `None`; a caller that
/// reads only the first page is sampling, not enumerating.
///
/// # Object safety
///
/// This trait uses `#[async_trait]` rather than native `async fn` so that it
/// stays dyn-compatible. Selecting a backend at runtime behind
/// `Box<dyn Dht>` is the reason the trait exists, and native `async fn` in
/// trait cannot express that.
#[async_trait]
pub trait Dht: Send + Sync {
    /// Registers an agent at its capability path.
    ///
    /// The agent is indexed by the DHT key derived from its trust root and
    /// capability path, and at every ancestor path, enabling discovery by
    /// capability prefix.
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if:
    /// - The agent is already registered (`AlreadyRegistered`)
    /// - The endpoints list is empty (`NoEndpoints`)
    /// - The DHT key is at capacity (`KeyCapacityExceeded`)
    /// - Attestation verification fails (`InvalidAttestation`)
    /// - The operation times out, finds no peers, or misses quorum
    ///   (`Timeout`, `NoPeers`, `QuorumFailed`)
    async fn register(
        &self,
        registration: Registration,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError>;

    /// Updates an existing registration's endpoints.
    ///
    /// Used for agent migration: changing network location without changing
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if the agent is not registered (`NotFound`), the
    /// registration has expired (`Expired`), the endpoints list is empty
    /// (`NoEndpoints`), or the operation fails to reach the network.
    async fn update_endpoint(
        &self,
        agent_uri: &AgentUri,
        new_endpoints: Vec<Endpoint>,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError>;

    /// Extends an existing registration's lifetime.
    ///
    /// Registrations expire, so an agent that intends to remain reachable must
    /// republish before its TTL elapses. Without this a long-lived agent has to
    /// deregister and re-register, which makes it briefly undiscoverable.
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if the agent is not registered (`NotFound`) or the
    /// operation fails to reach the network.
    async fn refresh(
        &self,
        agent_uri: &AgentUri,
        ttl: Duration,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError>;

    /// Removes a registration.
    ///
    /// # Errors
    ///
    /// Returns `DhtError::NotFound` if the agent is not registered, or a
    /// network error if the operation fails to reach the network.
    async fn deregister(&self, agent_uri: &AgentUri, options: WriteOptions)
    -> Result<(), DhtError>;

    /// Looks up agents matching a capability query.
    ///
    /// Returns one page of results. An empty page with no cursor means no
    /// agents matched; an empty page *with* a cursor means the shard read was
    /// empty and more shards remain.
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if the lookup times out, finds no peers, or fails to
    /// reach the requested quorum.
    async fn lookup(
        &self,
        query: &Query,
        options: &ReadOptions,
    ) -> Result<Page<Registration>, DhtError>;

    /// Returns this node's identity in the overlay.
    fn local_id(&self) -> NodeId;

    /// Joins the overlay through the given peers.
    ///
    /// # Errors
    ///
    /// Returns `DhtError::NoPeers` if no peer could be reached, or
    /// `DhtError::Timeout` if the attempt did not complete in time.
    async fn bootstrap(&self, peers: &[PeerAddr]) -> Result<(), DhtError>;
}
