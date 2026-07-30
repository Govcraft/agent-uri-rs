//! The [`Dht`] implementation, written as protocol over the worker's two
//! primitives.
//!
//! # A registration is several records
//!
//! One `register` call writes the agent's own signed record at its identity
//! key, and a pointer to it at the agent's capability path and every ancestor.
//! That is SPECIFICATION.md §6.2's sharded model, which a Kademlia overlay is
//! required to use: a broad ancestor key cannot hold its subtree under a 16 KiB
//! wire limit (issue #72).
//!
//! # A lookup is three rounds, not one
//!
//! A prefix lookup is a descriptor read, then a page read per shard, then one
//! read per agent found, which is what §6.4 costs the sharded model at. Each of
//! those is one exact-key read, so each is still `O(log N)` hops.
//!
//! # A lookup verifies what it is given
//!
//! Nothing about being handed a record by the overlay makes it true. Every
//! record a lookup returns has been through the same validation a storing node
//! applies, on this node, after it arrived. Replicas that answer with an older
//! record are handled by taking the greatest version across every copy
//! returned, so a lookup is as fresh as the best-informed peer that replied.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use agent_uri::{AgentUri, TrustRoot};
use agent_uri_attestation::Verifier;
use agent_uri_dht::{
    Cursor, Dht, DhtError, Endpoint, MatchMode, MutationProof, NodeId, Page, PeerAddr, Query,
    Quorum, ReadOptions, Registration, WriteOptions, WriteReceipt,
};
use async_trait::async_trait;
use libp2p::kad::{Quorum as KadQuorum, RecordKey};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};

use crate::config::Libp2pConfig;
use crate::keys::{
    descriptor_key, identity_key, page_count, page_for, page_key, path_and_ancestors,
};
use crate::merge::{best_of, merge_pages, widest_descriptor};
use crate::record::{IdentityRecord, Pointer, PointerPage, ShardDescriptor, WireKind};
use crate::validate::{matches_query, validate_identity};
use crate::worker::Command;

/// A handle to a node on the agent-uri overlay.
///
/// Cloning a handle is cheap and gives another way to talk to the same node.
/// The node runs until the last handle is dropped.
#[derive(Clone)]
pub struct Libp2pDht {
    commands: mpsc::Sender<Command>,
    local_peer: PeerId,
    verifier: Arc<Verifier>,
    config: Libp2pConfig,
    descriptors: Arc<Mutex<HashMap<RecordKey, (u8, Instant)>>>,
}

impl std::fmt::Debug for Libp2pDht {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Libp2pDht")
            .field("local_peer", &self.local_peer)
            .finish_non_exhaustive()
    }
}

impl Libp2pDht {
    pub(crate) fn new(
        commands: mpsc::Sender<Command>,
        local_peer: PeerId,
        verifier: Arc<Verifier>,
        config: Libp2pConfig,
    ) -> Self {
        Self {
            commands,
            local_peer,
            verifier,
            config,
            descriptors: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the addresses this node accepts connections on.
    ///
    /// Assigned by the operating system when a configured address asked for an
    /// ephemeral port, so this is the only way to learn where a node actually
    /// listens.
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::Unavailable`] if the node has shut down.
    pub async fn listen_addresses(&self) -> Result<Vec<Multiaddr>, DhtError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Listeners { reply }).await?;
        answer.await.map_err(|_| stopped())
    }

    /// Returns the multiaddrs another node can bootstrap against.
    ///
    /// Each carries this node's peer identity, which Kademlia needs and a bare
    /// listen address does not have.
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::Unavailable`] if the node has shut down.
    pub async fn dial_addresses(&self) -> Result<Vec<PeerAddr>, DhtError> {
        Ok(self
            .listen_addresses()
            .await?
            .into_iter()
            .map(|address| PeerAddr::new(format!("{address}/p2p/{}", self.local_peer)))
            .collect())
    }

    /// Drops a peer from this node's connections and routing table.
    ///
    /// For tests that need to partition an overlay, and for an operator
    /// evicting a misbehaving peer. Kademlia will re-learn the peer if it is
    /// discovered again.
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::Unavailable`] if the node has shut down.
    pub async fn disconnect(&self, peer: &NodeId) -> Result<(), DhtError> {
        let peer = PeerId::from_bytes(peer.as_bytes())
            .map_err(|_| DhtError::unavailable("peer identity is not a libp2p peer id"))?;
        let (reply, answer) = oneshot::channel();
        self.send(Command::Disconnect { peer, reply }).await?;
        answer.await.map_err(|_| stopped())
    }

    async fn send(&self, command: Command) -> Result<(), DhtError> {
        self.commands.send(command).await.map_err(|_| stopped())
    }

    /// Reads every copy of a key the overlay will return.
    async fn get(&self, key: RecordKey, timeout: Duration) -> Result<Vec<Vec<u8>>, DhtError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Get { key, reply }).await?;
        match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(stopped()),
            Err(_) => Err(DhtError::Timeout {
                operation: "lookup",
                after: timeout,
            }),
        }
    }

    /// Publishes a value and waits for the requested quorum.
    async fn put(
        &self,
        key: RecordKey,
        value: Vec<u8>,
        options: &WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Put {
            key,
            value,
            quorum: kad_quorum(options.quorum),
            reply,
        })
        .await?;
        match tokio::time::timeout(options.timeout, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(stopped()),
            Err(_) => Err(DhtError::Timeout {
                operation: "write",
                after: options.timeout,
            }),
        }
    }

    /// Returns the shard level for a capability path, reading it at most once
    /// per [`Libp2pConfig::descriptor_cache_ttl`].
    ///
    /// A path nobody has ever widened has no descriptor record, and level zero
    /// is the right answer for it: one page, which is where its publishers
    /// will have written.
    async fn shard_level(
        &self,
        trust_root: &TrustRoot,
        path: &str,
        timeout: Duration,
    ) -> Result<u8, DhtError> {
        let key = descriptor_key(trust_root, path);
        if let Some(level) = self.cached_level(&key) {
            return Ok(level);
        }

        let values = self.get(key.clone(), timeout).await?;
        let level = values
            .iter()
            .filter_map(|value| ShardDescriptor::decode(value).ok())
            .fold(ShardDescriptor::default(), widest_descriptor)
            .level;

        if let Ok(mut cache) = self.descriptors.lock() {
            cache.insert(key, (level, Instant::now()));
        }
        Ok(level)
    }

    fn cached_level(&self, key: &RecordKey) -> Option<u8> {
        let cache = self.descriptors.lock().ok()?;
        let (level, read_at) = cache.get(key)?;
        (read_at.elapsed() < self.config.descriptor_cache_ttl).then_some(*level)
    }

    /// Writes the pointers that make an agent discoverable by capability.
    ///
    /// One per ancestor path, which is the `O(d)` write cost §6.2 describes. A
    /// failure to place a pointer is reported, because an agent whose record
    /// landed but whose pointers did not is registered and undiscoverable,
    /// which is the worst of the two outcomes to leave silent.
    async fn publish_pointers(
        &self,
        agent_uri: &AgentUri,
        expires_at: SystemTime,
        options: &WriteOptions,
    ) -> Result<(), DhtError> {
        let trust_root = agent_uri.trust_root();
        let pointer = Pointer::new(agent_uri.canonical(), expires_at);
        let value = PointerPage::new(vec![pointer])
            .encode()
            .map_err(|error| DhtError::rejected(agent_uri.canonical(), error.to_string()))?;

        for path in path_and_ancestors(agent_uri.capability_path()) {
            let level = self.shard_level(trust_root, &path, options.timeout).await?;
            let page = page_for(agent_uri, level);
            let key = page_key(trust_root, &path, page);

            // Read before writing so the publisher can see whether the page it
            // is joining is full. It is also what gives the merge something to
            // converge towards: a publisher that only ever wrote its own
            // pointer would leave every replica to reconcile on its own.
            let occupancy = self
                .read_page(trust_root, &path, page, options.timeout)
                .await?
                .len();
            self.put(key, value.clone(), options).await?;

            if let Some(wider) = next_level(level, occupancy + 1, self.config.page_high_water) {
                self.widen(trust_root, &path, wider, options).await?;
            }
        }
        Ok(())
    }

    /// Raises a capability path's shard level.
    ///
    /// Pointers already written are left where they are. A reader at the new
    /// level still visits every page the old level used, so nothing becomes
    /// unreadable, and each pointer moves to its new page the next time its
    /// agent republishes. The page that overflowed therefore drains over one
    /// registration lifetime rather than all at once.
    async fn widen(
        &self,
        trust_root: &TrustRoot,
        path: &str,
        level: u8,
        options: &WriteOptions,
    ) -> Result<(), DhtError> {
        let key = descriptor_key(trust_root, path);
        let value = ShardDescriptor::at_level(level)
            .encode()
            .map_err(|error| DhtError::unavailable(error.to_string()))?;
        self.put(key.clone(), value, options).await?;

        if let Ok(mut cache) = self.descriptors.lock() {
            cache.insert(key, (level, Instant::now()));
        }
        tracing::info!(%trust_root, path, level, "widened a capability path's shard");
        Ok(())
    }

    /// Reads one agent's registration, verifying every copy returned.
    async fn read_identity(
        &self,
        agent_uri: &AgentUri,
        timeout: Duration,
    ) -> Result<Option<IdentityRecord>, DhtError> {
        let key = identity_key(agent_uri);
        let now = SystemTime::now();
        let values = self.get(key.clone(), timeout).await?;
        let candidates = values
            .iter()
            .filter_map(|value| IdentityRecord::decode(value).ok())
            .filter(|record| {
                validate_identity(
                    record,
                    &key,
                    None,
                    &self.verifier,
                    self.config.attestation_policy,
                    now,
                    self.config.max_record_ttl,
                )
                .is_ok()
            });
        Ok(best_of(candidates))
    }

    /// Reads the registration a mutation is about to be applied to.
    ///
    /// Every mutating call needs it, because the record travels whole and the
    /// caller only supplies what changed.
    async fn current(
        &self,
        agent_uri: &AgentUri,
        timeout: Duration,
    ) -> Result<Registration, DhtError> {
        match self.read_identity(agent_uri, timeout).await? {
            Some(record) if record.is_tombstone() => {
                Err(DhtError::not_found(agent_uri.canonical()))
            }
            Some(record) => Ok(record.state),
            None => Err(DhtError::not_found(agent_uri.canonical())),
        }
    }

    /// Publishes one write to an agent's own record.
    async fn publish_identity(
        &self,
        record: IdentityRecord,
        options: &WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        let uri = record.state.agent_uri().clone();
        let value = record
            .encode()
            .map_err(|error| DhtError::rejected(uri.canonical(), error.to_string()))?;
        self.put(identity_key(&uri), value, options).await
    }

    /// Reads one page of pointers, merged across every copy returned.
    async fn read_page(
        &self,
        trust_root: &TrustRoot,
        path: &str,
        page: u32,
        timeout: Duration,
    ) -> Result<Vec<Pointer>, DhtError> {
        let values = self.get(page_key(trust_root, path, page), timeout).await?;
        let pages = values
            .iter()
            .filter_map(|value| PointerPage::decode(value).ok());
        Ok(merge_pages(pages, SystemTime::now()).pointers)
    }
}

#[async_trait]
impl Dht for Libp2pDht {
    async fn register(
        &self,
        registration: Registration,
        proof: &MutationProof,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        if registration.endpoints().is_empty() {
            return Err(DhtError::NoEndpoints);
        }

        let agent_uri = registration.agent_uri().clone();
        let expires_at = registration.expires_at();
        let receipt = self
            .publish_identity(
                IdentityRecord {
                    state: registration,
                    kind: WireKind::Register,
                    refresh_ttl_millis: None,
                    signature: proof.signature().into(),
                },
                &options,
            )
            .await?;

        self.publish_pointers(&agent_uri, expires_at, &options)
            .await?;
        Ok(receipt)
    }

    async fn update_endpoint(
        &self,
        agent_uri: &AgentUri,
        new_endpoints: Vec<Endpoint>,
        proof: &MutationProof,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        if new_endpoints.is_empty() {
            return Err(DhtError::NoEndpoints);
        }

        let mut state = self.current(agent_uri, options.timeout).await?;
        state.update_endpoints(new_endpoints);
        state.set_sequence(proof.sequence());

        self.publish_identity(
            IdentityRecord {
                state,
                kind: WireKind::UpdateEndpoint,
                refresh_ttl_millis: None,
                signature: proof.signature().into(),
            },
            &options,
        )
        .await
    }

    async fn refresh(
        &self,
        agent_uri: &AgentUri,
        ttl: Duration,
        expires_at: SystemTime,
        proof: &MutationProof,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        let mut state = self.current(agent_uri, options.timeout).await?;
        // The instant the agent signed, not one derived here from the TTL.
        // This record is about to travel, and a field outside the signature
        // is a field the next hop can rewrite (issue #81).
        state.set_expires_at(expires_at);
        state.set_sequence(proof.sequence());

        let receipt = self
            .publish_identity(
                IdentityRecord {
                    state,
                    kind: WireKind::Refresh,
                    refresh_ttl_millis: Some(millis_of(ttl)),
                    signature: proof.signature().into(),
                },
                &options,
            )
            .await?;

        // Pointers expire on their own schedule. An agent that refreshed its
        // record but not its pointers would stay registered and stop being
        // discoverable, which is the failure mode hardest to notice.
        self.publish_pointers(agent_uri, expires_at, &options)
            .await?;
        Ok(receipt)
    }

    async fn deregister(
        &self,
        agent_uri: &AgentUri,
        proof: &MutationProof,
        options: WriteOptions,
    ) -> Result<(), DhtError> {
        let mut state = self.current(agent_uri, options.timeout).await?;
        state.update_endpoints(Vec::new());
        state.set_sequence(proof.sequence());

        // The tombstone outlives nothing: it expires when the record it
        // replaces would have. Kademlia has no delete, so removal is a record
        // that says "gone" and then goes away itself.
        self.publish_identity(
            IdentityRecord {
                state,
                kind: WireKind::Deregister,
                refresh_ttl_millis: None,
                signature: proof.signature().into(),
            },
            &options,
        )
        .await?;
        Ok(())
    }

    async fn lookup(
        &self,
        query: &Query,
        options: &ReadOptions,
    ) -> Result<Page<Registration>, DhtError> {
        let trust_root = query.trust_root();
        let path = query.capability_path().as_str();
        let exact = matches!(query.match_mode(), MatchMode::Exact);

        let mut budget = KeyBudget::new(options.max_keys);
        let level = self.shard_level(trust_root, path, options.timeout).await?;
        budget.spend();

        let pages = page_count(level);
        let (mut page, mut offset) = split_cursor(options.cursor);
        let mut found = Vec::new();

        while page < pages {
            if budget.exhausted() {
                return Ok(Page::partial(found, join_cursor(page, offset)));
            }
            let pointers = self
                .read_page(trust_root, path, page, options.timeout)
                .await?;
            budget.spend();

            while (offset as usize) < pointers.len() {
                if budget.exhausted() {
                    return Ok(Page::partial(found, join_cursor(page, offset)));
                }
                let pointer = &pointers[offset as usize];
                offset += 1;

                // Filtering before the read is what keeps an injected pointer
                // from costing anything: a URI that does not sit under the
                // queried path is discarded without a lookup.
                let Ok(uri) = AgentUri::parse(&pointer.agent_uri) else {
                    continue;
                };
                if !matches_query(&uri, query.capability_path(), exact) {
                    continue;
                }

                budget.spend();
                if let Some(record) = self.read_identity(&uri, options.timeout).await?
                    && !record.is_tombstone()
                {
                    found.push(record.state);
                }
            }

            page += 1;
            offset = 0;
        }

        Ok(Page::complete(found))
    }

    fn local_id(&self) -> NodeId {
        NodeId::from_bytes(self.local_peer.to_bytes())
    }

    async fn bootstrap(&self, peers: &[PeerAddr]) -> Result<(), DhtError> {
        let addresses: Vec<Multiaddr> = peers
            .iter()
            .filter_map(|peer| peer.as_str().parse().ok())
            .collect();
        if addresses.is_empty() {
            return Err(DhtError::NoPeers);
        }

        let (reply, answer) = oneshot::channel();
        self.send(Command::Bootstrap {
            peers: addresses,
            reply,
        })
        .await?;
        answer.await.map_err(|_| stopped())?
    }
}

/// How many DHT keys one lookup call has left to read.
///
/// A prefix lookup fans out across shards and then across the agents it finds,
/// so without a bound one call could read the whole namespace. The bound is
/// also what keeps a hostile descriptor claiming a huge shard level from
/// costing a reader more than one page's worth of work.
struct KeyBudget {
    remaining: usize,
}

impl KeyBudget {
    const fn new(max_keys: usize) -> Self {
        Self {
            remaining: max_keys,
        }
    }

    const fn spend(&mut self) {
        self.remaining = self.remaining.saturating_sub(1);
    }

    const fn exhausted(&self) -> bool {
        self.remaining == 0
    }
}

/// Packs a shard page and an offset within it into a [`Cursor`].
///
/// The page index occupies the high 16 bits, which is exactly enough for the
/// 65 536 pages the maximum shard level allows.
///
/// Resuming is position-based, not a snapshot. A pointer added to a page
/// between two calls shifts the offsets after it, so an enumeration that spans
/// several calls can miss or repeat an agent that arrived mid-walk. Every
/// distributed lookup has that property; naming it is better than implying a
/// consistency the overlay does not offer.
const fn join_cursor(page: u32, offset: u32) -> Cursor {
    Cursor::at((page << 16) | (offset & 0xffff))
}

const fn split_cursor(cursor: Option<Cursor>) -> (u32, u32) {
    match cursor {
        Some(cursor) => {
            let position = cursor.position();
            (position >> 16, position & 0xffff)
        }
        None => (0, 0),
    }
}

/// Returns the shard level a full page should be widened to, if any.
///
/// Widening is opportunistic: whichever publisher notices a page at its high
/// water mark raises the level for everyone. There is no coordinator, and none
/// is needed, because the level merges by taking the maximum and raising it
/// never invalidates a pointer already written.
///
/// Returns `None` at the maximum level. A path that has outgrown 65 536 pages
/// is past what this scheme was designed for, and silently widening past the
/// cap would only make readers derive keys nobody writes to.
#[must_use]
fn next_level(current: u8, occupancy: usize, high_water: usize) -> Option<u8> {
    (occupancy >= high_water && current < crate::keys::MAX_SHARD_LEVEL).then_some(current + 1)
}

fn kad_quorum(quorum: Quorum) -> KadQuorum {
    match quorum {
        Quorum::One => KadQuorum::One,
        Quorum::Majority => KadQuorum::Majority,
        Quorum::All => KadQuorum::All,
        Quorum::N(n) => KadQuorum::N(n),
    }
}

fn millis_of(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn stopped() -> DhtError {
    DhtError::unavailable("the node has shut down")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_round_trips_a_page_and_an_offset() {
        for (page, offset) in [(0, 0), (1, 0), (0, 37), (4095, 511), (65535, 65535)] {
            assert_eq!(
                split_cursor(Some(join_cursor(page, offset))),
                (page, offset)
            );
        }
    }

    #[test]
    fn no_cursor_starts_at_the_first_pointer_of_the_first_page() {
        assert_eq!(split_cursor(None), (0, 0));
    }

    #[test]
    fn the_cursor_holds_every_page_the_maximum_shard_level_allows() {
        let last = page_count(crate::keys::MAX_SHARD_LEVEL) - 1;
        assert_eq!(split_cursor(Some(join_cursor(last, 0))).0, last);
    }

    #[test]
    fn a_budget_stops_at_zero_rather_than_wrapping() {
        let mut budget = KeyBudget::new(1);
        assert!(!budget.exhausted());
        budget.spend();
        assert!(budget.exhausted());
        budget.spend();
        assert!(budget.exhausted());
    }

    #[test]
    fn a_page_below_its_high_water_mark_is_left_alone() {
        assert_eq!(next_level(0, 127, 128), None);
    }

    #[test]
    fn a_page_at_its_high_water_mark_widens_by_one() {
        // By one, not to a size: doubling is what keeps pointers already
        // written where a reader at the new level will still look.
        assert_eq!(next_level(0, 128, 128), Some(1));
        assert_eq!(next_level(3, 500, 128), Some(4));
    }

    #[test]
    fn widening_stops_at_the_maximum_level() {
        // Past the cap a reader would derive keys no publisher writes to, which
        // costs lookups and buys nothing.
        assert_eq!(
            next_level(crate::keys::MAX_SHARD_LEVEL, usize::MAX, 1),
            None
        );
    }

    #[test]
    fn quorums_map_onto_kademlias() {
        assert!(matches!(kad_quorum(Quorum::One), KadQuorum::One));
        assert!(matches!(kad_quorum(Quorum::Majority), KadQuorum::Majority));
        assert!(matches!(kad_quorum(Quorum::All), KadQuorum::All));
        let n = std::num::NonZeroUsize::new(3).unwrap();
        assert!(matches!(kad_quorum(Quorum::N(n)), KadQuorum::N(m) if m == n));
    }

    #[test]
    fn a_shut_down_node_is_not_reported_as_a_network_problem() {
        // An operator who sees NoPeers goes looking at the overlay. This one is
        // about the handle they are holding.
        assert!(matches!(stopped(), DhtError::Unavailable { .. }));
        assert!(!stopped().is_transient());
    }
}
