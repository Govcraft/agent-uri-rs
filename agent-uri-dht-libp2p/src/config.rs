//! Configuration for a node on the overlay.

use std::num::NonZeroUsize;
use std::time::Duration;

use libp2p::{Multiaddr, StreamProtocol};

/// How strictly a storing node checks the attestation on a record it is asked
/// to hold.
///
/// SPECIFICATION.md §6.2 requirement 4 says DHT nodes MUST verify attestations
/// before storing records. That is unambiguous for a trust root the node knows.
/// It cannot be honored literally for one it does not: a node holds records for
/// keys near it in the overlay, which is every trust root, and no node can be
/// configured with every issuer's public key. This enum is where that gap is
/// made explicit rather than silently resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPolicy {
    /// Store only records whose attestation this node verified.
    ///
    /// The literal reading of §6.2 requirement 4. A node under this policy
    /// serves only the trust roots it was configured with and refuses to hold
    /// records for any other, which makes it a poor overlay citizen but leaves
    /// nothing unverified in its store.
    RequireVerified,
    /// Verify for known trust roots; accept records for unknown roots without
    /// one, but never let an unverified record take a key over from a
    /// different agent key.
    ///
    /// The default, and the only policy that lets a node participate in an
    /// overlay spanning trust roots it does not know. What it gives up is
    /// stated precisely: for an unknown root, the first record to arrive at a
    /// key is trusted, and later records are accepted only if they carry the
    /// same agent key and a valid signature. An attacker who reaches an empty
    /// replica first can seed it; the reader's merge across replicas and the
    /// verification it performs itself are what recover from that.
    VerifyKnownRoots,
    /// Store records without checking attestations at all.
    ///
    /// For isolated tests. A node under this policy will hold whatever it is
    /// handed, and readers still verify what they are given, but the storage
    /// layer contributes nothing.
    Unverified,
}

impl AttestationPolicy {
    /// Returns true if a record for an unknown trust root may be stored.
    #[must_use]
    pub const fn accepts_unknown_roots(self) -> bool {
        matches!(self, Self::VerifyKnownRoots | Self::Unverified)
    }
}

/// Configuration for a node, passed to [`start`](crate::start).
#[derive(Debug, Clone)]
pub struct Libp2pConfig {
    /// Addresses the node listens on.
    ///
    /// Empty means the node does not accept inbound connections, which makes it
    /// a client: it can read and publish but will not be asked to store.
    pub listen_addresses: Vec<Multiaddr>,

    /// The Kademlia protocol name.
    ///
    /// Distinct from the IPFS default on purpose. A node speaking this protocol
    /// only ever forms a routing table with other agent-uri nodes, so a
    /// misconfigured deployment fails to find peers rather than joining a
    /// foreign overlay and answering its queries.
    pub protocol: StreamProtocol,

    /// The replication factor, `k`.
    pub replication_factor: NonZeroUsize,

    /// The longest lifetime a node will accept on a record.
    ///
    /// A registration's expiry is inside its value, so this is the storing
    /// node's own bound on how far into the future a publisher may reach.
    /// Records asking for more are refused rather than clamped, because
    /// clamping would alter bytes a signature covers.
    pub max_record_ttl: Duration,

    /// How often a node re-announces the records it published.
    ///
    /// Distinct from Kademlia's own replication, which keeps a record on the
    /// `k` closest nodes as they change. This is what stops a record vanishing
    /// when the nodes that held it all leave.
    pub republication_interval: Duration,

    /// How long a cached shard descriptor is trusted before it is read again.
    ///
    /// Every publish and every lookup needs the shard level for each path it
    /// touches. Reading it fresh each time would double the round trips for a
    /// value that changes on the order of never.
    pub descriptor_cache_ttl: Duration,

    /// How many pointers a page may hold before a publisher widens the shard.
    ///
    /// The spike in issue #72 measured roughly 200 pointers per 16 KiB record.
    /// The default leaves headroom for the pointers a publisher has not seen
    /// yet, because it decides from one replica's copy of the page.
    pub page_high_water: usize,

    /// How a storing node treats attestations.
    pub attestation_policy: AttestationPolicy,

    /// How long a query may run before Kademlia abandons it.
    pub query_timeout: Duration,
}

impl Libp2pConfig {
    /// The protocol name agent-uri nodes speak.
    pub const PROTOCOL: StreamProtocol = StreamProtocol::new("/agent-uri/kad/1.0.0");

    /// Kademlia's `k`, the number of nodes a record is replicated to.
    const DEFAULT_REPLICATION_FACTOR: NonZeroUsize = NonZeroUsize::new(20).unwrap();

    /// Creates a configuration with the defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            listen_addresses: Vec::new(),
            protocol: Self::PROTOCOL,
            replication_factor: Self::DEFAULT_REPLICATION_FACTOR,
            max_record_ttl: Duration::from_hours(24),
            republication_interval: Duration::from_mins(15),
            descriptor_cache_ttl: Duration::from_mins(5),
            page_high_water: 128,
            attestation_policy: AttestationPolicy::VerifyKnownRoots,
            query_timeout: Duration::from_mins(1),
        }
    }

    /// Adds an address for the node to listen on.
    #[must_use]
    pub fn listening_on(mut self, address: Multiaddr) -> Self {
        self.listen_addresses.push(address);
        self
    }

    /// Sets the replication factor.
    #[must_use]
    pub const fn with_replication_factor(mut self, factor: NonZeroUsize) -> Self {
        self.replication_factor = factor;
        self
    }

    /// Sets the longest record lifetime this node will accept.
    #[must_use]
    pub const fn with_max_record_ttl(mut self, ttl: Duration) -> Self {
        self.max_record_ttl = ttl;
        self
    }

    /// Sets how often published records are re-announced.
    #[must_use]
    pub const fn with_republication_interval(mut self, interval: Duration) -> Self {
        self.republication_interval = interval;
        self
    }

    /// Sets how long a cached shard descriptor is trusted.
    #[must_use]
    pub const fn with_descriptor_cache_ttl(mut self, ttl: Duration) -> Self {
        self.descriptor_cache_ttl = ttl;
        self
    }

    /// Sets the pointer count at which a publisher widens a shard.
    #[must_use]
    pub const fn with_page_high_water(mut self, pointers: usize) -> Self {
        self.page_high_water = pointers;
        self
    }

    /// Sets how this node treats attestations on records it is asked to store.
    #[must_use]
    pub const fn with_attestation_policy(mut self, policy: AttestationPolicy) -> Self {
        self.attestation_policy = policy;
        self
    }

    /// Sets how long a Kademlia query may run.
    #[must_use]
    pub const fn with_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout;
        self
    }
}

impl Default for Libp2pConfig {
    /// Kademlia's `k` of 20, a 24-hour ceiling on record lifetime, and
    /// attestation verification for every trust root the node knows.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_verify_what_they_can() {
        let config = Libp2pConfig::default();
        assert_eq!(
            config.attestation_policy,
            AttestationPolicy::VerifyKnownRoots
        );
        assert_eq!(config.replication_factor.get(), 20);
    }

    #[test]
    fn the_protocol_is_not_the_ipfs_default() {
        // Sharing /ipfs/kad/1.0.0 would put agent-uri records into a foreign
        // overlay whose nodes would neither validate nor understand them.
        assert_eq!(Libp2pConfig::PROTOCOL.as_ref(), "/agent-uri/kad/1.0.0");
    }

    #[test]
    fn only_the_strict_policy_refuses_unknown_trust_roots() {
        assert!(!AttestationPolicy::RequireVerified.accepts_unknown_roots());
        assert!(AttestationPolicy::VerifyKnownRoots.accepts_unknown_roots());
        assert!(AttestationPolicy::Unverified.accepts_unknown_roots());
    }

    #[test]
    fn builders_override_defaults() {
        let config = Libp2pConfig::new()
            .with_max_record_ttl(Duration::from_hours(1))
            .with_page_high_water(8)
            .with_attestation_policy(AttestationPolicy::RequireVerified)
            .with_query_timeout(Duration::from_secs(5));

        assert_eq!(config.max_record_ttl, Duration::from_hours(1));
        assert_eq!(config.page_high_water, 8);
        assert_eq!(
            config.attestation_policy,
            AttestationPolicy::RequireVerified
        );
        assert_eq!(config.query_timeout, Duration::from_secs(5));
    }
}
