//! A multi-node overlay, in one process, over loopback TCP.
//!
//! The transport is real: nodes speak Kademlia to each other over sockets, with
//! noise and yamux, exactly as they would across a network. What the tests
//! control is the membership, so that partition and churn are things a test can
//! cause rather than wait for.

#![allow(dead_code)]

use std::num::NonZeroUsize;
use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::{Issuer, SigningKey, Verifier};
use agent_uri_dht::{
    Dht, DhtError, Endpoint, Mutation, MutationProof, Query, Quorum, ReadOptions, Registration,
    WriteOptions,
};
use agent_uri_dht_libp2p::{Libp2pConfig, Libp2pDht};
use libp2p::identity;

/// The trust root every test agent registers under.
pub const TRUST_ROOT: &str = "anthropic.com";

/// An overlay of nodes that have found each other.
pub struct Overlay {
    pub nodes: Vec<Libp2pDht>,
    pub issuer: Issuer,
    root_key: SigningKey,
    /// Pointers per page before a publisher widens the shard.
    page_high_water: usize,
}

impl Overlay {
    /// Starts `count` nodes and joins them into one overlay.
    ///
    /// Every node replicates every record, which is what makes the churn test
    /// deterministic: an overlay smaller than its own replication factor stores
    /// each record everywhere, so losing nodes is a question of how many copies
    /// remain rather than which ones.
    pub async fn start(count: usize) -> Self {
        Self::start_under(SigningKey::generate(), count).await
    }

    /// Starts an overlay that answers to an existing trust root.
    ///
    /// Two overlays are only halves of one partition if they agree on the
    /// trust root's key. Given different keys they are separate authorities,
    /// and each correctly refuses the other's records.
    pub async fn start_under(root_key: SigningKey, count: usize) -> Self {
        Self::start_with(root_key, count, Libp2pConfig::default().page_high_water).await
    }

    /// Starts an overlay whose pages shard at a chosen occupancy.
    ///
    /// The production default is 128 pointers, which a test would have to
    /// register 128 agents to reach.
    pub async fn start_with(root_key: SigningKey, count: usize, page_high_water: usize) -> Self {
        let issuer = Issuer::new(TRUST_ROOT, root_key.clone(), Duration::from_hours(1));

        let mut overlay = Self {
            nodes: Vec::new(),
            issuer,
            root_key,
            page_high_water,
        };
        for _ in 0..count {
            overlay.add_node().await;
        }
        overlay
    }

    /// The signing key behind this overlay's trust root.
    pub fn root_key(&self) -> SigningKey {
        self.root_key.clone()
    }

    /// Starts one more node and joins it to the overlay.
    pub async fn add_node(&mut self) -> Libp2pDht {
        let node = agent_uri_dht_libp2p::start(
            self.config(),
            self.verifier(),
            identity::Keypair::generate_ed25519(),
        )
        .await
        .expect("a node starts on loopback");

        if let Some(seed) = self.nodes.first() {
            let peers = seed.dial_addresses().await.expect("seed is running");
            node.bootstrap(&peers).await.expect("seed accepts the join");
            // Every existing node learns the newcomer, so that a record put
            // from any node reaches every replica rather than only the half of
            // the overlay that happened to dial first.
            let joining = node.dial_addresses().await.expect("new node is running");
            for existing in &self.nodes {
                let _ = existing.bootstrap(&joining).await;
            }
        }

        self.nodes.push(node.clone());
        node
    }

    /// Joins another overlay's node into this one, healing a partition.
    pub async fn connect_to(&self, other: &Self) {
        let peers = other.nodes[0]
            .dial_addresses()
            .await
            .expect("the other overlay is running");
        for node in &self.nodes {
            let _ = node.bootstrap(&peers).await;
        }
    }

    fn config(&self) -> Libp2pConfig {
        Libp2pConfig::default()
            .listening_on("/ip4/127.0.0.1/tcp/0".parse().expect("a valid multiaddr"))
            // Small enough that a handful of nodes can satisfy a majority, and
            // large enough that every node in a test overlay holds every record.
            .with_replication_factor(NonZeroUsize::new(8).expect("8 > 0"))
            .with_page_high_water(self.page_high_water)
            .with_query_timeout(Duration::from_secs(10))
    }

    /// A verifier holding this overlay's trust root.
    pub fn verifier(&self) -> Verifier {
        let mut verifier = Verifier::new();
        verifier.add_trusted_root(TRUST_ROOT, self.root_key.verifying_key());
        verifier
    }

    /// Builds an attested registration for a new agent.
    pub fn agent(
        &self,
        path: &str,
        id: &str,
        endpoint: &str,
    ) -> (AgentUri, SigningKey, Registration) {
        let uri = AgentUri::parse(&format!("agent://{TRUST_ROOT}/{path}/{id}"))
            .expect("a well-formed agent URI");
        let key = SigningKey::generate();
        let token = self
            .issuer
            .issue(&uri, &key.verifying_key(), vec![])
            .expect("the issuer signs for its own trust root");
        let registration = Registration::new(
            uri.clone(),
            key.verifying_key(),
            vec![Endpoint::https(endpoint)],
        )
        .with_attestation(token);
        (uri, key, registration)
    }
}

/// Write options a small overlay can satisfy.
///
/// `Quorum::One` because a test overlay has fewer nodes than the replication
/// factor a deployment would use, and a majority of `k` is not reachable when
/// `k` exceeds the node count.
pub fn write_options() -> WriteOptions {
    WriteOptions::new()
        .with_quorum(Quorum::One)
        .with_timeout(Duration::from_secs(20))
}

pub fn read_options() -> ReadOptions {
    ReadOptions::new().with_timeout(Duration::from_secs(20))
}

/// Registers an agent, signing the registration with its own key.
pub async fn register(
    node: &Libp2pDht,
    registration: Registration,
    key: &SigningKey,
) -> Result<(), DhtError> {
    let proof = MutationProof::sign_registration(key, &registration);
    node.register(registration, &proof, write_options())
        .await
        .map(|_| ())
}

/// Looks up one capability path and returns every registration found.
pub async fn lookup(node: &Libp2pDht, query: &Query) -> Vec<Registration> {
    node.lookup(query, &read_options())
        .await
        .expect("the overlay answers")
        .into_items()
}

/// Retries a lookup until it returns something, or gives up.
///
/// Kademlia is eventually consistent, and a record put a moment ago has to
/// propagate. Waiting on the result rather than on a fixed sleep keeps the test
/// honest about what it is waiting for.
pub async fn lookup_until_found(node: &Libp2pDht, query: &Query) -> Vec<Registration> {
    for _ in 0..20 {
        let found = lookup(node, query).await;
        if !found.is_empty() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Vec::new()
}

/// Builds the proof for a mutation against the record as it currently stands.
pub async fn proof_for(
    node: &Libp2pDht,
    uri: &AgentUri,
    key: &SigningKey,
    mutation: &Mutation<'_>,
) -> MutationProof {
    let current = current(node, uri).await;
    MutationProof::sign_next(key, &current, mutation)
}

/// Reads the registration a node currently holds for an agent.
pub async fn current(node: &Libp2pDht, uri: &AgentUri) -> Registration {
    let query = Query::exact(uri.trust_root().clone(), uri.capability_path().clone());
    lookup_until_found(node, &query)
        .await
        .into_iter()
        .find(|record| record.agent_uri() == uri)
        .expect("the agent is registered")
}

/// A query for exactly the path an agent registered at.
pub fn exact(uri: &AgentUri) -> Query {
    Query::exact(uri.trust_root().clone(), uri.capability_path().clone())
}

/// A query for a capability path and everything beneath it.
pub fn prefix(path: &str) -> Query {
    Query::prefix(
        agent_uri::TrustRoot::parse(TRUST_ROOT).expect("a valid trust root"),
        agent_uri::CapabilityPath::parse(path).expect("a valid capability path"),
    )
}
