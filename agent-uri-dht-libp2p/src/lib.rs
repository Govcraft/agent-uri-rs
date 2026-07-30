//! A Kademlia backend for `agent://` discovery, over `libp2p-kad`.
//!
//! [`agent-uri-dht`](agent_uri_dht) defines what discovery means and ships an
//! in-process index that implements it. This crate implements the same
//! [`Dht`](agent_uri_dht::Dht) trait against a real overlay: records live on
//! other people's machines, reads cross the network, and every node that stores
//! a record decides for itself whether it should.
//!
//! It is a separate crate because `libp2p` is a large dependency and the core
//! crate is useful without it. A caller that only derives DHT keys should not
//! inherit a networking stack.
//!
//! # Starting a node
//!
//! ```no_run
//! use std::time::Duration;
//! use agent_uri::AgentUri;
//! use agent_uri_attestation::{SigningKey, Verifier};
//! use agent_uri_dht::{
//!     Dht, Endpoint, MutationProof, Query, ReadOptions, Registration, WriteOptions,
//! };
//! use agent_uri_dht_libp2p::Libp2pConfig;
//! use libp2p::identity;
//!
//! # async fn example(trust_root_key: agent_uri_attestation::VerifyingKey, token: String)
//! # -> Result<(), Box<dyn std::error::Error>> {
//! // A node verifies attestations against the trust roots it is given.
//! let mut verifier = Verifier::new();
//! verifier.add_trusted_root("anthropic.com", trust_root_key);
//!
//! let node = agent_uri_dht_libp2p::start(
//!     Libp2pConfig::default().listening_on("/ip4/0.0.0.0/tcp/0".parse()?),
//!     verifier,
//!     identity::Keypair::generate_ed25519(),
//! )
//! .await?;
//!
//! // Join an existing overlay. Peer addresses carry a peer identity, because
//! // Kademlia routes to identities rather than to addresses.
//! node.bootstrap(&[agent_uri_dht::PeerAddr::new(
//!     "/ip4/198.51.100.7/tcp/4001/p2p/12D3KooWExample",
//! )])
//! .await?;
//!
//! // Publishing is a signed write, like every other write to a record.
//! let uri = AgentUri::parse(
//!     "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q",
//! )?;
//! let agent_key = SigningKey::generate();
//! let registration = Registration::new(
//!     uri.clone(),
//!     agent_key.verifying_key(),
//!     vec![Endpoint::https("agent.anthropic.com:443")],
//! )
//! .with_attestation(token);
//! let proof = MutationProof::sign_registration(&agent_key, &registration);
//! node.register(registration, &proof, WriteOptions::default()).await?;
//!
//! // A registration expires unless the agent renews it, and renewing needs
//! // the agent's key, so it cannot be the node's job.
//! let _renewal = agent_uri_dht_libp2p::keep_alive(
//!     node.clone(),
//!     uri,
//!     agent_key,
//!     Duration::from_hours(1),
//! );
//!
//! // Discovery by capability, paged.
//! let query = Query::prefix(
//!     agent_uri::TrustRoot::parse("anthropic.com")?,
//!     agent_uri::CapabilityPath::parse("assistant")?,
//! );
//! let page = node.lookup(&query, &ReadOptions::default()).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # How a registration is stored
//!
//! This crate implements the **sharded** record model of SPECIFICATION.md §6.2,
//! which a Kademlia overlay is required to use. The alternative, materializing
//! the whole registration at the exact path and every ancestor, does not
//! survive contact with a real overlay: `libp2p-kad`'s wire limit is 16 KiB,
//! which the spike in issue #72 measured at 1 to 27 registrations, against a
//! broad ancestor key meant to hold an entire subtree.
//!
//! The sharded model splits the two jobs one record was doing:
//!
//! | key | holds | written by |
//! |---|---|---|
//! | identity | the agent's signed registration | the agent, once per write |
//! | page | pointers to agents beneath a path | every agent, at every ancestor |
//! | descriptor | how many pages a path is spread over | whoever widens it |
//!
//! A pointer is about 74 bytes against a registration's 600, so a page holds
//! roughly 220 agents rather than 27, and pages shard when that is not enough.
//! Lookup costs a descriptor read, a page read per shard, and one read per agent
//! found, which is what §6.4 costs the model at; each is still `O(log N)` hops.
//! See [`keys`] for the derivations, which §6.1.1 makes normative.
//!
//! # What makes this safe under replication
//!
//! Kademlia copies records between nodes verbatim, on its own schedule, in
//! whichever direction fires first. A backend whose nodes edited what they
//! stored, or preferred whatever arrived last, would have replication undoing
//! writes.
//!
//! Every value here is instead reconciled by a rule that does not depend on
//! arrival order, and no node ever rewrites a value it accepts:
//!
//! - identity records are immutable and signed, and the later
//!   `(registered_at, sequence)` wins;
//! - pointer pages union, keeping the later expiry per URI;
//! - shard descriptors take the greater level.
//!
//! All three are commutative, associative, and idempotent. Replication becomes
//! anti-entropy rather than a race. See [`merge`] for the rules and
//! [`validate`] for what a node checks before applying them.
//!
//! # What a node refuses to store
//!
//! §6.2 requirement 4 says DHT nodes MUST verify attestations before storing
//! records. Every value entering a node's store passes [`validate`], via
//! Kademlia's `StoreInserts::FilterBoth`, including values this node publishes
//! itself. A node will not store a record whose signature does not cover it,
//! whose key does not match its URI, or whose attestation names a different key
//! than the record does.
//!
//! The one place that requirement cannot be met literally is a trust root the
//! node has no key for, and a node holds records for keys near it in the
//! overlay, which is every trust root. [`AttestationPolicy`] is where that is
//! decided rather than assumed.
//!
//! # Reads verify too
//!
//! Being handed a record by the overlay makes it neither true nor current. A
//! lookup runs the same validation on every copy returned and then takes the
//! greatest version, so it is as fresh as the best-informed peer that replied
//! and no more trusting than a storing node.
//!
//! # Known limits
//!
//! - **A node with no peers cannot publish.** Kademlia counts remote
//!   acknowledgements, and a local store write is not one. Bootstrap first.
//! - **Pointer pages are unauthenticated.** Anyone can put any URI on any page.
//!   A lookup dereferences each pointer and checks the agent's own URI against
//!   the path queried, so an injected pointer costs a wasted read and nothing
//!   more.
//! - **`expires_at` is not fully covered by a signature on migrations and
//!   refreshes.** The bound, and what it costs, are stated in [`validate`].
//! - **Shard growth is opportunistic.** A page over its high-water mark is
//!   widened by whoever notices; until then it keeps accepting pointers.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

pub mod config;
mod dht;
pub mod keys;
pub mod merge;
mod node;
pub mod record;
mod republish;
pub mod validate;
mod worker;

pub use config::{AttestationPolicy, Libp2pConfig};
pub use dht::Libp2pDht;
pub use node::start;
pub use republish::{Renewal, keep_alive, renew};
