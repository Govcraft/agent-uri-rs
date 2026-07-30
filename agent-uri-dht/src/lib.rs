//! Capability-based DHT discovery for the agent:// URI scheme.
//!
//! This crate provides DHT (Distributed Hash Table) infrastructure for
//! discovering agents by their capabilities. It includes:
//!
//! - **Key derivation**: [`DhtKey`] for Kademlia-style routing
//! - **Registration records**: [`Registration`] with endpoints and attestations
//! - **Trait interface**: [`Dht`], an async trait abstracting DHT backends
//! - **In-memory simulation**: [`SimulatedDht`] for evaluation and testing
//! - **Prefix matching**: [`PathTrie`], a standalone helper for callers that
//!   want a local hierarchical index. Discovery itself does not use it: prefix
//!   lookup reads one materialized ancestor key.
//!
//! # Overview
//!
//! [`SimulatedDht`] implements the **direct** record model of SPECIFICATION.md
//! §6.2: agents register at keys for their exact capability path and every
//! ancestor, and a prefix lookup is one exact-key read.
//!
//! ```text
//! key = SHA256(trust_root || "/" || capability_path)
//! ```
//!
//! That model holds where one store owns the namespace and a stored value has
//! no practical size bound, which is what an in-process index is. A Kademlia
//! overlay is not, and is required to use the sharded model instead; see
//! [`agent-uri-dht-libp2p`](https://crates.io/crates/agent-uri-dht-libp2p). The
//! [`Dht`] trait is the same either way.
//!
//! This enables capability-based discovery: "find me an agent at
//! `anthropic.com` that can do `assistant/chat`".
//!
//! # Quick Start
//!
//! ```rust
//! use agent_uri::{AgentUri, CapabilityPath, TrustRoot};
//! use agent_uri_attestation::SigningKey;
//! use agent_uri_dht::{
//!     Dht, Endpoint, MutationProof, Query, ReadOptions, Registration, SimulatedDht,
//!     SimulationConfig, WriteOptions,
//! };
//! use futures::executor::block_on;
//!
//! // Disable verification only for this isolated indexing example. Production
//! // registration uses the secure default and a configured Verifier.
//! let dht = SimulatedDht::new(
//!     SimulationConfig::default().with_verify_attestations(false)
//! );
//!
//! // Register an agent. The key it names is the only one that will be able to
//! // change or remove the record later.
//! let uri = AgentUri::parse(
//!     "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
//! ).unwrap();
//! let endpoint = Endpoint::https("agent.anthropic.com:443");
//! let agent_key = SigningKey::generate();
//! let registration = Registration::new(uri, agent_key.verifying_key(), vec![endpoint]);
//! let proof = MutationProof::sign_registration(&agent_key, &registration);
//!
//! // Every operation is async, because a real backend crosses the network.
//! block_on(dht.register(registration, &proof, WriteOptions::default())).unwrap();
//!
//! // Discover agents by capability. Results are paged.
//! let query = Query::prefix(
//!     TrustRoot::parse("anthropic.com").unwrap(),
//!     CapabilityPath::parse("assistant").unwrap(),
//! );
//! let page = block_on(dht.lookup(&query, &ReadOptions::default())).unwrap();
//!
//! assert_eq!(page.len(), 1);
//! assert!(!page.has_more());
//! ```
//!
//! # Operating Against a Network
//!
//! [`Dht`] describes a distributed store, not a map, and its shape reflects
//! that even when the backend is [`SimulatedDht`]:
//!
//! - **Every operation is async and takes a deadline.** [`WriteOptions`] and
//!   [`ReadOptions`] carry a timeout; a call that does not finish returns
//!   [`DhtError::Timeout`], which does not mean the write failed to apply.
//! - **Writes name a [`Quorum`].** How many replicas must acknowledge is the
//!   caller's latency-versus-durability trade, and [`WriteReceipt`] reports
//!   what was actually reached.
//! - **Lookups are paged.** [`Dht::lookup`] returns a [`Page`]; follow
//!   [`Page::next_cursor`] until it is `None` or you are sampling rather than
//!   enumerating.
//! - **Failures are distinguishable.** [`DhtError::is_transient`] separates a
//!   slow or partitioned network from a rejected request. Collapsing the two
//!   turns a partition into an apparently empty namespace.
//! - **Writes are authorized, not merely addressed.** An agent URI is public,
//!   and so is the attestation token stored beside it, so every write carries a
//!   [`MutationProof`] signed by the agent's own key. Without this, reaching a
//!   replica would be enough to repoint an agent.
//!
//! `SimulatedDht` honors all of this against one in-process copy, so code
//! written against it does not acquire habits a real backend will punish.
//!
//! # Key Derivation
//!
//! DHT keys are derived deterministically from trust root and capability path
//! using SHA-256. This enables:
//!
//! - **Exact lookup**: Find agents at a specific capability path
//! - **Prefix lookup**: Find agents at a path and all child paths
//! - **Cross-trust-root lookup**: Find agents with a capability across all authorities
//!
//! ```rust
//! use agent_uri::{TrustRoot, CapabilityPath};
//! use agent_uri_dht::DhtKey;
//!
//! let trust_root = TrustRoot::parse("anthropic.com").unwrap();
//! let path = CapabilityPath::parse("assistant/chat").unwrap();
//!
//! // Derive a key for this capability
//! let key = DhtKey::derive(&trust_root, &path);
//!
//! // Keys are deterministic
//! let key2 = DhtKey::derive(&trust_root, &path);
//! assert_eq!(key, key2);
//!
//! // Partial depth for hierarchical queries
//! let parent_key = DhtKey::derive_at_depth(&trust_root, &path, 1).unwrap();
//! ```
//!
//! # Agent Migration
//!
//! The identity stability of agent:// URIs means agents can migrate
//! between network locations without changing their identity:
//!
//! ```rust
//! use agent_uri::AgentUri;
//! use agent_uri_attestation::SigningKey;
//! use agent_uri_dht::{
//!     Dht, Endpoint, Mutation, MutationProof, Registration, SimulatedDht, SimulationConfig,
//!     WriteOptions,
//! };
//! use futures::executor::block_on;
//!
//! let dht = SimulatedDht::new(
//!     SimulationConfig::default().with_verify_attestations(false)
//! );
//!
//! let uri = AgentUri::parse(
//!     "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
//! ).unwrap();
//! let agent_key = SigningKey::generate();
//!
//! // Register at initial location
//! let registration = Registration::new(
//!     uri.clone(),
//!     agent_key.verifying_key(),
//!     vec![Endpoint::https("us-east-1.agent.anthropic.com")]
//! );
//! let registration_proof = MutationProof::sign_registration(&agent_key, &registration);
//! block_on(dht.register(registration.clone(), &registration_proof, WriteOptions::default()))
//!     .unwrap();
//!
//! // Migrate to new location (same identity). The proof is signed against the
//! // record as it stands, so an intercepted migration cannot be re-aimed at
//! // other endpoints, applied twice, or replayed after the agent re-registers.
//! let endpoints = vec![Endpoint::https("eu-west-1.agent.anthropic.com")];
//! let mutation = Mutation::UpdateEndpoint { endpoints: &endpoints };
//! let proof = MutationProof::sign_next(&agent_key, &registration, &mutation);
//!
//! block_on(dht.update_endpoint(
//!     &uri,
//!     endpoints.clone(),
//!     &proof,
//!     WriteOptions::default(),
//! )).unwrap();
//! ```

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod config;
mod endpoint;
mod error;
mod key;
mod node;
mod options;
mod page;
mod proof;
mod query;
mod registration;
mod simulation;
mod stats;
mod traits;
mod trie;

pub use config::SimulationConfig;
pub use endpoint::Endpoint;
pub use error::DhtError;
pub use key::DhtKey;
pub use node::{NodeId, PeerAddr, WriteReceipt};
pub use options::{Quorum, ReadOptions, WriteOptions};
pub use page::{Cursor, Page};
pub use proof::{Mutation, MutationKind, MutationProof, RecordVersion, signing_payload};
pub use query::{MatchMode, Query};
pub use registration::Registration;
pub use simulation::SimulatedDht;
pub use stats::{DhtStats, MigrationResult};
pub use traits::Dht;
pub use trie::PathTrie;
