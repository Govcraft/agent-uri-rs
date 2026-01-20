//! Capability-based DHT discovery for the agent:// URI scheme.
//!
//! This crate provides DHT (Distributed Hash Table) infrastructure for
//! discovering agents by their capabilities. It includes:
//!
//! - **Key derivation**: [`DhtKey`] for Kademlia-style routing
//! - **Registration records**: [`Registration`] with endpoints and attestations
//! - **Trait interface**: [`Dht`] trait for abstracting DHT implementations
//! - **In-memory simulation**: [`SimulatedDht`] for evaluation and testing
//! - **Prefix matching**: [`PathTrie`] for efficient hierarchical discovery
//!
//! # Overview
//!
//! The core idea is that agents register at DHT keys derived from their
//! trust root and capability path:
//!
//! ```text
//! key = SHA256(trust_root || "/" || capability_path)
//! ```
//!
//! This enables capability-based discovery: "find me an agent at
//! `anthropic.com` that can do `assistant/chat`".
//!
//! # Quick Start
//!
//! ```rust
//! use agent_uri::{AgentUri, CapabilityPath, TrustRoot};
//! use agent_uri_dht::{Dht, Endpoint, Registration, SimulatedDht, SimulationConfig};
//!
//! // Create a simulated DHT
//! let dht = SimulatedDht::new(SimulationConfig::default());
//!
//! // Register an agent
//! let uri = AgentUri::parse(
//!     "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
//! ).unwrap();
//! let endpoint = Endpoint::https("agent.anthropic.com:443");
//! let registration = Registration::new(uri, vec![endpoint]);
//!
//! dht.register(registration).unwrap();
//!
//! // Discover agents by capability
//! let results = dht.lookup_prefix(
//!     &TrustRoot::parse("anthropic.com").unwrap(),
//!     &CapabilityPath::parse("assistant").unwrap(),
//! ).unwrap();
//!
//! assert_eq!(results.len(), 1);
//! ```
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
//! use agent_uri_dht::{Dht, Endpoint, Registration, SimulatedDht, SimulationConfig};
//!
//! let dht = SimulatedDht::with_defaults();
//!
//! let uri = AgentUri::parse(
//!     "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
//! ).unwrap();
//!
//! // Register at initial location
//! let registration = Registration::new(
//!     uri.clone(),
//!     vec![Endpoint::https("us-east-1.agent.anthropic.com")]
//! );
//! dht.register(registration).unwrap();
//!
//! // Migrate to new location (same identity)
//! dht.update_endpoint(
//!     &uri,
//!     vec![Endpoint::https("eu-west-1.agent.anthropic.com")]
//! ).unwrap();
//! ```

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod config;
mod endpoint;
mod error;
mod key;
mod registration;
mod simulation;
mod stats;
mod traits;
mod trie;

pub use config::SimulationConfig;
pub use endpoint::Endpoint;
pub use error::DhtError;
pub use key::DhtKey;
pub use registration::Registration;
pub use simulation::SimulatedDht;
pub use stats::{DhtStats, MigrationResult};
pub use traits::Dht;
pub use trie::PathTrie;
