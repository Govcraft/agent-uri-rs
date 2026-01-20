//! Parser and validator for the `agent://` URI scheme.
//!
//! This crate implements parsing, validation, and serialization of agent URIs
//! as defined in the Agent Identity URI Scheme specification.
//!
//! # Overview
//!
//! Agent URIs provide topology-independent identity for agents with
//! capability-based discovery. They have the structure:
//!
//! ```text
//! agent://<trust-root>/<capability-path>/<agent-id>[?query][#fragment]
//! ```
//!
//! # Quick Start
//!
//! ```rust
//! use agent_uri::AgentUri;
//!
//! // Parse an agent URI
//! let uri = AgentUri::parse(
//!     "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q"
//! ).unwrap();
//!
//! // Access components
//! assert_eq!(uri.trust_root().host_str(), "anthropic.com");
//! assert_eq!(uri.capability_path().as_str(), "assistant/chat");
//! assert_eq!(uri.agent_id().prefix().as_str(), "llm_chat");
//!
//! // Create new agent IDs
//! use agent_uri::AgentId;
//! let id = AgentId::new("llm_chat");
//! println!("New agent: {}", id);
//! ```
//!
//! # Builder Pattern
//!
//! Use the typestate builder for compile-time enforced construction:
//!
//! ```rust
//! use agent_uri::{AgentUriBuilder, TrustRoot, CapabilityPath, AgentId};
//!
//! let uri = AgentUriBuilder::new()
//!     .trust_root(TrustRoot::parse("anthropic.com").unwrap())
//!     .capability_path(CapabilityPath::parse("assistant/chat").unwrap())
//!     .agent_id(AgentId::new("llm_chat"))
//!     .build()
//!     .unwrap();
//!
//! assert_eq!(uri.trust_root().host_str(), "anthropic.com");
//! ```
//!
//! # Length Constraints
//!
//! | Component | Max Length |
//! |-----------|------------|
//! | Total URI | 512 chars |
//! | Trust root | 128 chars |
//! | Capability path | 256 chars |
//! | Path segments | 32 max count |
//! | Each segment | 64 chars |
//! | Agent ID prefix | 63 chars |
//! | Agent ID suffix | 26 chars (fixed) |
//!
//! # Grammar Specification
//!
//! This crate implements the ABNF grammar defined in `grammar.abnf` at the crate root.
//! The grammar follows RFC 5234 (ABNF) and specifies:
//!
//! - **URI structure**: `agent://<trust-root>/<capability-path>/<agent-id>[?query][#fragment]`
//! - **Trust root**: Domain names, IPv4, and IPv6 addresses with optional ports
//! - **Capability path**: Hierarchical path with 1-32 segments
//! - **Agent ID**: `TypeID` format with semantic prefix and `UUIDv7` suffix
//!
//! See `grammar.abnf` for the complete formal specification.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod agent_id;
mod agent_prefix;
mod builder;
mod capability_path;
mod constants;
mod error;
mod fragment;
#[cfg(kani)]
mod kani_impls;
mod path_segment;
pub mod prelude;
mod query;
mod trust_root;
mod type_class;
mod uri;

pub use agent_id::AgentId;
pub use agent_prefix::AgentPrefix;
pub use builder::{AgentUriBuilder, Empty, HasCapabilityPath, HasTrustRoot, Ready};
pub use capability_path::CapabilityPath;
pub use constants::{
    AGENT_SUFFIX_LENGTH, MAX_AGENT_ID_LENGTH, MAX_AGENT_PREFIX_LENGTH, MAX_CAPABILITY_PATH_LENGTH,
    MAX_DNS_DOMAIN_LENGTH, MAX_DNS_LABEL_LENGTH, MAX_PATH_SEGMENTS, MAX_PATH_SEGMENT_LENGTH,
    MAX_TRUST_ROOT_LENGTH, MAX_URI_LENGTH, SCHEME,
};
pub use error::{
    AgentIdError, AgentPrefixError, BuilderError, CapabilityPathError, FragmentError, ParseError,
    ParseErrorKind, PathSegmentError, QueryError, TrustRootError,
};
pub use fragment::Fragment;
pub use path_segment::PathSegment;
pub use query::QueryParams;
pub use trust_root::{Host, TrustRoot};
pub use type_class::{ExtensionClass, TypeClass};
pub use uri::AgentUri;
