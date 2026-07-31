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
//!
//! // `new` sanitizes a prefix the grammar refuses. Where the prefix did not
//! // come from your own source, use `try_new`, which reports it instead.
//! assert_eq!(AgentId::new("LLM Chat!").prefix().as_str(), "llmchat");
//! assert!(AgentId::try_new("LLM Chat!").is_err());
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
//!
//! # Breaking changes in 0.6.0
//!
//! Two changes, neither of which affects a caller who only propagates errors.
//!
//! ## Error enums are `#[non_exhaustive]`
//!
//! An exhaustive `match` on [`ParseErrorKind`], [`TrustRootError`],
//! [`CapabilityPathError`], [`PathSegmentError`], [`AgentIdError`],
//! [`AgentPrefixError`], [`QueryError`], [`FragmentError`], [`BuilderError`],
//! or [`TypeClassError`] now needs a `_` arm.
//!
//! A parser learns to be more specific over time: a rejection reported today as
//! a generic bad character turns out to deserve a variant of its own, and
//! naming it is an improvement a caller wants. On an exhaustive enum that
//! improvement is a major version bump forever, so past 1.0 it stops happening
//! and the errors stay vaguer than they need to be.
//!
//! The wildcard arm should say what to do about a variant this version does not
//! recognise, rather than treat its absence as impossible:
//!
//! ```
//! use agent_uri::{AgentUri, ParseErrorKind};
//!
//! let error = AgentUri::parse("").unwrap_err();
//! let advice = match error.kind {
//!     ParseErrorKind::Empty => "supply a URI",
//!     ParseErrorKind::TooLong { .. } => "shorten it",
//!     _ => "check the URI against the specification",
//! };
//! assert_eq!(advice, "supply a URI");
//! ```
//!
//! Matching on a specific variant, which is the common case, is unaffected:
//! `matches!`, `if let`, and `Result::is_err` all read the same as before.
//!
//! ## `TypeClass` parsing reports a real error
//!
//! [`ExtensionClass::new`] and `<TypeClass as FromStr>::Err` return
//! [`TypeClassError`] instead of `&'static str`, so a type-class rejection is a
//! [`std::error::Error`] that composes with `?` and names the offending
//! character and its position. [`AgentPrefixError::InvalidTypeClass`]'s
//! `reason` field carries it too.

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
    MAX_DNS_DOMAIN_LENGTH, MAX_DNS_LABEL_LENGTH, MAX_PATH_SEGMENT_LENGTH, MAX_PATH_SEGMENTS,
    MAX_TRUST_ROOT_LENGTH, MAX_URI_LENGTH, SCHEME,
};
pub use error::{
    AgentIdError, AgentPrefixError, BuilderError, CapabilityPathError, FragmentError, ParseError,
    ParseErrorKind, PathSegmentError, QueryError, TrustRootError, TypeClassError,
};
pub use fragment::Fragment;
pub use path_segment::PathSegment;
pub use query::QueryParams;
pub use trust_root::{Host, TrustRoot};
pub use type_class::{ExtensionClass, TypeClass};
pub use uri::AgentUri;
