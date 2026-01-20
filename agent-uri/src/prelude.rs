//! Convenient re-exports for glob imports.
//!
//! This module provides a single import for all common types, making it easy
//! to get started with the crate:
//!
//! ```rust
//! use agent_uri::prelude::*;
//!
//! let uri = AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
//! ```
//!
//! Builder state markers (`Empty`, `HasTrustRoot`, `HasCapabilityPath`, `Ready`)
//! are intentionally excluded as they are implementation details.

pub use crate::{
    // Core types
    AgentId, AgentPrefix, AgentUri, CapabilityPath, ExtensionClass, Fragment, Host, PathSegment,
    QueryParams, TrustRoot, TypeClass,
    // Builder
    AgentUriBuilder,
    // Errors
    AgentIdError, AgentPrefixError, BuilderError, CapabilityPathError, FragmentError, ParseError,
    ParseErrorKind, PathSegmentError, QueryError, TrustRootError,
    // Constants
    AGENT_SUFFIX_LENGTH, MAX_AGENT_ID_LENGTH, MAX_AGENT_PREFIX_LENGTH, MAX_CAPABILITY_PATH_LENGTH,
    MAX_DNS_DOMAIN_LENGTH, MAX_DNS_LABEL_LENGTH, MAX_PATH_SEGMENTS, MAX_PATH_SEGMENT_LENGTH,
    MAX_TRUST_ROOT_LENGTH, MAX_URI_LENGTH, SCHEME,
};
