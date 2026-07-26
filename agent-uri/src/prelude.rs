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
    // Constants
    AGENT_SUFFIX_LENGTH,
    // Core types
    AgentId,
    // Errors
    AgentIdError,
    AgentPrefix,
    AgentPrefixError,
    AgentUri,
    // Builder
    AgentUriBuilder,
    BuilderError,
    CapabilityPath,
    CapabilityPathError,
    ExtensionClass,
    Fragment,
    FragmentError,
    Host,
    MAX_AGENT_ID_LENGTH,
    MAX_AGENT_PREFIX_LENGTH,
    MAX_CAPABILITY_PATH_LENGTH,
    MAX_DNS_DOMAIN_LENGTH,
    MAX_DNS_LABEL_LENGTH,
    MAX_PATH_SEGMENT_LENGTH,
    MAX_PATH_SEGMENTS,
    MAX_TRUST_ROOT_LENGTH,
    MAX_URI_LENGTH,
    ParseError,
    ParseErrorKind,
    PathSegment,
    PathSegmentError,
    QueryError,
    QueryParams,
    SCHEME,
    TrustRoot,
    TrustRootError,
    TypeClass,
};
