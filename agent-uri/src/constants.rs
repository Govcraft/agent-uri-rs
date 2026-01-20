//! Constants for agent URI validation.

/// Maximum total URI length in characters.
pub const MAX_URI_LENGTH: usize = 512;

/// Maximum trust root length including port.
pub const MAX_TRUST_ROOT_LENGTH: usize = 128;

/// Maximum capability path length (all segments combined with slashes).
pub const MAX_CAPABILITY_PATH_LENGTH: usize = 256;

/// Maximum number of path segments.
pub const MAX_PATH_SEGMENTS: usize = 32;

/// Maximum length of a single path segment.
pub const MAX_PATH_SEGMENT_LENGTH: usize = 64;

/// Maximum agent-id prefix length per `TypeID` spec.
pub const MAX_AGENT_PREFIX_LENGTH: usize = 63;

/// Fixed agent-id suffix length (`UUIDv7` in base32).
pub const AGENT_SUFFIX_LENGTH: usize = 26;

/// Maximum total agent-id length (prefix + underscore + suffix).
pub const MAX_AGENT_ID_LENGTH: usize = 90;

/// DNS label maximum length.
pub const MAX_DNS_LABEL_LENGTH: usize = 63;

/// DNS domain maximum length.
pub const MAX_DNS_DOMAIN_LENGTH: usize = 253;

/// The URI scheme.
pub const SCHEME: &str = "agent";
