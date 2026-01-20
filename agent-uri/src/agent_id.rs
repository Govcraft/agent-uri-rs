//! Agent identifier type using `TypeID` format.
//!
//! # Grammar Reference
//!
//! The agent ID grammar is defined in `grammar.abnf`:
//!
//! ```abnf
//! agent-id     = agent-prefix "_" type-suffix
//! agent-prefix = type-class *( "_" type-modifier )
//! type-class   = "llm" / "rule" / "human" / "composite"
//!              / "sensor" / "actuator" / "hybrid"
//!              / extension-class
//! type-suffix  = suffix-first 25( BASE32-TYPEID )
//! suffix-first = %x30-37  ; "0" through "7"
//! ```
//!
//! Maximum agent ID length: 90 characters (63 prefix + 1 underscore + 26 suffix).

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use mti::prelude::*;

use crate::agent_prefix::AgentPrefix;
use crate::constants::{AGENT_SUFFIX_LENGTH, MAX_AGENT_ID_LENGTH};
use crate::error::AgentIdError;

/// Base32 alphabet for `TypeID` suffix (Crockford-derived).
/// Excludes: i, l, o, u (visually ambiguous).
const BASE32_ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// A validated agent identifier in `TypeID` format.
///
/// The agent ID uniquely identifies an agent and encodes:
/// - Semantic classification (the prefix)
/// - Unique identity (the `UUIDv7` suffix)
/// - Creation timestamp (encoded in `UUIDv7`)
///
/// # Format
///
/// `<prefix>_<suffix>` where:
/// - prefix: 1-63 lowercase letters and underscores
/// - suffix: 26 character base32-encoded `UUIDv7`
///
/// # Examples
///
/// ```
/// use agent_uri::AgentId;
///
/// let id = AgentId::parse("llm_01h455vb4pex5vsknk084sn02q").unwrap();
/// assert_eq!(id.prefix().as_str(), "llm");
/// assert_eq!(id.suffix(), "01h455vb4pex5vsknk084sn02q");
///
/// // Create a new agent ID
/// let id = AgentId::new("llm_chat");
/// assert_eq!(id.suffix().len(), 26);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId {
    prefix: AgentPrefix,
    suffix: String,
    inner: MagicTypeId,
}

impl AgentId {
    /// Creates a new agent ID with the given prefix and a fresh `UUIDv7`.
    ///
    /// # Panics
    ///
    /// Panics if the prefix is invalid. Use `AgentId::try_new` for fallible creation.
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        Self::try_new(prefix).expect("valid prefix")
    }

    /// Creates a new agent ID with the given prefix and a fresh `UUIDv7`.
    ///
    /// # Errors
    ///
    /// Returns `AgentIdError` if the prefix is invalid.
    pub fn try_new(prefix: &str) -> Result<Self, AgentIdError> {
        let agent_prefix = AgentPrefix::parse(prefix).map_err(AgentIdError::InvalidPrefix)?;
        let type_id = prefix.create_type_id::<V7>();
        let suffix = type_id
            .suffix_str()
            .map_err(|e| AgentIdError::TypeIdError(e.to_string()))?;

        Ok(Self {
            prefix: agent_prefix,
            suffix,
            inner: type_id,
        })
    }

    /// Parses an agent ID from a string.
    ///
    /// # Errors
    ///
    /// Returns `AgentIdError` if:
    /// - The input is empty
    /// - The input exceeds 90 characters
    /// - The prefix is invalid
    /// - The suffix is invalid (not valid base32 or wrong length)
    /// - The separator is missing
    pub fn parse(input: &str) -> Result<Self, AgentIdError> {
        if input.is_empty() {
            return Err(AgentIdError::Empty);
        }

        if input.len() > MAX_AGENT_ID_LENGTH {
            return Err(AgentIdError::TooLong {
                max: MAX_AGENT_ID_LENGTH,
                actual: input.len(),
            });
        }

        // Find the last underscore (separator between prefix and suffix)
        let sep_idx = input.rfind('_').ok_or(AgentIdError::MissingSeparator)?;

        if sep_idx == 0 {
            return Err(AgentIdError::InvalidPrefix(
                crate::error::AgentPrefixError::Empty,
            ));
        }

        let prefix_str = &input[..sep_idx];
        let suffix_str = &input[sep_idx + 1..];

        // Validate prefix
        let prefix = AgentPrefix::parse(prefix_str).map_err(AgentIdError::InvalidPrefix)?;

        // Validate suffix
        Self::validate_suffix(suffix_str)?;

        // Parse as MagicTypeId
        let inner =
            MagicTypeId::from_str(input).map_err(|e| AgentIdError::TypeIdError(e.to_string()))?;

        Ok(Self {
            prefix,
            suffix: suffix_str.to_string(),
            inner,
        })
    }

    /// Returns the prefix (semantic classification).
    #[must_use]
    pub const fn prefix(&self) -> &AgentPrefix {
        &self.prefix
    }

    /// Returns the suffix (base32-encoded `UUIDv7`).
    #[must_use]
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// Returns the underlying [`MagicTypeId`].
    #[must_use]
    pub const fn inner(&self) -> &MagicTypeId {
        &self.inner
    }

    /// Returns the UUID from the suffix.
    ///
    /// # Errors
    ///
    /// Returns an error if UUID extraction fails.
    pub fn uuid(&self) -> Result<uuid::Uuid, AgentIdError> {
        self.inner
            .uuid()
            .map_err(|e| AgentIdError::TypeIdError(e.to_string()))
    }

    fn validate_suffix(suffix: &str) -> Result<(), AgentIdError> {
        if suffix.len() != AGENT_SUFFIX_LENGTH {
            return Err(AgentIdError::InvalidSuffix {
                value: suffix.to_string(),
                reason: "suffix must be exactly 26 characters",
            });
        }

        // First character must be 0-7 (prevent 130-bit overflow)
        let first = suffix
            .chars()
            .next()
            .expect("already checked suffix is not empty");
        if !('0'..='7').contains(&first) {
            return Err(AgentIdError::InvalidSuffix {
                value: suffix.to_string(),
                reason: "first character must be 0-7",
            });
        }

        // All characters must be valid base32
        for c in suffix.chars() {
            if !BASE32_ALPHABET.contains(&(c as u8)) {
                return Err(AgentIdError::InvalidSuffix {
                    value: suffix.to_string(),
                    reason: "contains invalid base32 character",
                });
            }
        }

        Ok(())
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl FromStr for AgentId {
    type Err = AgentIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<MagicTypeId> for AgentId {
    fn as_ref(&self) -> &MagicTypeId {
        &self.inner
    }
}

impl TryFrom<&str> for AgentId {
    type Error = AgentIdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl PartialOrd for AgentId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AgentId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AgentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AgentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_id() {
        let id = AgentId::new("llm_chat");
        assert_eq!(id.prefix().as_str(), "llm_chat");
        assert_eq!(id.suffix().len(), 26);
    }

    #[test]
    fn parse_valid_id() {
        let id = AgentId::parse("llm_chat_01h455vb4pex5vsknk084sn02q").unwrap();
        assert_eq!(id.prefix().as_str(), "llm_chat");
        assert_eq!(id.suffix(), "01h455vb4pex5vsknk084sn02q");
    }

    #[test]
    fn parse_simple_prefix() {
        let id = AgentId::parse("llm_01h455vb4pex5vsknk084sn02q").unwrap();
        assert_eq!(id.prefix().as_str(), "llm");
    }

    #[test]
    fn parse_empty_fails() {
        let result = AgentId::parse("");
        assert!(matches!(result, Err(AgentIdError::Empty)));
    }

    #[test]
    fn parse_too_long_fails() {
        let long_prefix = "a".repeat(65);
        let input = format!("{long_prefix}_01h455vb4pex5vsknk084sn02q");
        let result = AgentId::parse(&input);
        assert!(matches!(result, Err(AgentIdError::TooLong { .. })));
    }

    #[test]
    fn parse_missing_separator_fails() {
        let result = AgentId::parse("llm01h455vb4pex5vsknk084sn02q");
        assert!(matches!(result, Err(AgentIdError::MissingSeparator)));
    }

    #[test]
    fn parse_invalid_prefix_fails() {
        let result = AgentId::parse("LLM_01h455vb4pex5vsknk084sn02q");
        assert!(matches!(result, Err(AgentIdError::InvalidPrefix(_))));
    }

    #[test]
    fn parse_suffix_wrong_length_fails() {
        let result = AgentId::parse("llm_01h455vb4pex");
        assert!(matches!(result, Err(AgentIdError::InvalidSuffix { .. })));
    }

    #[test]
    fn parse_suffix_invalid_first_char_fails() {
        // First char must be 0-7
        let result = AgentId::parse("llm_91h455vb4pex5vsknk084sn02q");
        assert!(matches!(result, Err(AgentIdError::InvalidSuffix { .. })));
    }

    #[test]
    fn parse_suffix_invalid_base32_char_fails() {
        // 'i' is not in base32 alphabet
        let result = AgentId::parse("llm_01h455vb4pex5vsknk084sn0iq");
        assert!(matches!(result, Err(AgentIdError::InvalidSuffix { .. })));
    }

    #[test]
    fn roundtrip_display_parse() {
        let id1 = AgentId::new("llm_chat");
        let display = id1.to_string();
        let id2 = AgentId::parse(&display).unwrap();
        assert_eq!(id1.prefix(), id2.prefix());
        assert_eq!(id1.suffix(), id2.suffix());
    }
}
