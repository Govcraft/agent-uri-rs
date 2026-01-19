//! Agent prefix type for semantic classification.

use std::fmt;
use std::str::FromStr;

use crate::constants::MAX_AGENT_PREFIX_LENGTH;
use crate::error::AgentPrefixError;
use crate::type_class::TypeClass;

/// A validated agent prefix (semantic type classification).
///
/// The prefix encodes WHAT THE AGENT IS (its implementation type).
/// Structure: `type-class[_type-modifier[_type-modifier...]]`
///
/// # Constraints
///
/// - Maximum 63 characters
/// - Only lowercase letters and underscores
/// - Must start and end with a letter
/// - No digits allowed
///
/// # Examples
///
/// ```
/// use agent_uri::AgentPrefix;
///
/// let prefix = AgentPrefix::parse("llm").unwrap();
/// assert_eq!(prefix.type_class().as_str(), "llm");
/// assert!(prefix.modifiers().is_empty());
///
/// let prefix = AgentPrefix::parse("llm_chat_streaming").unwrap();
/// assert_eq!(prefix.type_class().as_str(), "llm");
/// assert_eq!(prefix.modifiers(), &["chat", "streaming"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentPrefix {
    type_class: TypeClass,
    modifiers: Vec<String>,
    /// Original string (normalized)
    normalized: String,
}

impl AgentPrefix {
    /// Parses an agent prefix from a string.
    ///
    /// # Errors
    ///
    /// Returns `AgentPrefixError` if:
    /// - The prefix is empty
    /// - The prefix exceeds 63 characters
    /// - The prefix contains invalid characters
    /// - The prefix doesn't start with a letter
    /// - The prefix doesn't end with a letter
    /// - The prefix contains digits
    pub fn parse(input: &str) -> Result<Self, AgentPrefixError> {
        if input.is_empty() {
            return Err(AgentPrefixError::Empty);
        }

        if input.len() > MAX_AGENT_PREFIX_LENGTH {
            return Err(AgentPrefixError::TooLong {
                max: MAX_AGENT_PREFIX_LENGTH,
                actual: input.len(),
            });
        }

        // Check first character - safe because we already verified input is not empty
        let Some(first) = input.chars().next() else {
            return Err(AgentPrefixError::Empty);
        };
        if !first.is_ascii_lowercase() {
            return Err(AgentPrefixError::MustStartWithLetter { found: first });
        }

        // Check last character - safe because we already verified input is not empty
        let Some(last) = input.chars().next_back() else {
            return Err(AgentPrefixError::Empty);
        };
        if !last.is_ascii_lowercase() {
            return Err(AgentPrefixError::MustEndWithLetter { found: last });
        }

        // Validate all characters and check for digits
        for (i, c) in input.chars().enumerate() {
            if c.is_ascii_digit() {
                return Err(AgentPrefixError::ContainsDigit { position: i });
            }
            if !c.is_ascii_lowercase() && c != '_' {
                return Err(AgentPrefixError::InvalidChar { char: c, position: i });
            }
        }

        // Split into class and modifiers
        let parts: Vec<&str> = input.split('_').collect();
        let type_class = parts[0].parse::<TypeClass>().map_err(|_| {
            AgentPrefixError::InvalidChar {
                char: parts[0].chars().next().unwrap_or(' '),
                position: 0,
            }
        })?;

        let modifiers = parts[1..].iter().map(|s| (*s).to_string()).collect();

        Ok(Self {
            type_class,
            modifiers,
            normalized: input.to_string(),
        })
    }

    /// Returns the type class.
    #[must_use]
    pub const fn type_class(&self) -> &TypeClass {
        &self.type_class
    }

    /// Returns the modifiers (subclasses).
    #[must_use]
    pub fn modifiers(&self) -> &[String] {
        &self.modifiers
    }

    /// Returns the normalized string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }
}

impl fmt::Display for AgentPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.normalized)
    }
}

impl FromStr for AgentPrefix {
    type Err = AgentPrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for AgentPrefix {
    fn as_ref(&self) -> &str {
        &self.normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_class() {
        let prefix = AgentPrefix::parse("llm").unwrap();
        assert_eq!(prefix.type_class().as_str(), "llm");
        assert!(prefix.modifiers().is_empty());
    }

    #[test]
    fn parse_with_modifiers() {
        let prefix = AgentPrefix::parse("llm_chat_streaming").unwrap();
        assert_eq!(prefix.type_class().as_str(), "llm");
        assert_eq!(prefix.modifiers(), &["chat", "streaming"]);
    }

    #[test]
    fn parse_empty_fails() {
        let result = AgentPrefix::parse("");
        assert!(matches!(result, Err(AgentPrefixError::Empty)));
    }

    #[test]
    fn parse_too_long_fails() {
        let long = "a".repeat(64);
        let result = AgentPrefix::parse(&long);
        assert!(matches!(result, Err(AgentPrefixError::TooLong { .. })));
    }

    #[test]
    fn parse_with_digit_fails() {
        // Digit in middle (not at end, which would trigger MustEndWithLetter first)
        let result = AgentPrefix::parse("ll2m");
        assert!(matches!(
            result,
            Err(AgentPrefixError::ContainsDigit { position: 2 })
        ));
    }

    #[test]
    fn parse_uppercase_fails() {
        let result = AgentPrefix::parse("LLM");
        assert!(matches!(result, Err(AgentPrefixError::MustStartWithLetter { found: 'L' })));
    }

    #[test]
    fn parse_ends_with_underscore_fails() {
        let result = AgentPrefix::parse("llm_");
        assert!(matches!(result, Err(AgentPrefixError::MustEndWithLetter { found: '_' })));
    }

    #[test]
    fn parse_starts_with_underscore_fails() {
        let result = AgentPrefix::parse("_llm");
        assert!(matches!(result, Err(AgentPrefixError::MustStartWithLetter { found: '_' })));
    }
}
