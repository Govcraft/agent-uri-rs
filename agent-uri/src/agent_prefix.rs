//! Agent prefix type for semantic classification.

use std::cmp::Ordering;
use std::fmt;
use std::ops::Deref;
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
/// Consecutive underscores are permitted, because a prefix is a `TypeID`
/// prefix and `TypeID` permits them. See [`modifiers`](Self::modifiers) for
/// what that means for the class/modifier reading.
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
    /// - The leading type class is not a valid core class or extension class
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
                return Err(AgentPrefixError::InvalidChar {
                    char: c,
                    position: i,
                });
            }
        }

        // Split into class and modifiers. A run of underscores yields empty
        // segments, which are not modifiers and are dropped; see `modifiers`.
        let parts: Vec<&str> = input.split('_').collect();
        let type_class =
            parts[0]
                .parse::<TypeClass>()
                .map_err(|reason| AgentPrefixError::InvalidTypeClass {
                    class: parts[0].to_string(),
                    reason,
                })?;

        let modifiers = parts[1..]
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| (*s).to_string())
            .collect();

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
    ///
    /// Reading a prefix as a type class followed by refining modifiers is a
    /// convention, not syntax: the specification says custom prefixes SHOULD
    /// follow `type_modifier_modifier`, and a prefix that does not is still
    /// valid. So this is a lossy view rather than a decomposition. Empty
    /// segments, which a run of underscores produces, are not modifiers and do
    /// not appear here, which means the class and the modifiers do not always
    /// reassemble into the prefix. [`as_str`](Self::as_str) is the authority on
    /// what the prefix actually is.
    ///
    /// ```
    /// use agent_uri::AgentPrefix;
    ///
    /// // `llm__chat` is a well-formed TypeID prefix, so it parses.
    /// let prefix = AgentPrefix::parse("llm__chat").unwrap();
    ///
    /// assert_eq!(prefix.type_class().as_str(), "llm");
    /// assert_eq!(prefix.modifiers(), &["chat"]);
    /// assert_eq!(prefix.as_str(), "llm__chat");
    /// ```
    #[must_use]
    pub fn modifiers(&self) -> &[String] {
        &self.modifiers
    }

    /// Returns the normalized string representation.
    ///
    /// This is the prefix exactly as it was written, and the only view of it
    /// that is lossless.
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

impl TryFrom<&str> for AgentPrefix {
    type Error = AgentPrefixError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl Deref for AgentPrefix {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.normalized
    }
}

impl PartialOrd for AgentPrefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AgentPrefix {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalized.cmp(&other.normalized)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AgentPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.normalized)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AgentPrefix {
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
    fn parse_one_letter_type_class_with_a_modifier() {
        // A one-letter type class is a valid TypeID prefix segment (issue #20).
        let prefix = AgentPrefix::parse("a_b").unwrap();

        assert_eq!(prefix.type_class().as_str(), "a");
        assert_eq!(prefix.modifiers(), &["b"]);
    }

    #[test]
    fn parse_single_letter_prefix() {
        let prefix = AgentPrefix::parse("a").unwrap();

        assert_eq!(prefix.type_class().as_str(), "a");
        assert!(prefix.modifiers().is_empty());
    }

    #[test]
    fn parse_consecutive_underscores_is_accepted() {
        // A TypeID prefix may carry a run of underscores, so this crate must
        // accept one: refusing it would reject identifiers other TypeID
        // implementations mint. The empty segment between them is not a
        // modifier, and the exact text survives in `as_str`.
        let prefix = AgentPrefix::parse("llm__chat").unwrap();

        assert_eq!(prefix.type_class().as_str(), "llm");
        assert_eq!(prefix.modifiers(), &["chat"]);
        assert_eq!(prefix.as_str(), "llm__chat");
    }

    #[test]
    fn parse_long_underscore_run_yields_no_empty_modifiers() {
        let prefix = AgentPrefix::parse("a___b").unwrap();

        assert_eq!(prefix.modifiers(), &["b"]);
        assert!(
            prefix.modifiers().iter().all(|m| !m.is_empty()),
            "an empty string is not a modifier by any reading"
        );
    }

    #[test]
    fn a_prefix_with_only_underscores_between_two_letters_has_one_modifier() {
        let prefix = AgentPrefix::parse("llm____streaming").unwrap();

        assert_eq!(prefix.modifiers(), &["streaming"]);
    }

    #[test]
    fn underscore_runs_are_distinct_values_despite_a_shared_reading() {
        // The class/modifier view is lossy on purpose. The values are not: two
        // prefixes that differ in text remain different prefixes, so nothing
        // downstream can conflate the two identities.
        let one = AgentPrefix::parse("llm_chat").unwrap();
        let two = AgentPrefix::parse("llm__chat").unwrap();

        assert_eq!(one.type_class(), two.type_class());
        assert_eq!(one.modifiers(), two.modifiers());
        assert_ne!(one, two);
        assert_ne!(one.as_str(), two.as_str());
    }

    #[test]
    fn parse_invalid_character_still_reports_invalid_char() {
        let result = AgentPrefix::parse("llm-chat");

        assert!(matches!(
            result,
            Err(AgentPrefixError::InvalidChar {
                char: '-',
                position: 3,
            })
        ));
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
        assert!(matches!(
            result,
            Err(AgentPrefixError::MustStartWithLetter { found: 'L' })
        ));
    }

    #[test]
    fn parse_ends_with_underscore_fails() {
        let result = AgentPrefix::parse("llm_");
        assert!(matches!(
            result,
            Err(AgentPrefixError::MustEndWithLetter { found: '_' })
        ));
    }

    #[test]
    fn parse_starts_with_underscore_fails() {
        let result = AgentPrefix::parse("_llm");
        assert!(matches!(
            result,
            Err(AgentPrefixError::MustStartWithLetter { found: '_' })
        ));
    }
}
