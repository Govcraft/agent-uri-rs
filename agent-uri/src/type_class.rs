//! Type classification for agents.

use std::fmt;
use std::str::FromStr;

use crate::error::TypeClassError;

/// Primary type classification for agents.
///
/// Represents what kind of agent this is at the most fundamental level.
/// These are the core classes defined in the specification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeClass {
    /// Large language model based agent
    Llm,
    /// Deterministic rule/logic based agent
    Rule,
    /// Human-in-the-loop agent
    Human,
    /// Meta-agent that orchestrates other agents
    Composite,
    /// Agent that observes/monitors (read-only)
    Sensor,
    /// Agent that effects changes (write-only)
    Actuator,
    /// Mixed LLM + rule-based reasoning
    Hybrid,
    /// Extension class not in the core set
    Extension(ExtensionClass),
}

/// An extension class name (custom type classes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtensionClass(String);

impl ExtensionClass {
    /// Creates a new extension class.
    ///
    /// A single letter is a valid name: an agent ID is a `TypeID`, and the
    /// `TypeID` specification admits prefixes of one to sixty-three characters.
    ///
    /// # Errors
    ///
    /// Returns [`TypeClassError::Empty`] for an empty name, and
    /// [`TypeClassError::InvalidChar`] naming the first character that is not a
    /// lowercase ASCII letter.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_uri::{ExtensionClass, TypeClassError};
    ///
    /// assert_eq!(ExtensionClass::new("custom").unwrap().as_str(), "custom");
    /// assert_eq!(
    ///     ExtensionClass::new("v2"),
    ///     Err(TypeClassError::InvalidChar { char: '2', position: 1 })
    /// );
    /// ```
    pub fn new(name: &str) -> Result<Self, TypeClassError> {
        if name.is_empty() {
            return Err(TypeClassError::Empty);
        }
        // Position counted in characters, not bytes: an offset that lands
        // mid-character points a reader at nothing (issues #33, #89).
        if let Some((position, char)) = name
            .chars()
            .enumerate()
            .find(|(_, c)| !c.is_ascii_lowercase())
        {
            return Err(TypeClassError::InvalidChar { char, position });
        }
        Ok(Self(name.to_string()))
    }

    /// Returns the class name as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ExtensionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TypeClass {
    /// Returns the string representation of this type class.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Llm => "llm",
            Self::Rule => "rule",
            Self::Human => "human",
            Self::Composite => "composite",
            Self::Sensor => "sensor",
            Self::Actuator => "actuator",
            Self::Hybrid => "hybrid",
            Self::Extension(ext) => ext.as_str(),
        }
    }

    /// Returns true if this is a core type class (not an extension).
    #[must_use]
    pub const fn is_core(&self) -> bool {
        !matches!(self, Self::Extension(_))
    }
}

impl fmt::Display for TypeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for TypeClass {
    type Err = TypeClassError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "llm" => Ok(Self::Llm),
            "rule" => Ok(Self::Rule),
            "human" => Ok(Self::Human),
            "composite" => Ok(Self::Composite),
            "sensor" => Ok(Self::Sensor),
            "actuator" => Ok(Self::Actuator),
            "hybrid" => Ok(Self::Hybrid),
            other => {
                let ext = ExtensionClass::new(other)?;
                Ok(Self::Extension(ext))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_core_classes() {
        assert_eq!("llm".parse::<TypeClass>().unwrap(), TypeClass::Llm);
        assert_eq!("rule".parse::<TypeClass>().unwrap(), TypeClass::Rule);
        assert_eq!("human".parse::<TypeClass>().unwrap(), TypeClass::Human);
        assert_eq!(
            "composite".parse::<TypeClass>().unwrap(),
            TypeClass::Composite
        );
        assert_eq!("sensor".parse::<TypeClass>().unwrap(), TypeClass::Sensor);
        assert_eq!(
            "actuator".parse::<TypeClass>().unwrap(),
            TypeClass::Actuator
        );
        assert_eq!("hybrid".parse::<TypeClass>().unwrap(), TypeClass::Hybrid);
    }

    #[test]
    fn core_classes_are_core() {
        assert!(TypeClass::Llm.is_core());
        assert!(TypeClass::Rule.is_core());
        assert!(TypeClass::Human.is_core());
    }

    #[test]
    fn parse_extension_class() {
        let tc = "custom".parse::<TypeClass>().unwrap();
        assert!(matches!(tc, TypeClass::Extension(_)));
        assert!(!tc.is_core());
        assert_eq!(tc.as_str(), "custom");
    }

    #[test]
    fn extension_class_validation() {
        // Empty
        assert!(ExtensionClass::new("").is_err());
        // Contains uppercase
        assert!(ExtensionClass::new("Custom").is_err());
        // Contains digit
        assert!(ExtensionClass::new("v2").is_err());
        // Valid
        assert!(ExtensionClass::new("custom").is_ok());
    }

    #[test]
    fn a_single_letter_is_a_valid_extension_class() {
        // TypeID prefixes run from one to sixty-three characters, and an agent
        // ID is a TypeID (issue #20).
        assert_eq!(ExtensionClass::new("a").unwrap().as_str(), "a");
    }

    #[test]
    fn a_one_character_name_that_is_not_a_lowercase_letter_is_refused() {
        // Two bytes, one character, and not a-z (issue #33).
        assert_eq!(
            ExtensionClass::new("\u{00e9}"),
            Err(TypeClassError::InvalidChar {
                char: '\u{00e9}',
                position: 0
            })
        );
    }

    #[test]
    fn a_rejection_names_the_character_that_caused_it() {
        // The old `&'static str` could only say "not all lowercase". A caller
        // fixing a name wants to know which character and where.
        assert_eq!(
            ExtensionClass::new("v2"),
            Err(TypeClassError::InvalidChar {
                char: '2',
                position: 1
            })
        );
        assert_eq!(ExtensionClass::new(""), Err(TypeClassError::Empty));
    }

    #[test]
    fn a_position_counts_characters_rather_than_bytes() {
        // A byte offset past a multi-byte character points at nothing a reader
        // can find in the string they wrote (issues #33, #89).
        assert_eq!(
            ExtensionClass::new("\u{00e9}\u{00e9}X"),
            Err(TypeClassError::InvalidChar {
                char: '\u{00e9}',
                position: 0
            })
        );
        assert_eq!(
            ExtensionClass::new("ab\u{00e9}"),
            Err(TypeClassError::InvalidChar {
                char: '\u{00e9}',
                position: 2
            })
        );
    }

    #[test]
    fn a_type_class_rejection_is_a_std_error() {
        // What the `&'static str` could not be: a type that composes with `?`
        // and with every error-reporting crate.
        fn assert_error<E: std::error::Error>(_: &E) {}

        let error = "Custom".parse::<TypeClass>().unwrap_err();
        assert_error(&error);
        assert!(error.to_string().contains("lowercase"), "{error}");
    }
}
