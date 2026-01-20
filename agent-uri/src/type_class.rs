//! Type classification for agents.

use std::fmt;
use std::str::FromStr;

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
    /// # Errors
    ///
    /// Returns an error if the name is empty, less than 2 characters,
    /// or contains non-lowercase letters.
    pub fn new(name: &str) -> Result<Self, &'static str> {
        if name.is_empty() {
            return Err("extension class name cannot be empty");
        }
        if name.len() < 2 {
            return Err("extension class name must be at least 2 characters");
        }
        if !name.chars().all(|c| c.is_ascii_lowercase()) {
            return Err("extension class name must be all lowercase letters");
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
    type Err = &'static str;

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
        assert_eq!("composite".parse::<TypeClass>().unwrap(), TypeClass::Composite);
        assert_eq!("sensor".parse::<TypeClass>().unwrap(), TypeClass::Sensor);
        assert_eq!("actuator".parse::<TypeClass>().unwrap(), TypeClass::Actuator);
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
        // Too short
        assert!(ExtensionClass::new("a").is_err());
        // Empty
        assert!(ExtensionClass::new("").is_err());
        // Contains uppercase
        assert!(ExtensionClass::new("Custom").is_err());
        // Contains digit
        assert!(ExtensionClass::new("v2").is_err());
        // Valid
        assert!(ExtensionClass::new("custom").is_ok());
    }
}
