//! Fragment type for sub-agent addressing.

use std::fmt;
use std::str::FromStr;

use crate::error::FragmentError;

/// A validated fragment from an agent URI.
///
/// The fragment addresses sub-agent functionality or capability subsets.
///
/// # Examples
///
/// ```
/// use agent_uri::Fragment;
///
/// let frag = Fragment::parse("summarization").unwrap();
/// assert_eq!(frag.as_str(), "summarization");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fragment(String);

impl Fragment {
    /// Parses a fragment from a string (without leading '#').
    ///
    /// # Errors
    ///
    /// Returns `FragmentError` if the fragment contains invalid characters.
    pub fn parse(input: &str) -> Result<Self, FragmentError> {
        for (i, c) in input.chars().enumerate() {
            if !Self::is_valid_char(c) {
                return Err(FragmentError::InvalidChar { char: c, position: i });
            }
        }
        Ok(Self(input.to_string()))
    }

    /// Returns the fragment as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns true if the character is valid for a fragment.
    #[must_use]
    pub const fn is_valid_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':')
    }
}

impl fmt::Display for Fragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Fragment {
    type Err = FragmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for Fragment {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_fragment() {
        let frag = Fragment::parse("summarization").unwrap();
        assert_eq!(frag.as_str(), "summarization");
    }

    #[test]
    fn parse_fragment_with_special_chars() {
        let frag = Fragment::parse("sub/path:v2").unwrap();
        assert_eq!(frag.as_str(), "sub/path:v2");
    }

    #[test]
    fn parse_fragment_with_hyphen() {
        let frag = Fragment::parse("sub-capability").unwrap();
        assert_eq!(frag.as_str(), "sub-capability");
    }

    #[test]
    fn parse_fragment_with_underscore() {
        let frag = Fragment::parse("sub_capability").unwrap();
        assert_eq!(frag.as_str(), "sub_capability");
    }

    #[test]
    fn parse_fragment_with_dot() {
        let frag = Fragment::parse("v1.0").unwrap();
        assert_eq!(frag.as_str(), "v1.0");
    }

    #[test]
    fn parse_empty_fragment() {
        // Empty fragments are valid (stripped by URI parser)
        let frag = Fragment::parse("").unwrap();
        assert_eq!(frag.as_str(), "");
    }

    #[test]
    fn parse_invalid_char_fails() {
        let result = Fragment::parse("test@value");
        assert!(matches!(result, Err(FragmentError::InvalidChar { char: '@', position: 4 })));
    }

    #[test]
    fn parse_space_fails() {
        let result = Fragment::parse("test value");
        assert!(matches!(result, Err(FragmentError::InvalidChar { char: ' ', position: 4 })));
    }
}
