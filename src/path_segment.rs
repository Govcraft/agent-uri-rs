//! Path segment type for capability paths.

use std::fmt;
use std::str::FromStr;

use crate::constants::MAX_PATH_SEGMENT_LENGTH;
use crate::error::PathSegmentError;

/// A validated path segment in a capability path.
///
/// Path segments are lowercase alphanumeric strings with hyphens,
/// between 1 and 64 characters long.
///
/// # Examples
///
/// ```
/// use agent_uri::PathSegment;
///
/// let seg = PathSegment::parse("chat").unwrap();
/// assert_eq!(seg.as_str(), "chat");
///
/// let seg = PathSegment::parse("code-interpreter").unwrap();
/// assert_eq!(seg.as_str(), "code-interpreter");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathSegment(String);

impl PathSegment {
    /// Parses a path segment from a string.
    ///
    /// # Errors
    ///
    /// Returns `PathSegmentError` if:
    /// - The segment is empty
    /// - The segment exceeds 64 characters
    /// - The segment contains invalid characters (only lowercase letters, digits, hyphens allowed)
    pub fn parse(input: &str) -> Result<Self, PathSegmentError> {
        if input.is_empty() {
            return Err(PathSegmentError::Empty);
        }

        if input.len() > MAX_PATH_SEGMENT_LENGTH {
            return Err(PathSegmentError::TooLong {
                max: MAX_PATH_SEGMENT_LENGTH,
                actual: input.len(),
            });
        }

        for (i, c) in input.chars().enumerate() {
            if !Self::is_valid_char(c) {
                return Err(PathSegmentError::InvalidChar { char: c, position: i });
            }
        }

        Ok(Self(input.to_string()))
    }

    /// Returns the segment as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns true if the character is valid for a path segment.
    #[must_use]
    pub const fn is_valid_char(c: char) -> bool {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
    }
}

impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PathSegment {
    type Err = PathSegmentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for PathSegment {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_segment() {
        let seg = PathSegment::parse("chat").unwrap();
        assert_eq!(seg.as_str(), "chat");
    }

    #[test]
    fn parse_segment_with_hyphen() {
        let seg = PathSegment::parse("code-interpreter").unwrap();
        assert_eq!(seg.as_str(), "code-interpreter");
    }

    #[test]
    fn parse_segment_with_digits() {
        let seg = PathSegment::parse("v2").unwrap();
        assert_eq!(seg.as_str(), "v2");
    }

    #[test]
    fn parse_empty_fails() {
        let result = PathSegment::parse("");
        assert!(matches!(result, Err(PathSegmentError::Empty)));
    }

    #[test]
    fn parse_too_long_fails() {
        let long = "a".repeat(65);
        let result = PathSegment::parse(&long);
        assert!(matches!(result, Err(PathSegmentError::TooLong { max: 64, actual: 65 })));
    }

    #[test]
    fn parse_uppercase_fails() {
        let result = PathSegment::parse("Chat");
        assert!(matches!(result, Err(PathSegmentError::InvalidChar { char: 'C', position: 0 })));
    }

    #[test]
    fn parse_underscore_fails() {
        let result = PathSegment::parse("code_interpreter");
        assert!(matches!(result, Err(PathSegmentError::InvalidChar { char: '_', position: 4 })));
    }
}
