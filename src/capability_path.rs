//! Capability path type for agent capabilities.

use std::fmt;
use std::str::FromStr;

use crate::constants::{MAX_CAPABILITY_PATH_LENGTH, MAX_PATH_SEGMENTS};
use crate::error::CapabilityPathError;
use crate::path_segment::PathSegment;

/// A validated capability path from an agent URI.
///
/// The capability path describes what an agent does, organized as a
/// hierarchical path of segments separated by forward slashes.
///
/// # Constraints
///
/// - At least one segment required
/// - Maximum 32 segments
/// - Maximum 256 total characters
/// - Each segment: 1-64 chars, lowercase alphanumeric + hyphens
///
/// # Examples
///
/// ```
/// use agent_uri::CapabilityPath;
///
/// let path = CapabilityPath::parse("assistant/chat").unwrap();
/// assert_eq!(path.segments().len(), 2);
/// assert_eq!(path.segments()[0].as_str(), "assistant");
/// assert_eq!(path.segments()[1].as_str(), "chat");
///
/// // Deep hierarchies
/// let path = CapabilityPath::parse("workflow/approval/invoice").unwrap();
/// assert_eq!(path.segments().len(), 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityPath {
    segments: Vec<PathSegment>,
    /// Normalized string representation
    normalized: String,
}

impl CapabilityPath {
    /// Parses a capability path from a string.
    ///
    /// # Errors
    ///
    /// Returns `CapabilityPathError` if:
    /// - The path is empty
    /// - The path exceeds 256 characters
    /// - The path has more than 32 segments
    /// - Any segment is invalid
    pub fn parse(input: &str) -> Result<Self, CapabilityPathError> {
        if input.is_empty() {
            return Err(CapabilityPathError::Empty);
        }

        if input.len() > MAX_CAPABILITY_PATH_LENGTH {
            return Err(CapabilityPathError::TooLong {
                max: MAX_CAPABILITY_PATH_LENGTH,
                actual: input.len(),
            });
        }

        let segment_strs: Vec<&str> = input.split('/').collect();

        if segment_strs.len() > MAX_PATH_SEGMENTS {
            return Err(CapabilityPathError::TooManySegments {
                max: MAX_PATH_SEGMENTS,
                actual: segment_strs.len(),
            });
        }

        let mut segments = Vec::with_capacity(segment_strs.len());
        for (i, seg_str) in segment_strs.iter().enumerate() {
            let segment =
                PathSegment::parse(seg_str).map_err(|e| CapabilityPathError::InvalidSegment {
                    segment: (*seg_str).to_string(),
                    index: i,
                    reason: e,
                })?;
            segments.push(segment);
        }

        let normalized = segments
            .iter()
            .map(PathSegment::as_str)
            .collect::<Vec<_>>()
            .join("/");

        Ok(Self {
            segments,
            normalized,
        })
    }

    /// Returns the path segments.
    #[must_use]
    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    /// Returns the number of segments.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// Returns true if this path starts with the given prefix path.
    #[must_use]
    pub fn starts_with(&self, prefix: &CapabilityPath) -> bool {
        if prefix.segments.len() > self.segments.len() {
            return false;
        }
        self.segments
            .iter()
            .zip(prefix.segments.iter())
            .all(|(a, b)| a == b)
    }

    /// Returns the normalized string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }
}

impl fmt::Display for CapabilityPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.normalized)
    }
}

impl FromStr for CapabilityPath {
    type Err = CapabilityPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for CapabilityPath {
    fn as_ref(&self) -> &str {
        &self.normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_segment() {
        let path = CapabilityPath::parse("chat").unwrap();
        assert_eq!(path.depth(), 1);
        assert_eq!(path.as_str(), "chat");
    }

    #[test]
    fn parse_multiple_segments() {
        let path = CapabilityPath::parse("workflow/approval/invoice").unwrap();
        assert_eq!(path.depth(), 3);
        assert_eq!(path.segments()[0].as_str(), "workflow");
        assert_eq!(path.segments()[1].as_str(), "approval");
        assert_eq!(path.segments()[2].as_str(), "invoice");
    }

    #[test]
    fn starts_with_prefix() {
        let path = CapabilityPath::parse("workflow/approval/invoice").unwrap();
        let prefix = CapabilityPath::parse("workflow/approval").unwrap();
        assert!(path.starts_with(&prefix));
    }

    #[test]
    fn does_not_start_with_longer_prefix() {
        let path = CapabilityPath::parse("workflow/approval").unwrap();
        let prefix = CapabilityPath::parse("workflow/approval/invoice").unwrap();
        assert!(!path.starts_with(&prefix));
    }

    #[test]
    fn does_not_start_with_different_prefix() {
        let path = CapabilityPath::parse("workflow/approval").unwrap();
        let prefix = CapabilityPath::parse("assistant/chat").unwrap();
        assert!(!path.starts_with(&prefix));
    }

    #[test]
    fn parse_empty_fails() {
        let result = CapabilityPath::parse("");
        assert!(matches!(result, Err(CapabilityPathError::Empty)));
    }

    #[test]
    fn parse_too_long_fails() {
        let long = "a".repeat(257);
        let result = CapabilityPath::parse(&long);
        assert!(matches!(result, Err(CapabilityPathError::TooLong { .. })));
    }

    #[test]
    fn parse_too_many_segments_fails() {
        let segments = (0..33).map(|_| "a").collect::<Vec<_>>().join("/");
        let result = CapabilityPath::parse(&segments);
        assert!(matches!(
            result,
            Err(CapabilityPathError::TooManySegments { max: 32, actual: 33 })
        ));
    }

    #[test]
    fn parse_invalid_segment_fails() {
        let result = CapabilityPath::parse("valid/INVALID/also-valid");
        assert!(matches!(
            result,
            Err(CapabilityPathError::InvalidSegment { index: 1, .. })
        ));
    }

    #[test]
    fn parse_empty_segment_fails() {
        let result = CapabilityPath::parse("valid//invalid");
        assert!(matches!(
            result,
            Err(CapabilityPathError::InvalidSegment { index: 1, .. })
        ));
    }
}
