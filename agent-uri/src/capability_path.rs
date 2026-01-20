//! Capability path type for agent capabilities.
//!
//! # Grammar Reference
//!
//! The capability path grammar is defined in `grammar.abnf`:
//!
//! ```abnf
//! capability-path = path-segment *31( "/" path-segment )
//! path-segment    = 1*64( LOWER / DIGIT / "-" )
//! LOWER           = %x61-7A  ; a-z
//! ```
//!
//! Constraints:
//! - Maximum 256 characters total
//! - Maximum 32 segments
//! - Each segment: 1-64 characters

use std::cmp::Ordering;
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
    /// Builds a `CapabilityPath` from pre-validated `PathSegment` vectors.
    ///
    /// This method allows constructing a `CapabilityPath` from segments that
    /// have already been validated individually, while still validating
    /// that the resulting path meets the overall path constraints.
    ///
    /// # Arguments
    ///
    /// * `segments` - A vector of pre-validated `PathSegment` instances
    ///
    /// # Returns
    ///
    /// A validated `CapabilityPath` on success.
    ///
    /// # Errors
    ///
    /// Returns `CapabilityPathError` if:
    /// - The segments vector is empty
    /// - The path exceeds 256 total characters
    /// - The path has more than 32 segments
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{CapabilityPath, PathSegment};
    ///
    /// let segments = vec![
    ///     PathSegment::parse("assistant").unwrap(),
    ///     PathSegment::parse("chat").unwrap(),
    /// ];
    /// let path = CapabilityPath::from_segments(segments).unwrap();
    /// assert_eq!(path.as_str(), "assistant/chat");
    /// ```
    pub fn from_segments(segments: Vec<PathSegment>) -> Result<Self, CapabilityPathError> {
        if segments.is_empty() {
            return Err(CapabilityPathError::Empty);
        }

        if segments.len() > MAX_PATH_SEGMENTS {
            return Err(CapabilityPathError::TooManySegments {
                max: MAX_PATH_SEGMENTS,
                actual: segments.len(),
            });
        }

        let normalized = segments
            .iter()
            .map(PathSegment::as_str)
            .collect::<Vec<_>>()
            .join("/");

        if normalized.len() > MAX_CAPABILITY_PATH_LENGTH {
            return Err(CapabilityPathError::TooLong {
                max: MAX_CAPABILITY_PATH_LENGTH,
                actual: normalized.len(),
            });
        }

        Ok(Self {
            segments,
            normalized,
        })
    }

    /// Builds a `CapabilityPath` by parsing each segment string individually.
    ///
    /// This is a convenience method for constructing paths from string slices
    /// without first parsing them into `PathSegment` instances.
    ///
    /// # Arguments
    ///
    /// * `segments` - A slice of string slices, each representing a path segment
    ///
    /// # Returns
    ///
    /// A validated `CapabilityPath` on success.
    ///
    /// # Errors
    ///
    /// Returns `CapabilityPathError` if:
    /// - The segments slice is empty
    /// - Any segment string is invalid
    /// - The path exceeds 256 total characters
    /// - The path has more than 32 segments
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::CapabilityPath;
    ///
    /// let path = CapabilityPath::try_from_strs(&["assistant", "chat"]).unwrap();
    /// assert_eq!(path.as_str(), "assistant/chat");
    ///
    /// // Invalid segment fails
    /// let result = CapabilityPath::try_from_strs(&["valid", "INVALID"]);
    /// assert!(result.is_err());
    /// ```
    pub fn try_from_strs(segments: &[&str]) -> Result<Self, CapabilityPathError> {
        if segments.is_empty() {
            return Err(CapabilityPathError::Empty);
        }

        let parsed_segments: Result<Vec<PathSegment>, CapabilityPathError> = segments
            .iter()
            .enumerate()
            .map(|(i, s)| {
                PathSegment::parse(s).map_err(|e| CapabilityPathError::InvalidSegment {
                    segment: (*s).to_string(),
                    index: i,
                    reason: e,
                })
            })
            .collect();

        Self::from_segments(parsed_segments?)
    }

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

    /// Returns the parent path, or `None` if this is a single-segment path.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::CapabilityPath;
    ///
    /// let path = CapabilityPath::parse("assistant/chat/streaming").unwrap();
    /// let parent = path.parent().unwrap();
    /// assert_eq!(parent.as_str(), "assistant/chat");
    ///
    /// let root = CapabilityPath::parse("chat").unwrap();
    /// assert!(root.parent().is_none());
    /// ```
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.segments.len() <= 1 {
            return None;
        }
        let parent_segments: Vec<PathSegment> = self.segments[..self.segments.len() - 1].to_vec();
        let normalized = parent_segments
            .iter()
            .map(PathSegment::as_str)
            .collect::<Vec<_>>()
            .join("/");
        Some(Self {
            segments: parent_segments,
            normalized,
        })
    }

    /// Returns a new path with the given segment appended.
    ///
    /// # Errors
    ///
    /// Returns `CapabilityPathError` if the resulting path would be invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{CapabilityPath, PathSegment};
    ///
    /// let path = CapabilityPath::parse("assistant").unwrap();
    /// let segment = PathSegment::parse("chat").unwrap();
    /// let joined = path.join(&segment).unwrap();
    /// assert_eq!(joined.as_str(), "assistant/chat");
    /// ```
    pub fn join(&self, segment: &PathSegment) -> Result<Self, CapabilityPathError> {
        let new_len = self.segments.len() + 1;
        if new_len > MAX_PATH_SEGMENTS {
            return Err(CapabilityPathError::TooManySegments {
                max: MAX_PATH_SEGMENTS,
                actual: new_len,
            });
        }

        let mut segments = self.segments.clone();
        segments.push(segment.clone());

        let normalized = segments
            .iter()
            .map(PathSegment::as_str)
            .collect::<Vec<_>>()
            .join("/");

        if normalized.len() > MAX_CAPABILITY_PATH_LENGTH {
            return Err(CapabilityPathError::TooLong {
                max: MAX_CAPABILITY_PATH_LENGTH,
                actual: normalized.len(),
            });
        }

        Ok(Self {
            segments,
            normalized,
        })
    }

    /// Returns a new path with a segment parsed from a string appended.
    ///
    /// # Errors
    ///
    /// Returns `CapabilityPathError` if the segment or resulting path would be invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::CapabilityPath;
    ///
    /// let path = CapabilityPath::parse("assistant").unwrap();
    /// let joined = path.try_join("chat").unwrap();
    /// assert_eq!(joined.as_str(), "assistant/chat");
    /// ```
    pub fn try_join(&self, s: &str) -> Result<Self, CapabilityPathError> {
        let segment = PathSegment::parse(s).map_err(|e| CapabilityPathError::InvalidSegment {
            segment: s.to_string(),
            index: self.segments.len(),
            reason: e,
        })?;
        self.join(&segment)
    }

    /// Returns the last segment of the path.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::CapabilityPath;
    ///
    /// let path = CapabilityPath::parse("assistant/chat").unwrap();
    /// assert_eq!(path.last().as_str(), "chat");
    /// ```
    ///
    /// # Panics
    ///
    /// This method will not panic because a `CapabilityPath` always has
    /// at least one segment (empty paths cannot be created).
    #[must_use]
    pub fn last(&self) -> &PathSegment {
        // Safe: CapabilityPath always has at least one segment
        self.segments.last().expect("path has at least one segment")
    }

    /// Returns an iterator over the path segments.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::CapabilityPath;
    ///
    /// let path = CapabilityPath::parse("assistant/chat/streaming").unwrap();
    /// let names: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
    /// assert_eq!(names, vec!["assistant", "chat", "streaming"]);
    /// ```
    pub fn iter(&self) -> std::slice::Iter<'_, PathSegment> {
        self.segments.iter()
    }
}

impl<'a> IntoIterator for &'a CapabilityPath {
    type Item = &'a PathSegment;
    type IntoIter = std::slice::Iter<'a, PathSegment>;

    fn into_iter(self) -> Self::IntoIter {
        self.segments.iter()
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

impl TryFrom<&str> for CapabilityPath {
    type Error = CapabilityPathError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl PartialOrd for CapabilityPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CapabilityPath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalized.cmp(&other.normalized)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CapabilityPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.normalized)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CapabilityPath {
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

    // from_segments tests

    #[test]
    fn from_segments_empty_returns_error() {
        let result = CapabilityPath::from_segments(vec![]);
        assert!(matches!(result, Err(CapabilityPathError::Empty)));
    }

    #[test]
    fn from_segments_single_segment_succeeds() {
        let segments = vec![PathSegment::parse("chat").unwrap()];
        let path = CapabilityPath::from_segments(segments).unwrap();
        assert_eq!(path.depth(), 1);
        assert_eq!(path.as_str(), "chat");
    }

    #[test]
    fn from_segments_multiple_segments_succeeds() {
        let segments = vec![
            PathSegment::parse("assistant").unwrap(),
            PathSegment::parse("chat").unwrap(),
        ];
        let path = CapabilityPath::from_segments(segments).unwrap();
        assert_eq!(path.depth(), 2);
        assert_eq!(path.as_str(), "assistant/chat");
    }

    #[test]
    fn from_segments_max_segments_succeeds() {
        let segments: Vec<PathSegment> = (0..32)
            .map(|_| PathSegment::parse("a").unwrap())
            .collect();
        let path = CapabilityPath::from_segments(segments).unwrap();
        assert_eq!(path.depth(), 32);
    }

    #[test]
    fn from_segments_too_many_segments_returns_error() {
        let segments: Vec<PathSegment> = (0..33)
            .map(|_| PathSegment::parse("a").unwrap())
            .collect();
        let result = CapabilityPath::from_segments(segments);
        assert!(matches!(
            result,
            Err(CapabilityPathError::TooManySegments {
                max: 32,
                actual: 33
            })
        ));
    }

    #[test]
    fn from_segments_too_long_returns_error() {
        // Create segments that together exceed 256 chars
        // 8 segments of 32 chars each = 256 chars + 7 slashes = 263 chars
        let long_segment = "a".repeat(32);
        let segments: Vec<PathSegment> = (0..8)
            .map(|_| PathSegment::parse(&long_segment).unwrap())
            .collect();
        let result = CapabilityPath::from_segments(segments);
        assert!(matches!(result, Err(CapabilityPathError::TooLong { .. })));
    }

    // try_from_strs tests

    #[test]
    fn try_from_strs_empty_returns_error() {
        let result = CapabilityPath::try_from_strs(&[]);
        assert!(matches!(result, Err(CapabilityPathError::Empty)));
    }

    #[test]
    fn try_from_strs_valid_segments_succeeds() {
        let path = CapabilityPath::try_from_strs(&["assistant", "chat"]).unwrap();
        assert_eq!(path.as_str(), "assistant/chat");
    }

    #[test]
    fn try_from_strs_invalid_segment_uppercase_returns_error() {
        let result = CapabilityPath::try_from_strs(&["valid", "INVALID"]);
        assert!(matches!(
            result,
            Err(CapabilityPathError::InvalidSegment { index: 1, .. })
        ));
    }

    #[test]
    fn try_from_strs_invalid_segment_empty_returns_error() {
        let result = CapabilityPath::try_from_strs(&["valid", ""]);
        assert!(matches!(
            result,
            Err(CapabilityPathError::InvalidSegment { index: 1, .. })
        ));
    }

    #[test]
    fn try_from_strs_first_invalid_returns_error() {
        // Should fail on first invalid, not continue to check others
        let result = CapabilityPath::try_from_strs(&["INVALID", "also-valid"]);
        assert!(matches!(
            result,
            Err(CapabilityPathError::InvalidSegment { index: 0, .. })
        ));
    }
}
